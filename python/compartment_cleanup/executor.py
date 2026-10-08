"""Bounded bulk helpers; the deletion scheduler is implemented separately.

IAM chunks use a conservative 20 (no documented IAM numeric limit verified).
Bulk has no ETag precondition; typed preflight cannot eliminate movement races.
Saved bulk hints never select a method or construct a mutation payload.
"""
from copy import deepcopy
from datetime import datetime, timezone
import math
import time

import oci

from .discovery import _catalog
from .graph import compute_depths, validate_scope
from .handlers.core import BlockBootVolumes
from .handlers.network import Networks, NETWORK_OPERATIONS
from .handlers.storage import Storage
from .model import CleanupError, Submission
from .journal import bulk_record_key, bulk_attempt_records, resource_records

IAM_CHUNK_SIZE = 20
STORAGE_CHUNK_SIZE = 1000


class BulkJournalError(CleanupError):
    """Fatal durable-journal failure; never reinterpret as an OCI outcome."""

_CANDIDATES = frozenset(('Volume','BootVolume','VolumeBackup','BootVolumeBackup',*NETWORK_OPERATIONS))
_TERMINAL = frozenset(('SUCCEEDED','FAILED','CANCELED'))
_PENDING = frozenset(('ACCEPTED','IN_PROGRESS','CANCELING'))


def _candidate(node, handler):
    # The known implementations are part of this contract. Runtime handler maps,
    # arbitrary registered types and artifact aliases cannot widen it.
    return (type(handler) in (BlockBootVolumes, Networks)
            and node.resource_type in _CANDIDATES
            and node.action == 'delete' and not node.blockers
            and not any(node.metadata.get(k) for k in ('cascade_owner','cascade_members','cascade_snapshot')))


def bulk_groups(plan, ready, registry):
    """Propose groups from report catalog; submission revalidates a fresh catalog.

    Caller supplies dependency-ready nodes. Depths and blocked predecessors are
    recomputed here; no recorded depth or bulk payload hint is trusted.
    Storage eligibility is live-checked by its batch hook during submission.
    """
    validate_scope(plan, plan.parent_id)
    depths, blocked = compute_depths(plan.nodes, plan.edges)
    grouped = {}
    seen = set()
    for node in ready:
        if node.key in seen or plan.nodes.get(node.key) != node:
            raise CleanupError('Ready group identity differs from validated plan')
        seen.add(node.key)
        handler = registry.handler_for(node)
        if node.key in blocked or node.key not in depths or node.action != 'delete' or node.blockers:
            continue
        safe = registry.classify(node)
        if safe.action != 'delete' or safe.blockers:
            continue
        if type(handler) is Storage and node.resource_type == 'ObjectStorageObject':
            metadata = safe.metadata
            required = ('namespace','bucket_id','bucket_name','bucket_created','object_name')
            if any(not metadata.get(k) for k in required):
                continue
            kind = ('storage', *(metadata[k] for k in required[:-1]))
        elif _candidate(safe, handler) and plan.bulk_types.get(node.resource_type) == ():
            kind = ('identity',)
        else:
            continue
        key = (node.compartment_id,node.region,depths[node.key],bool(handler.late_action),kind)
        grouped.setdefault(key, []).append(node)
    result = []
    for key, nodes in grouped.items():
        size = STORAGE_CHUNK_SIZE if key[-1][0] == 'storage' else IAM_CHUNK_SIZE
        result.extend(nodes[start:start+size] for start in range(0,len(nodes),size))
    return result


def _journal_context(plan, workspace, state):
    if workspace is None or state is None:
        raise CleanupError('Bulk operations require a locked durable workspace and state')
    workspace._writer()
    if state.tenancy_id != plan.tenancy_id or state.parent_id != plan.parent_id:
        raise CleanupError('Bulk journal scope differs from plan')


def _persist(workspace, state, nodes, attempt):
    old = deepcopy(state.records)
    try:
        key = bulk_record_key(attempt['attempt_id'])
        existing = state.records.get(key)
        if existing is not None:
            groups = dict(bulk_attempt_records(state))
            original = groups.get(key)
            mutable = {'status','request_id','resource_evidence','resource_status','work_request'}
            if original is None or {k:v for k,v in original.items() if k not in mutable} != {k:v for k,v in attempt.items() if k not in mutable}:
                raise CleanupError('Bulk original endpoint and arguments are immutable')
            if original.get('request_id') and original['request_id'] != attempt.get('request_id'):
                raise CleanupError('Recorded work request identity is immutable')
        state.records[key] = {'record_type':'bulk_attempt','attempt':deepcopy(attempt)}
        reference = {'bulk_attempt':key,'attempt_id':attempt['attempt_id']}
        for node in nodes:
            if node.key == key:
                raise CleanupError('Resource identity collides with reserved group journal')
            record = state.records.setdefault(node.key, {'status':'discovered','attempts':[]})
            history = record.setdefault('attempts', [])
            matches = [a for a in history if a.get('attempt_id') == attempt['attempt_id']]
            if len(matches)>1 or (matches and matches[0] != reference):
                raise CleanupError('Conflicting bulk reference in resource history')
            if not matches:
                history.append(dict(reference))
        workspace.save_state(state)
    except Exception as error:
        state.records = old
        raise BulkJournalError('Bulk journal persistence failed; stop further operations') from error


def _new_attempt(state, nodes, token):
    bulk_record_key(token)
    groups=dict(bulk_attempt_records(state))
    resources=resource_records(state)  # Validates narrow references once, linearly.
    if any(a.get('attempt_id')==token for a in groups.values()):
        raise CleanupError('Retry token is already bound to an immutable original group')
    # Inline direct histories also participate in globally unique attempt tokens.
    if any(a.get('attempt_id')==token for record in resources.values() for a in record.get('attempts',[])):
        raise CleanupError('Retry token is already bound to an immutable original action')
    for node in nodes:
        for item in resources.get(node.key,{}).get('attempts',[]):
            attempt=groups[item['bulk_attempt']] if 'bulk_attempt' in item else item
            if attempt.get('status') not in ('failed','deleted'):
                raise CleanupError('Previous ambiguous or pending operation must be reconciled first')
            if attempt.get('resource_status',{}).get(node.key) != 'failed':
                raise CleanupError('New action requires established per-resource failure')


def _work_id(headers):
    values = [v for k,v in headers.items() if str(k).lower() in ('opc-workrequest-id','opc-work-request-id')]
    if not values or any(not isinstance(v,str) or not v.strip() for v in values) or len(set(values)) != 1:
        return None
    return values[0]


def submit_bulk(gateway, plan, nodes, attempt_id, *, registry=None, workspace=None, state=None, now=None):
    """Fresh preflight then durable intent then one mutation, never blind retry.

    The required keyword journal context resolves the plan interface's missing
    persistence boundary. Caller must hold Workspace.locked; save failures stop
    the call. Existing attempts are reconciled through inspect_bulk, not rebuilt.
    """
    _journal_context(plan, workspace, state)
    scope = validate_scope(plan,plan.parent_id)
    if registry is None or not nodes or gateway.tenancy_id != plan.tenancy_id or gateway.home_region != plan.home_region or gateway.cleanup_scope != scope:
        raise CleanupError('Bulk requires fresh gateway scope and registered handlers')
    _new_attempt(state,nodes,attempt_id)
    if not any(group == nodes for group in bulk_groups(plan,nodes,registry)):
        raise CleanupError('Bulk nodes are not one eligible bounded group')
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset().total_seconds() != 0:
        raise CleanupError('Submission timestamp must be UTC')
    safe = [registry.classify(n) for n in nodes]
    handler = registry.handler_for(safe[0])
    attempt = {'attempt_id':attempt_id,'started_at':moment.isoformat(),
               'home_region':plan.home_region,'compartment_id':nodes[0].compartment_id,
               'node_keys':[n.key for n in nodes], 'node_regions':{n.key:n.region for n in nodes},
               'status':'attempting','request_id':None,'resource_evidence':{},'resource_status':{}}
    if type(handler) is Storage:
        handler.bind_plan([registry.classify(n) for n in plan.nodes.values()])
        attempt.update(service='object_storage',operation='batch_delete_objects',region=nodes[0].region)
        intent_saved=False
        def before_write(params):
            nonlocal intent_saved
            # This is the exact conditional body assembled by the Storage hook.
            attempt['namespace_name'] = params['namespace_name']
            attempt['bucket_name'] = params['bucket_name']
            attempt['bucket_identity'] = {n.key:{k:n.metadata[k] for k in ('bucket_id','bucket_created')} for n in safe}
            attempt['payload'] = oci.util.to_dict(params['batch_delete_objects_details'])
            _persist(workspace,state,nodes,attempt)
            intent_saved=True
        try:
            results = handler.submit_group(gateway,safe,scope,attempt_id,before_write=before_write)
        except Exception:
            if not intent_saved:raise
            attempt['status']='unresolved'
            _persist(workspace,state,nodes,attempt)
            return Submission('unresolved',None,None,'Storage response lost; reconcile exact items without replay')
        attempt['status']='pending' if any(r.operation_evidence for r in results.values()) else 'unresolved'
        attempt['resource_evidence']={key:r.operation_evidence for key,r in results.items() if r.operation_evidence}
        attempt['resource_status']={key:r.status for key,r in results.items()}
        _persist(workspace,state,nodes,attempt)
        return Submission(attempt['status'],None,None,'Storage batch results persisted; per-item postflight required',deepcopy(attempt))
    catalog = _catalog(gateway,plan.home_region)
    resources=[];preflight={}
    for node in safe:
        h = registry.handler_for(node)
        if not _candidate(node,h) or catalog.get(node.resource_type) != ():
            raise CleanupError('Fresh exact bulk catalog does not support identifying metadata')
        observation=h.inspect(gateway,node,scope)
        if observation.status!='present' or observation.compartment_id!=node.compartment_id or not observation.etag:
            raise CleanupError('Fresh typed bulk identity, scope or dependencies unresolved')
        resources.append({'identifier':node.key,'entity_type':node.resource_type,'metadata':{}})
        preflight[node.key]={'compartment_id':observation.compartment_id,'etag':observation.etag,'lifecycle_state':observation.lifecycle_state}
    attempt.update(service='identity',operation='bulk_delete_resources',region=plan.home_region,
                   opc_retry_token=attempt_id,resources=resources,preflight=preflight,
                   catalog={r['entity_type']:[] for r in resources},chunk_size=IAM_CHUNK_SIZE)
    _persist(workspace,state,nodes,attempt)
    details=oci.identity.models.BulkDeleteResourcesDetails(resources=[oci.identity.models.BulkActionResource(**r) for r in resources])
    try:
        _,headers=gateway.write('identity',plan.home_region,'bulk_delete_resources',{
            'compartment_id':attempt['compartment_id'],'bulk_delete_resources_details':details,'opc_retry_token':attempt_id})
    except Exception:
        attempt['status']='unresolved'
        _persist(workspace,state,nodes,attempt)
        return Submission('unresolved',None,None,'Bulk response lost; reconcile before any further action')
    request_id=_work_id(headers)
    attempt.update(request_id=request_id,status='pending' if request_id else 'unresolved')
    _persist(workspace,state,nodes,attempt)
    return Submission(attempt['status'],request_id,None,'Bulk acceptance requires exact per-resource completion',deepcopy(attempt))


def _recorded_attempt(plan, state, workspace, request_id):
    # State must still match the bytes saved under the same held lock.
    from .model import state_from_dict, state_to_dict
    durable=state_from_dict(workspace._read('state.json'))
    if state_to_dict(durable) != state_to_dict(state):
        raise CleanupError('In-memory journal differs from durable state')
    found=[(key,a) for key,a in bulk_attempt_records(state) if a.get('request_id')==request_id]
    if len(found)!=1:
        raise CleanupError('Work request lacks one consistent durable attempt')
    group_key,original=found[0]
    attempt=deepcopy(original)
    keys=attempt.get('node_keys',[])
    if (attempt.get('service')!='identity' or attempt.get('operation')!='bulk_delete_resources'
            or attempt.get('home_region')!=plan.home_region or attempt.get('region')!=plan.home_region
            or any(k not in plan.nodes for k in keys)):
        raise CleanupError('Work request original endpoint or group does not match plan')
    for key in keys:
        references=[a for a in state.records.get(key,{}).get('attempts',[]) if a.get('bulk_attempt')==group_key]
        if references != [{'bulk_attempt':group_key,'attempt_id':attempt['attempt_id']}]:
            raise CleanupError('Resource lacks its exact durable group reference')
    return attempt,[plan.nodes[k] for k in keys]


def inspect_bulk(gateway, plan, request_id, *, registry=None, workspace=None, state=None,
                 wait_seconds=0, clock=time.monotonic, sleep=time.sleep):
    """Read and persist exact Identity work-request evidence, with bounded polling.

    wait_seconds=0 performs one snapshot; Task9 may request its default 300-second
    budget explicitly. No historical success overrides an active live identity.
    """
    _journal_context(plan,workspace,state)
    scope=validate_scope(plan,plan.parent_id)
    if registry is None or gateway.tenancy_id!=plan.tenancy_id or gateway.home_region!=plan.home_region or gateway.cleanup_scope!=scope:
        raise CleanupError('Bulk inspection requires fresh validated gateway scope')
    if type(wait_seconds) not in (int,float) or not math.isfinite(wait_seconds) or wait_seconds<0 or wait_seconds>300:
        raise CleanupError('Bulk polling budget must be between zero and 300 seconds')
    attempt,nodes=_recorded_attempt(plan,state,workspace,request_id)
    expected={r['identifier']:r['entity_type'] for r in attempt['resources']}
    if len(expected)!=len(nodes) or set(expected)!={n.key for n in nodes} or any(expected[n.key]!=n.resource_type or n.compartment_id!=attempt['compartment_id'] or n.region!=attempt['node_regions'].get(n.key) for n in nodes):
        raise CleanupError('Journaled resource identity differs from original group')
    deadline=clock()+wait_seconds
    while True:
        result={'status':'unresolved','resources':{n.key:'unresolved' for n in nodes},'request_id':request_id}
        try:
            wr,_=gateway.read('identity',attempt['home_region'],'get_work_request',{'work_request_id':request_id})
            if not isinstance(wr,dict):raise CleanupError('Malformed work request')
            attempt['work_request']=deepcopy(wr)
            # Persist response before interpreting or attempting typed postflight.
            _persist(workspace,state,nodes,attempt)
            if wr.get('id')!=request_id or wr.get('compartment_id')!=attempt['compartment_id'] or wr.get('operation_type') not in (None,'UNKNOWN_ENUM_VALUE','BULK_DELETE_RESOURCES'):
                raise CleanupError('Work request correlation failed')
            for field in ('errors','logs'):
                value=wr.get(field)
                if value is not None and (not isinstance(value,list) or any(not isinstance(v,dict) for v in value)):
                    raise CleanupError('Malformed embedded work-request evidence')
            rows=wr.get('resources')
            if not isinstance(rows,list):raise CleanupError('Missing resource-level work-request evidence')
            entries={}
            for row in rows:
                if not isinstance(row,dict) or row.get('identifier') not in expected or row['identifier'] in entries or row.get('entity_type')!=expected[row['identifier']]:
                    raise CleanupError('Unexpected or duplicate affected resource; scope concern')
                entries[row['identifier']]=row
            status=wr.get('status')
            if status not in _TERMINAL|_PENDING:raise CleanupError('Unknown work-request status')
            for key,row in entries.items():
                if row.get('action_type')=='DELETED':attempt['resource_evidence'][key]=deepcopy(row)
            _persist(workspace,state,nodes,attempt)
            if status in _PENDING:
                result['status']='pending'
            else:
                result['status']='failed' if status!='SUCCEEDED' else 'unresolved'
                for node in nodes:
                    row=entries.get(node.key,{})
                    if row.get('action_type')=='DELETED':
                        h=registry.handler_for(node)
                        if type(h) in (BlockBootVolumes,Networks) and h.corroborate_bulk_absence(gateway,registry.classify(node),scope):
                            result['resources'][node.key]='deleted'
                    elif row.get('action_type')=='FAILED':result['resources'][node.key]='failed'
                if status=='SUCCEEDED' and all(v=='deleted' for v in result['resources'].values()):result['status']='deleted'
        except BulkJournalError:
            raise
        except CleanupError:
            pass
        except Exception:
            pass
        attempt['status']=result['status'];attempt['resource_status']=deepcopy(result['resources'])
        _persist(workspace,state,nodes,attempt)
        remaining=deadline-clock()
        if result['status']!='pending' or remaining<=0:return result
        sleep(min(5,remaining))
