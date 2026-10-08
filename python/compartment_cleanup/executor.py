"""Bounded bulk helpers; the deletion scheduler is implemented separately.

IAM chunks use a conservative 20 (no documented IAM numeric limit verified).
Bulk has no ETag precondition; typed preflight cannot eliminate movement races.
Saved bulk hints never select a method or construct a mutation payload.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import time

import oci

from .discovery import _catalog
from .graph import compute_depths, validate_scope
from .handlers.core import BlockBootVolumes, ComputeInstances, IAMPolicies
from .handlers.network import Networks, NETWORK_OPERATIONS, _TERMINAL as NETWORK_TERMINAL
from .handlers.storage import Storage
from .handlers.scheduled import ScheduledResources
from .handlers.logging_analytics import LoggingAnalytics
from .handlers.load_balancers import LoadBalancers
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
            if attempt['attempt_id'] in {token for entry in _invalidations(resources.get(node.key, {})) for token in entry['completed_attempt_ids']}:
                continue
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
                    if row.get('action_type')=='DELETED' and attempt['attempt_id'] not in {token for entry in _invalidations(state.records.get(node.key, {})) for token in entry['attempt_ids']}:
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

# Direct submissions use the handler’s typed dispatch, never journal dispatch.
from dataclasses import replace
from uuid import uuid4
from .discovery import discover
from .gateway import discover_scope, GatewayError
from .journal import attempt_history
from .model import Observation, plan_to_dict, state_to_dict
from .reporting import render_report

class JournalError(CleanupError):
    """A local persistence failure stops every subsequent mutation."""

def _save(workspace, state):
    try:
        workspace.save_state(state)
    except Exception as error:
        raise JournalError('Cannot persist cleanup journal; stop all mutations') from error

def _scope_now(gateway, plan):
    tenancy, home, _, current = discover_scope(gateway, plan.parent_id)
    gateway.cleanup_scope = set(plan.compartments)
    if tenancy != plan.tenancy_id or home != plan.home_region:
        raise CleanupError('Authenticated tenancy or home region changed')
    if current.get(plan.parent_id) != plan.compartments[plan.parent_id]:
        raise CleanupError('Retained parent membership changed')
    moved = {k for k, v in gateway.compartment_links.items() if k in plan.compartments and v != plan.compartments[k]}
    return (current, moved)

def _bind(registry, plan):
    for handler in registry.handlers.values():
        if type(handler) is Storage:
            handler.bind_plan([registry.classify(n) for n in plan.nodes.values() if n.resource_type != 'Compartment'])

def _progress_node(plan, node, state, registry):
    safe = registry.classify(node) if node.resource_type != 'Compartment' else node
    metadata = deepcopy(safe.metadata)
    for key, prep in plan.nodes.items():
        if prep.resource_type != 'RouteTablePreparation' or state.records.get(key, {}).get('status') != 'deleted':
            continue
        target = prep.metadata.get('route_table_id')
        if safe.key == target and metadata.get('route_rules') == prep.metadata.get('route_rules'):
            metadata['route_rules'] = []
        member = metadata.get('cascade_snapshot', {}).get(target)
        if isinstance(member, dict) and member.get('references', {}).get('route_rules') == prep.metadata.get('route_rules'):
            member['references']['route_rules'] = []
    return replace(safe, metadata=metadata)

_TERMINAL_LIFECYCLES = {
    'Compartment': 'DELETED',
    **IAMPolicies.terminal,
    **BlockBootVolumes.terminal,
    **ComputeInstances.terminal,
    **NETWORK_TERMINAL,
    'RouteTablePreparation': 'AVAILABLE',
    **{kind: 'DELETED' for kind in (
        'Certificate', 'CertificateAuthority', 'CaBundle', 'Vault', 'Key', 'Secret',
        'LoadBalancer', 'NetworkLoadBalancer', 'LoadBalancerConfiguration',
        'LogAnalyticsEntity', 'LogAnalyticsObjectCollectionRule',
        'LogAnalyticsEmBridge', 'ServiceConnector',
    )},
}


def _valid_terminal_proof(node, proof):
    """Only a recorded positive typed event can authorize absence corroboration."""
    if not isinstance(proof, dict):
        return False
    identity = {
        'node_key': node.key, 'resource_type': node.resource_type,
        'compartment_id': node.compartment_id, 'region': node.region,
    }
    if any(proof.get(key) != value for key, value in identity.items()):
        return False
    expected = _TERMINAL_LIFECYCLES.get(node.resource_type)
    if expected is None or proof.get('lifecycle_state') != expected:
        return False
    timestamp = proof.get('observed_at')
    if not isinstance(timestamp, str):
        return False
    try:
        observed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except ValueError:
        return False
    return (
        observed.tzinfo is not None
        and observed.utcoffset().total_seconds() == 0
        and observed <= datetime.now(timezone.utc)
    )


def _corroborate_iam_absence(gateway, node, plan):
    """Corroborate a valid earlier IAM DELETED event, never infer an event."""
    if plan is None or node.resource_type not in ('Policy', 'Compartment'):
        return False
    operation, parameter = (
        ('get_policy', 'policy_id') if node.resource_type == 'Policy'
        else ('get_compartment', 'compartment_id')
    )
    try:
        try:
            gateway.read('identity', plan.home_region, operation, {parameter: node.key})
            return False
        except GatewayError as error:
            if error.status != 404:
                return False
        current, moved = _scope_now(gateway, plan)
        if moved:
            return False
        if node.resource_type == 'Compartment':
            # discover_scope obtains every page of tenancy ANY inventory and
            # validates all IAM parent chains before exposing these records.
            return node.key not in gateway.compartment_records and node.key not in current
        seen = set()
        for compartment in sorted({gateway.tenancy_id, *gateway.compartment_links}):
            rows = gateway.items('identity', plan.home_region, 'list_policies',
                                 {'compartment_id': compartment})
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                        or row.get('compartment_id') != compartment or row['id'] in seen):
                    return False
                seen.add(row['id'])
                if row['id'] == node.key:
                    return False
        return True
    except Exception:
        return False


def _invalidations(record):
    entries = record.get('proof_invalidations', [])
    if not isinstance(entries, list):
        raise CleanupError('Malformed proof invalidations')
    fields = {'observed_at', 'plan_created_at', 'attempt_ids', 'completed_attempt_ids',
              'terminal_observed_at', 'owner_attempt_ids'}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise CleanupError('Malformed proof invalidation entry')
        for field in ('attempt_ids', 'completed_attempt_ids', 'owner_attempt_ids'):
            values = entry[field]
            if (not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values)
                    or len(set(values)) != len(values)):
                raise CleanupError('Malformed invalidated attempt identities')
        if not set(entry['completed_attempt_ids']) <= set(entry['attempt_ids']):
            raise CleanupError('Malformed completed invalidation identities')
        for field in ('observed_at', 'plan_created_at', 'terminal_observed_at'):
            value = entry[field]
            if value is None and field != 'observed_at':
                continue
            try:
                timestamp = datetime.fromisoformat(value)
                if timestamp.utcoffset() != timedelta(0) or timestamp > datetime.now(timezone.utc):
                    raise ValueError('Invalid event time')
            except (TypeError, ValueError):
                raise CleanupError('Malformed proof invalidation timestamp')
    return entries


def _positive_iam_item(attempt, key):
    work = attempt.get('work_request', {})
    originals = attempt.get('resources', [])
    expected = next((row for row in originals if row.get('identifier') == key), None)
    evidence = attempt.get('resource_evidence', {}).get(key, {})
    return (attempt.get('service') == 'identity'
            and attempt.get('operation') == 'bulk_delete_resources'
            and work.get('id') == attempt.get('request_id')
            and work.get('compartment_id') == attempt.get('compartment_id')
            and work.get('status') in _TERMINAL
            and expected is not None and evidence.get('identifier') == key
            and evidence.get('entity_type') == expected.get('entity_type')
            and evidence.get('action_type') == 'DELETED')


def _completed_attempt(attempt, key):
    if attempt.get('status') == 'deleted' or attempt.get('resource_status', {}).get(key) == 'deleted':
        return True
    evidence = attempt.get('resource_evidence', {}).get(key, {})
    if _positive_iam_item(attempt, key):
        return True
    if attempt.get('service') != 'object_storage' or attempt.get('operation') != 'batch_delete_objects':
        return False
    identity = attempt.get('bucket_identity', {}).get(key, {})
    if (evidence.get('operation') != 'batch_delete_objects' or evidence.get('node_key') != key
            or evidence.get('region') != attempt.get('node_regions', {}).get(key)
            or not identity or any(evidence.get(field) != value for field, value in identity.items())):
        return False
    try:
        deleted = datetime.fromisoformat(evidence['deleted_at'])
        return deleted.utcoffset() == timedelta(0) and deleted <= datetime.now(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False


def _validate_invalidation_references(state, key):
    history = {a['attempt_id']: a for a in attempt_history(state, key)}
    for entry in _invalidations(state.records.get(key, {})):
        if not set(entry['attempt_ids']) <= set(history):
            raise CleanupError('Invalidation refers to unknown original attempt')
        for token in entry['completed_attempt_ids']:
            attempt = history[token]
            if not _completed_attempt(attempt, key):
                raise CleanupError('Invalidation cannot authorize replay of an ambiguous original action')


def _proof_history(state, key):
    invalid = {token for entry in _invalidations(state.records.get(key, {}))
               for token in entry['attempt_ids']}
    return [attempt for attempt in attempt_history(state, key)
            if attempt.get('attempt_id') not in invalid]


def _current_terminal_proof(node, record):
    proof = record.get('terminal_observation')
    excluded = {entry['terminal_observed_at'] for entry in _invalidations(record)}
    return proof if _valid_terminal_proof(node, proof) and proof['observed_at'] not in excluded else None


def _invalidate_contradicted_proofs(state, node, observation, plan):
    if observation.status not in ('present', 'pending', 'moved'):
        return
    record = state.records[node.key]
    history = _proof_history(state, node.key)
    proof = _current_terminal_proof(node, record)
    completed = [a for a in history if _completed_attempt(a, node.key)]
    if proof is None and not completed and record.get('status') != 'deleted':
        return
    owner_key = node.metadata.get('bucket_id') if node.resource_type != 'Bucket' else None
    owner_key = owner_key or node.metadata.get('cascade_owner')
    owner_ids = [a['attempt_id'] for a in attempt_history(state, owner_key)] if owner_key in state.records else []
    entry = {'observed_at': datetime.now(timezone.utc).isoformat(),
             'plan_created_at': plan.created_at if plan is not None else None,
             'attempt_ids': [a['attempt_id'] for a in history],
             'completed_attempt_ids': [a['attempt_id'] for a in completed],
             'terminal_observed_at': proof['observed_at'] if proof is not None else None,
             'owner_attempt_ids': owner_ids}
    record.setdefault('proof_invalidations', []).append(entry)
    record.update(status=observation.status, detail='Fresh live evidence contradicts earlier completion; refresh discovery')


def _observe(gateway, node, scope, handler, state, plan=None):
    record = state.records.setdefault(node.key, {'status': 'discovered', 'attempts': []})
    if node.resource_type == 'Compartment':
        try:
            row, headers = gateway.read('identity', node.region, 'get_compartment', {'compartment_id': node.key})
            if row.get('id') != node.key or row.get('compartment_id') != node.compartment_id:
                observation = Observation('moved', row.get('compartment_id', ''), ' ', None, None, 'Compartment membership changed')
                _invalidate_contradicted_proofs(state, node, observation, plan)
                return observation
            status = 'deleted' if row.get('lifecycle_state') == 'DELETED' else 'present' if row.get('lifecycle_state') == 'ACTIVE' else 'pending'
            observation = Observation(status, node.compartment_id, row.get('lifecycle_state', ''), None, headers.get('etag'), 'Fresh IAM observation')
            _invalidate_contradicted_proofs(state, node, observation, plan)
            return observation
        except Exception:
            proof = _current_terminal_proof(node, record)
            if (_valid_terminal_proof(node, proof)
                    and _corroborate_iam_absence(gateway, node, plan)):
                return Observation('deleted', node.compartment_id, 'DELETED', None, None,
                                   'Earlier positive IAM DELETED event and fresh authoritative hierarchy absence')
            return Observation('unresolved', node.compartment_id, '', None, None, 'IAM terminal proof unresolved')
    if handler is None:
        return Observation('unresolved', node.compartment_id, '', None, None, 'Unsupported resource')
    observation = handler.inspect(gateway, node, scope)
    _invalidate_contradicted_proofs(state, node, observation, plan)
    if observation.status == 'unresolved' and type(handler) is Storage and handler.corroborate_live_presence(gateway, node, scope):
        _invalidate_contradicted_proofs(state, node, Observation('present', node.compartment_id, '', None, None, 'Fresh typed storage presence'), plan)
    if (observation.status == 'unresolved' and type(handler) in (
            BlockBootVolumes, ComputeInstances, Networks, IAMPolicies,
            LoadBalancers, ScheduledResources, LoggingAnalytics)
            and (record.get('status') == 'deleted' or _current_terminal_proof(node, record)
                 or list(attempt_history(state, node.key)))):
        # An actual typed list can prove presence even when dependency or saved
        # metadata checks make the target ineligible. Search is not used here.
        try:
            found, _, _ = handler.discover(gateway, node.compartment_id, node.region)
            present = next((live for live in found if live.key == node.key
                            and live.resource_type == node.resource_type
                            and live.region == node.region
                            and live.lifecycle_state != _TERMINAL_LIFECYCLES.get(node.resource_type)), None)
            if present is not None:
                status = 'present' if present.compartment_id == node.compartment_id else 'moved'
                _invalidate_contradicted_proofs(state, node, Observation(
                    status, present.compartment_id, present.lifecycle_state, None, None,
                    'Fresh typed identity remains present despite ineligible deletion'), plan)
        except CleanupError:
            pass
    history = _proof_history(state, node.key)
    if type(handler) is Storage and history:
        evidence = history[-1].get('operation_evidence') or history[-1].get('resource_evidence', {}).get(node.key)
        if evidence:
            observation = handler.reconcile_submission(gateway, node, evidence, scope)
    elif observation.status == 'unresolved' and history and hasattr(handler, 'inspect_work_request'):
        request = history[-1].get('request_id')
        if request:
            observation = handler.inspect_work_request(gateway, node, request, scope)
    if observation.status == 'unresolved' and plan is not None and (node.resource_type == 'RouteTablePreparation'):
        target = plan.nodes.get(node.metadata.get('route_table_id'))
        proof = _current_terminal_proof(node, record)
        if target is not None and _valid_terminal_proof(node, proof):
            target_observation = _observe(gateway, Networks().classify(target), scope, Networks(), state, plan)
            if target_observation.status == 'deleted':
                observation = Observation('deleted', node.compartment_id, '', None, None, 'Completed route preparation and positively verified removed route table')
    if observation.status == 'unresolved' and plan is not None:
        owner_key = node.metadata.get('bucket_id') if type(handler) is Storage and node.resource_type != 'Bucket' else node.metadata.get('cascade_owner')
        owner = plan.nodes.get(owner_key) if isinstance(owner_key, str) else None
        if owner is not None and owner.key != node.key and (not owner.metadata.get('cascade_owner')):
            owner_handler = handler
            owner_cache = handler._owner_observations if type(handler) is Storage and handler._observation_cache is not None else {}
            if owner.key not in owner_cache:
                owner_cache[owner.key] = _observe(gateway, owner, scope, owner_handler, state)
            owner_observation = owner_cache[owner.key]
            if owner_observation.status == 'deleted':
                excluded_owner_ids = {token for entry in _invalidations(record) for token in entry['owner_attempt_ids']}
                memberships = [a.get('cascade_membership', {}) for a in _proof_history(state, owner.key)
                               if a.get('attempt_id') not in excluded_owner_ids]
                member_proof = any((node.key in m.get('cascade_members', []) and node.key in m.get('cascade_snapshot', {}) for m in memberships))
                storage_proof = False
                if type(handler) is Storage:
                    for a in history:
                        evidence = a.get('operation_evidence') or a.get('resource_evidence', {}).get(node.key)
                        if isinstance(evidence, dict) and evidence.get('node_key') == node.key and (evidence.get('bucket_id') == owner.key) and (evidence.get('bucket_created') == node.metadata.get('bucket_created')) and (evidence.get('region') == node.region):
                            storage_proof = evidence.get('http_status') == 204 or (evidence.get('operation') == 'batch_delete_objects' and bool(evidence.get('deleted_at')))
                if member_proof or storage_proof:
                    try:
                        discovery_cache = handler._owner_discoveries if type(handler) is Storage and handler._observation_cache is not None else {}
                        discovery_key = (node.compartment_id, node.region)
                        if discovery_key not in discovery_cache:
                            discovery_cache[discovery_key] = handler.discover(gateway, node.compartment_id, node.region)
                        found, _, probes = discovery_cache[discovery_key]
                    except Exception:
                        found, probes = [], []
                    if probes and all((p.status == 'complete' for p in probes)) and (not any((n.key == node.key for n in found))):
                        observation = Observation('deleted', node.compartment_id, '', None, None, 'Durable exact member proof and positive owner deletion with complete fresh inventory')
    proof = _current_terminal_proof(node, record)
    if (observation.status == 'unresolved' and _valid_terminal_proof(node, proof)
            and node.resource_type == 'Policy' and type(handler) is IAMPolicies
            and _corroborate_iam_absence(gateway, node, plan)):
        observation = Observation('deleted', node.compartment_id, 'DELETED', None, None,
                                  'Earlier positive policy DELETED event and fresh complete typed inventory absence')
    if (observation.status == 'unresolved' and _valid_terminal_proof(node, proof)
            and type(handler) in (ScheduledResources, LoggingAnalytics, ComputeInstances, LoadBalancers)
            and handler.corroborate_terminal_absence(gateway, node, scope)):
        observation = Observation('deleted', node.compartment_id, proof['lifecycle_state'], None, None,
                                  'Earlier positive typed terminal event and fresh exact service inventory absence')
    if observation.status == 'unresolved' and _valid_terminal_proof(node, proof) and hasattr(handler, 'corroborate_bulk_absence'):
        if handler.corroborate_bulk_absence(gateway, node, scope):
            observation = Observation('deleted', node.compartment_id, proof['lifecycle_state'], None, None, 'Persisted positive terminal observation and fresh complete typed inventory absence')
    if observation.status == 'deleted':
        for attempt in record.get('attempts', []):
            if 'bulk_attempt' not in attempt and attempt.get('status') != 'failed':
                attempt['status'] = 'deleted'
    return observation

def _apply_observation(state, node, observation):
    record = state.records.setdefault(node.key, {'status': 'discovered', 'attempts': []})
    record.update(status=observation.status, lifecycle_state=observation.lifecycle_state, detail=observation.detail)
    if (observation.status == 'deleted'
            and observation.lifecycle_state == _TERMINAL_LIFECYCLES.get(node.resource_type)):
        old_proof = _current_terminal_proof(node, record)
        if not _valid_terminal_proof(node, old_proof):
            if record.get('terminal_observation') is not None:
                record.setdefault('terminal_history', []).append(deepcopy(record['terminal_observation']))
            record['terminal_observation'] = {
                'node_key': node.key, 'resource_type': node.resource_type,
                'compartment_id': node.compartment_id, 'region': node.region,
                'lifecycle_state': observation.lifecycle_state,
                'observed_at': datetime.now(timezone.utc).isoformat(),
            }
    if observation.status in ('present', 'pending', 'deleted') and node.action == 'schedule':
        old = record.get('scheduled_at')
        if old is not None and old != observation.scheduled_at:
            record.setdefault('schedule_history', []).append({'scheduled_at': old})
        record['scheduled_at'] = observation.scheduled_at
    elif observation.scheduled_at is not None:
        record['scheduled_at'] = observation.scheduled_at

def _previous(plan, state):
    """Drop only positively reconciled removals from historical refresh inventory."""
    done = {k for k, r in resource_records(state).items() if r.get('status') == 'deleted' and k != plan.parent_id}
    return replace(plan, nodes={k: v for k, v in plan.nodes.items() if k not in done}, compartments={k: v for k, v in plan.compartments.items() if k not in done}, edges=[e for e in plan.edges if e.before not in done and e.after not in done], probes=[p for p in plan.probes if p.compartment_id not in done], depths={k: v for k, v in plan.depths.items() if k not in done})

@contextmanager
def _observation_pass(registry):
    with ExitStack() as stack:
        for handler in registry.handlers.values():
            if type(handler) is Storage:
                stack.enter_context(handler.observation_pass())
        yield

def _inventory(gateway, plan, state, registry):
    live = discover(gateway, plan.parent_id, registry, previous=_previous(plan, state))
    gateway.cleanup_scope = set(plan.compartments)
    added = set(live.nodes) - set(plan.nodes)
    moved = {k for k in set(live.nodes) & set(plan.nodes) if (live.nodes[k].resource_type, live.nodes[k].region, live.nodes[k].compartment_id) != (plan.nodes[k].resource_type, plan.nodes[k].region, plan.nodes[k].compartment_id)}
    moved.update((k for k, v in gateway.compartment_links.items() if k in plan.compartments and v != plan.compartments[k]))
    moved.update((k for k, n in live.nodes.items() if k in plan.nodes and n.metadata.get('observed_compartment_id', n.compartment_id) != plan.nodes[k].compartment_id))
    with _observation_pass(registry):
        for key, node in live.nodes.items():
            if key in plan.nodes and state.records.get(key, {}).get('status') == 'deleted' and (_observe(gateway, registry.classify(node) if node.resource_type != 'Compartment' else node, set(plan.compartments), registry.handler_for(node), state).status != 'deleted'):
                state.records[key]['status'] = 'unresolved'
                state.records[key]['detail'] = 'Live resource reappeared after terminal proof; refresh report'
                moved.add(key)
    return (live, added, moved)

class _SubmissionGateway:
    """Capture exactly one already code-defined handler write at its boundary."""

    def __init__(self, gateway, plan, state, workspace, node, handler, attempt, registry):
        self.gateway = gateway
        self.plan = plan
        self.state = state
        self.workspace = workspace
        self.node = node
        self.handler = handler
        self.attempt = attempt
        self.registry = registry
        self.used = False

    def __getattr__(self, name):
        return getattr(self.gateway, name)

    def write(self, service, region, operation, params, endpoint=None):
        if self.used:
            raise CleanupError('A direct attempt permits one typed operation')
        self.used = True
        current, moved = _scope_now(self.gateway, self.plan)
        if moved or set(current) - set(self.plan.compartments):
            raise CleanupError('Compartment boundary drift before submission')
        fresh = _observe(self.gateway, self.node, set(self.plan.compartments), self.handler, self.state)
        if fresh.status != 'present' or (params.get('if_match') is not None and params['if_match'] != fresh.etag):
            raise CleanupError('Fresh direct submission identity or ETag changed')
        if self.node.compartment_id not in current and self.node.resource_type != 'Compartment':
            raise CleanupError('Resource compartment disappeared from live scope')
        self.attempt.update(service=service, region=region, operation=operation, endpoint=endpoint, params=oci.util.to_dict(params), preflight={'compartment_id': fresh.compartment_id, 'etag': fresh.etag, 'lifecycle_state': fresh.lifecycle_state}, cascade_membership=deepcopy({k: self.node.metadata[k] for k in ('cascade_members', 'cascade_snapshot') if k in self.node.metadata}))
        self.state.records[self.node.key]['attempts'].append(self.attempt)
        self.state.records[self.node.key]['status'] = 'attempting'
        _save(self.workspace, self.state)
        return self.gateway.write(service, region, operation, params, endpoint=endpoint)

def _direct(gateway, plan, state, workspace, node, handler, registry, observation):
    attempt = {'attempt_id': str(uuid4()), 'status': 'attempting', 'started_at': datetime.now(timezone.utc).isoformat(), 'node_key': node.key, 'resource_type': node.resource_type, 'compartment_id': node.compartment_id}
    proxy = _SubmissionGateway(gateway, plan, state, workspace, node, handler, attempt, registry)
    try:
        if node.resource_type == 'Compartment':
            proxy.write('identity', plan.home_region, 'delete_compartment', {'compartment_id': node.key})
            submission = Submission('pending', None, None, 'Compartment delete accepted; terminal IAM proof required')
        else:
            submission = handler.submit(proxy, node, observation, attempt['attempt_id'])
    except JournalError:
        raise
    except Exception as error:
        if not proxy.used or 'params' not in attempt:
            state.records[node.key].update(status='unresolved', detail='Typed action preflight changed; refresh report', run_blocked=True)
            _save(workspace, state)
            return
        if (isinstance(error, GatewayError) and error.status == 412
                and error.code == 'NoEtagMatch' and attempt['params'].get('if_match')):
            attempt.update(status='failed', detail='Conditional request rejected before effect',
                           error={'http_status': 412, 'code': 'NoEtagMatch'})
            state.records[node.key].update(status='failed', run_blocked=True,
                                           detail='Precondition rejected; a later run must revalidate')
            _save(workspace, state)
            return
        attempt.update(status='unresolved', detail=str(error))
        state.records[node.key].update(status='unresolved', detail='Response uncertain; reconcile before any replay')
        _save(workspace, state)
        if isinstance(error, GatewayError) and error.status in (401, 403):
            raise CleanupError('OCI authentication or authorization failed during submission') from error
        return
    attempt.update(status=submission.status, request_id=submission.request_id, scheduled_at=submission.scheduled_at, detail=submission.detail, operation_evidence=submission.operation_evidence)
    state.records[node.key].update(status=submission.status, scheduled_at=submission.scheduled_at, detail=submission.detail)
    _save(workspace, state)

def execute(plan, state, workspace, gateway, registry, supplied_parent, wait_seconds=300):
    """Execute only saved identities; each run has a positive bounded wait budget.

    Local/schema/authentication/scope failures raise CleanupError (CLI exit 1).
    Known drift and unfinished service operations remain durable exit-2 progress.
    """
    plan_to_dict(plan)
    state_to_dict(state)
    scope = validate_scope(plan, supplied_parent)
    if state.tenancy_id != plan.tenancy_id or state.parent_id != plan.parent_id:
        raise CleanupError('Journal boundary differs from plan')
    if type(wait_seconds) not in (int, float) or not math.isfinite(wait_seconds) or wait_seconds <= 0:
        raise CleanupError('Wait budget must be positive and finite')
    deadline = None
    for key in resource_records(state):
        _validate_invalidation_references(state, key)
    with workspace.locked():
        _scope_now(gateway, plan)
        _bind(registry, plan)
        for record in resource_records(state).values():
            record.pop('run_blocked', None)
        for _, attempt in list(bulk_attempt_records(state)):
            if attempt.get('service') == 'identity' and attempt.get('request_id'):
                missing = set(attempt['node_keys']) - set(plan.nodes)
                if missing:
                    if (attempt.get('home_region') == plan.home_region
                            and attempt.get('region') == plan.home_region
                            and all(_positive_iam_item(attempt, key) for key in attempt['node_keys'])):
                        continue
                    raise CleanupError('Pending original group lacks saved resource identities after refresh')
                outcome = inspect_bulk(gateway, plan, attempt['request_id'], registry=registry, workspace=workspace, state=state, wait_seconds=0)
                for key, status in outcome['resources'].items():
                    state.records[key]['status'] = status
                _save(workspace, state)
        with _observation_pass(registry):
            for key, old in plan.nodes.items():
                if key == plan.parent_id:
                    continue
                safe = _progress_node(plan, old, state, registry)
                observation = _observe(gateway, safe, scope, registry.handler_for(safe), state, plan)
                if state.records.get(key, {}).get('status') == 'deleted' and observation.status == 'unresolved' and any((a.get('resource_status', {}).get(key) == 'deleted' for a in attempt_history(state, key))):
                    continue
                _apply_observation(state, safe, observation)
        _save(workspace, state)
        live, added, moved = _inventory(gateway, plan, state, registry)
        hierarchy_drift = moved & scope or set(live.compartments) - scope or any((live.compartments.get(k) != v for k, v in plan.compartments.items() if state.records.get(k, {}).get('status') != 'deleted'))
        while not hierarchy_drift:
            _bind(registry, plan)
            with _observation_pass(registry):
                for key, old in plan.nodes.items():
                    if key == plan.parent_id:
                        continue
                    safe = _progress_node(plan, old, state, registry)
                    observation = _observe(gateway, safe, scope, registry.handler_for(safe), state, plan)
                    if state.records.get(key, {}).get('status') == 'deleted' and observation.status == 'unresolved':
                        continue
                    if state.records.get(key, {}).get('status') == 'failed':
                        continue
                    _apply_observation(state, safe, observation)
            _save(workspace, state)
            depths, blocked = compute_depths(live.nodes, live.edges)
            predecessors = {k: set() for k in live.nodes}
            for edge in live.edges:
                predecessors[edge.after].add(edge.before)
            ready = []
            for key in sorted(depths, key=lambda k: (-depths[k], k)):
                if key not in plan.nodes or key in moved or key in blocked:
                    continue
                node = live.nodes[key]
                record = state.records.get(key, {})
                if record.get('status') != 'present' or record.get('run_blocked'):
                    continue
                if any((state.records.get(p, {}).get('status') not in ('deleted', 'prepared') for p in predecessors[key])):
                    continue
                invalidations = _invalidations(record)
                if invalidations and datetime.fromisoformat(plan.created_at) <= datetime.fromisoformat(invalidations[-1]['observed_at']):
                    continue
                completed_ids = {token for entry in invalidations for token in entry['completed_attempt_ids']}
                history = [a for a in attempt_history(state, key) if a.get('attempt_id') not in completed_ids]
                if history and (history[-1].get('status') != 'failed' or history[-1].get('resource_status', {}).get(key, 'failed') != 'failed'):
                    continue
                if node.action in ('unresolved', 'retain', 'cascade') or node.blockers:
                    continue
                ready.append(node)
            if not ready:
                pending = [key for key, record in resource_records(state).items() if key in plan.nodes and record.get('status') == 'pending' and (plan.nodes[key].resource_type == 'Compartment' or registry.classify(plan.nodes[key]).action != 'schedule')]
                pending_groups = any(
                    attempt.get('service') == 'identity'
                    and attempt.get('request_id')
                    and attempt.get('status') == 'pending'
                    for _, attempt in bulk_attempt_records(state)
                )
                if not pending and not pending_groups:
                    break
                if deadline is None:
                    deadline = time.monotonic() + wait_seconds
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(5, remaining))
                for _, attempt in list(bulk_attempt_records(state)):
                    if attempt.get('service') == 'identity' and attempt.get('request_id') and (attempt.get('status') == 'pending'):
                        outcome = inspect_bulk(gateway, plan, attempt['request_id'], registry=registry, workspace=workspace, state=state, wait_seconds=0)
                        for key, status in outcome['resources'].items():
                            state.records[key]['status'] = status
                live, added, moved = _inventory(gateway, plan, state, registry)
                continue
            groups = bulk_groups(live, ready, registry)
            selected = groups[0] if groups else None
            if selected:
                candidate = replace(live, compartments=dict(plan.compartments))
                _, boundary_moved = _scope_now(gateway, plan)
                if boundary_moved:
                    break
                gateway.cleanup_scope = scope
                submission = submit_bulk(gateway, candidate, selected, str(uuid4()), registry=registry, workspace=workspace, state=state)
                if submission.request_id:
                    outcome = inspect_bulk(gateway, candidate, submission.request_id, registry=registry, workspace=workspace, state=state, wait_seconds=0)
                    for key, status in outcome['resources'].items():
                        state.records[key]['status'] = status
                _bind(registry, plan)
                with _observation_pass(registry):
                    for node in selected:
                        if type(registry.handler_for(node)) is Storage:
                            _apply_observation(state, node, _observe(gateway, node, scope, registry.handler_for(node), state, plan))
                _save(workspace, state)
            else:
                node = ready[0]
                handler = registry.handler_for(node)
                if node.resource_type == 'Compartment':
                    checked, extra, drift = _inventory(gateway, plan, state, registry)
                    if extra or drift or any((p.status != 'complete' for p in checked.probes if p.compartment_id == node.key)):
                        state.records[node.key]['run_blocked'] = True
                        _save(workspace, state)
                        live, added, moved = checked, extra, drift
                        continue
                    if any((k != node.key and (n.compartment_id == node.key or checked.compartments.get(k) == node.key) and (state.records.get(k, {}).get('status') != 'deleted') for k, n in checked.nodes.items())):
                        state.records[node.key]['run_blocked'] = True
                        _save(workspace, state)
                        continue
                safe = _progress_node(plan, plan.nodes[node.key], state, registry)
                observation = _observe(gateway, safe, scope, handler, state, plan)
                if observation.status != 'present':
                    _apply_observation(state, safe, observation)
                    _save(workspace, state)
                else:
                    _direct(gateway, plan, state, workspace, safe, handler, registry, observation)
                    _apply_observation(state, safe, _observe(gateway, safe, scope, handler, state, plan))
                    _save(workspace, state)
            live, added, moved = _inventory(gateway, plan, state, registry)
            hierarchy_drift = moved & scope or set(live.compartments) - scope or any((live.compartments.get(k) != v for k, v in plan.compartments.items() if state.records.get(k, {}).get('status') != 'deleted'))
        live, added, moved = _inventory(gateway, plan, state, registry)
        incomplete = bool(added or moved or hierarchy_drift or (not live.probes) or any((p.status != 'complete' for p in live.probes)) or any((k != plan.parent_id and state.records.get(k, {}).get('status') not in ('deleted', 'prepared') for k in plan.nodes)) or any((k != plan.parent_id and state.records.get(k, {}).get('status') not in ('deleted', 'prepared') for k in live.nodes)))
        incomplete = incomplete or any(record.get('proof_invalidations') and record.get('status') not in ('deleted', 'prepared')
                                       for record in resource_records(state).values())
        state.records.setdefault(plan.parent_id, {'status': 'retained', 'attempts': []})['verification'] = {'complete': not incomplete, 'added': sorted(added), 'moved': sorted(moved), 'coverage': [{'service': p.service, 'region': p.region, 'compartment_id': p.compartment_id, 'status': p.status} for p in live.probes]}
        _save(workspace, state)
        try:
            workspace.save_report(render_report(live, state) + cleanup_result(plan, state)[0] + '\n')
        except Exception as error:
            raise JournalError('Cannot persist final cleanup report') from error
    return state

def cleanup_result(plan, state):
    """Return the exact coverage-qualified outcome; internal groups are not nodes."""
    records = resource_records(state)
    verification = records.get(plan.parent_id, {}).get('verification', {})
    complete = verification.get('complete') is True and all((records.get(k, {}).get('status') in ('deleted', 'prepared') for k in plan.nodes if k != plan.parent_id))
    if complete:
        return (f'Cleanup complete for the recorded discovery coverage; retained parent: {plan.parent_id}.', 0)
    return (f'Cleanup incomplete for the recorded discovery coverage; retained parent: {plan.parent_id}. OCI has no universal resource inventory; preserve the work directory and rerun after resolving reported blockers.', 2)
