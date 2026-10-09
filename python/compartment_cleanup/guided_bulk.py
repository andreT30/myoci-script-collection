"""Targeted guided IAM bulk deletion with per-member durable evidence.

IAM offers no per-resource ETag precondition. Each member is freshly prepared
before submission, and only an exact terminal event plus typed corroboration
confirms deletion. Owner inventory corroborates the original scope only.
"""
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4
import oci
from . import actions
from .executor import (_catalog, _persist, _new_attempt, _work_id, _journal_context,
                       _recorded_attempt, BulkJournalError, _invalidations, _invalidate_contradicted_proofs)
from .gateway import GatewayError
from .handlers.core import BlockBootVolumes, _VOLUMES, _identity
from .journal import bulk_attempt_records, resource_records
from .model import CleanupError, Observation, Submission

_KINDS=frozenset(_VOLUMES)
_PENDING=frozenset(('ACCEPTED','IN_PROGRESS','CANCELING'))
_TERMINAL=frozenset(('SUCCEEDED','FAILED','CANCELED'))


def eligible_group(gateway,plan,nodes,registry):
    """Return the first bounded same-owner/region group of simple volume targets."""
    if gateway.tenancy_id!=plan.tenancy_id or gateway.home_region!=plan.home_region:
        raise CleanupError('Bulk authentication differs from saved scope')
    catalog=_catalog(gateway,plan.home_region)
    group=[];seen=set();owner=None
    for node in nodes:
        if node.key in seen or plan.nodes.get(node.key)!=node:
            raise CleanupError('Bulk target identity differs from saved plan')
        seen.add(node.key)
        if node.resource_type not in _KINDS or type(registry.handler_for(node)) is not BlockBootVolumes:
            continue
        safe=registry.classify(node)
        if safe.action!='delete' or safe.blockers or catalog.get(node.resource_type)!=():continue
        if any(node.metadata.get(k) for k in ('cascade_owner','cascade_members','cascade_snapshot')):continue
        if owner is None:owner=(node.compartment_id,node.region)
        if owner!=(node.compartment_id,node.region):continue
        # Group members must not have a known dependency on each other.
        if any(e.before in {n.key for n in group} and e.after==node.key or
               e.after in {n.key for n in group} and e.before==node.key for e in plan.edges):continue
        group.append(node)
        if len(group)==20:break
    return group


def submit_guided_bulk(gateway,plan,state,workspace,nodes,registry):
    """Persist one complete group before the single code-defined IAM write."""
    _journal_context(plan,workspace,state)
    if not nodes or eligible_group(gateway,plan,nodes,registry)!=nodes:
        raise CleanupError('Targets are not one eligible bounded guided bulk group')
    token=str(uuid4());_new_attempt(state,nodes,token)
    prepared=[]
    try:
        for node in nodes:prepared.append(actions.prepare_action(gateway,plan,node,registry))
        # Revalidate every captured ETag/effect and fresh owner chain at the write boundary.
        for original in prepared:
            fresh=actions.prepare_action(gateway,plan,original.node,registry)
            getattr(gateway,'_guided_prepared',{}).pop(id(fresh),None)
            if (original.service,original.operation,original.endpoint,original.params,original.effects)!=(fresh.service,fresh.operation,fresh.endpoint,fresh.params,fresh.effects):
                raise CleanupError('Bulk member ownership, ETag, or effects changed')
        attempt={'attempt_id':token,'started_at':datetime.now(timezone.utc).isoformat(),
                 'home_region':plan.home_region,'compartment_id':nodes[0].compartment_id,
                 'node_keys':[n.key for n in nodes],'node_regions':{n.key:n.region for n in nodes},
                 'status':'attempting','request_id':None,'resource_evidence':{},'resource_status':{},
                 'service':'identity','operation':'bulk_delete_resources','region':plan.home_region,
                 'opc_retry_token':token,'guided_bulk':True,'chunk_size':20,
                 'resources':[{'identifier':n.key,'entity_type':n.resource_type,'metadata':{}} for n in nodes],
                 'catalog':{n.resource_type:[] for n in nodes},
                 'preflight':{p.node.key:{'compartment_id':p.node.compartment_id,'etag':p.params['if_match'],
                                      'effects':list(p.effects)} for p in prepared}}
        details=oci.identity.models.BulkDeleteResourcesDetails(resources=[oci.identity.models.BulkActionResource(**r) for r in attempt['resources']])
        _persist(workspace,state,nodes,attempt)
        try:
            _,headers=gateway.write('identity',plan.home_region,'bulk_delete_resources',{
                'compartment_id':nodes[0].compartment_id,'bulk_delete_resources_details':details,'opc_retry_token':token})
        except GatewayError as error:
            attempt['status']='unresolved'
            if error.status in (401, 403):
                _persist(workspace,state,nodes,attempt)
                raise
        except Exception:
            attempt['status']='unresolved'
        else:
            attempt['request_id']=_work_id(headers)
            attempt['status']='pending' if attempt['request_id'] else 'unresolved'
        _persist(workspace,state,nodes,attempt)
        for n in nodes:state.records[n.key]['status']=attempt['status']
        actions._save(workspace,state)
        return Submission(attempt['status'],attempt['request_id'],None,
                          'Bulk accepted; exact per-member completion must be verified',deepcopy(attempt))
    finally:
        for p in prepared:getattr(gateway,'_guided_prepared',{}).pop(id(p),None)


def _absence(gateway,plan,node,state):
    """Exact typed 404 plus fresh original-owner inventory, never tenancy proof."""
    actions._scope(gateway,plan,node)
    try:
        row,_,_,_,_,_=actions._target(gateway,plan,node)
        if row.get('lifecycle_state')=='TERMINATED':return True
        _invalidate_contradicted_proofs(state,node,Observation('present',node.compartment_id,
                                       row.get('lifecycle_state',''),None,None,
                                       'Fresh typed identity contradicts bulk completion'),plan)
        return False
    except GatewayError as error:
        if error.status in (401, 403):raise
        if error.status!=404:return False
    service,listing,_,_,_=_VOLUMES[node.resource_type]
    params={'compartment_id':node.compartment_id}
    seen=set()
    for row in gateway.items(service,node.region,listing,params):
        _identity(row,owner=node.compartment_id)
        if row['id'] in seen:raise CleanupError('Duplicate owner inventory identity')
        seen.add(row['id'])
        if row['id']==node.key:return False
    return True


def _failure_error(wr,node,request_id):
    # A generic group failure cannot select a dependency resolver. Only an exact
    # identified member error can expose service diagnostics to the guided flow.
    errors=[e for e in wr.get('errors') or [] if e.get('identifier')==node.key or e.get('resource_id')==node.key]
    if len(errors)!=1:return None
    e=errors[0]
    if not isinstance(e.get('code'),str) or not isinstance(e.get('message'),str):return None
    error=GatewayError('identity','bulk_delete_resources',e.get('status'),e['code'],request_id,e['message'])
    error.verified_member_failure=True
    return error


def reconcile_guided_bulk(gateway,plan,state,workspace,registry):
    """Return member Observations, exact member errors, and group snapshots.

    Legacy IAM volume groups are read using the same immutable endpoint and
    allowlist checks. Missing work-request IDs remain unresolved without replay.
    """
    _journal_context(plan,workspace,state);resource_records(state)
    result={'resources':{},'errors':{},'groups':{}}
    for group_key,original in list(bulk_attempt_records(state)):
        if original.get('service')!='identity' or original.get('operation')!='bulk_delete_resources':continue
        keys=original['node_keys']
        if any(k not in plan.nodes or plan.nodes[k].resource_type not in _KINDS for k in keys):continue
        nodes=[plan.nodes[k] for k in keys]
        statuses={k:'unresolved' for k in keys};attempt=deepcopy(original);wr=None
        try:
            if gateway.tenancy_id!=plan.tenancy_id or gateway.home_region!=plan.home_region:
                raise CleanupError('Work request authentication changed')
            request_id=attempt.get('request_id')
            if not request_id:raise CleanupError('Response did not record an exact work request')
            attempt,nodes=_recorded_attempt(plan,state,workspace,request_id)
            expected={r['identifier']:r['entity_type'] for r in attempt['resources']}
            if len(nodes)>20 or len(expected)!=len(nodes) or set(expected)!=set(keys) or any(
                expected[n.key]!=n.resource_type or n.compartment_id!=attempt['compartment_id'] or
                n.region!=attempt['node_regions'].get(n.key) for n in nodes) or len({n.region for n in nodes})!=1:
                raise CleanupError('Original bulk member scope changed')
            for n in nodes:actions._scope(gateway,plan,n)
            wr,_=gateway.read('identity',plan.home_region,'get_work_request',{'work_request_id':request_id})
            attempt['work_request']=deepcopy(wr);_persist(workspace,state,nodes,attempt)
            if not isinstance(wr,dict) or wr.get('id')!=request_id or wr.get('compartment_id')!=attempt['compartment_id'] or wr.get('operation_type') not in ('BULK_DELETE_RESOURCES','UNKNOWN_ENUM_VALUE',None):
                raise CleanupError('Work request correlation failed')
            if wr.get('status') not in _PENDING|_TERMINAL:raise CleanupError('Unknown work request state')
            for field in ('errors','logs'):
                if wr.get(field) is not None and (not isinstance(wr[field],list) or any(not isinstance(v,dict) for v in wr[field])):
                    raise CleanupError('Malformed work request diagnostics')
            rows=wr.get('resources')
            if not isinstance(rows,list):raise CleanupError('Missing exact resource evidence')
            entries={}
            for row in rows:
                if not isinstance(row,dict) or row.get('identifier') not in expected or row['identifier'] in entries or row.get('entity_type')!=expected[row['identifier']]:
                    raise CleanupError('Ambiguous work request resource identity')
                entries[row['identifier']]=row
            for n in nodes:
                row=entries.get(n.key,{})
                if wr['status'] in _PENDING:statuses[n.key]='pending';continue
                if row.get('action_type')=='FAILED':
                    statuses[n.key]='failed'
                    error=_failure_error(wr,n,request_id)
                    if error:result['errors'][n.key]=error
                elif row.get('action_type')=='DELETED':
                    attempt['resource_evidence'][n.key]=deepcopy(row)
                    _persist(workspace,state,nodes,attempt)
                    if any(attempt['attempt_id'] in e['attempt_ids'] for e in _invalidations(state.records[n.key])):continue
                    try:
                        if _absence(gateway,plan,n,state):statuses[n.key]='deleted'
                    except GatewayError as error:
                        if error.status in (401, 403):raise
                    except Exception:pass
        except BulkJournalError:raise
        except GatewayError as error:
            if error.status in (401, 403):raise
        except Exception:pass
        attempt['resource_status']=statuses
        attempt['status']='deleted' if all(s=='deleted' for s in statuses.values()) else 'pending' if any(s=='pending' for s in statuses.values()) else 'failed' if any(s=='failed' for s in statuses.values()) else 'unresolved'
        _persist(workspace,state,nodes,attempt)
        for n in nodes:
            status=statuses[n.key]
            observation=Observation(status,n.compartment_id,'',None,None,
                                    'Exact bulk member result; original owner scope corroborated' if status=='deleted' else 'Bulk member '+status+'; manual resolution may be required')
            result['resources'][n.key]=observation
            state.records[n.key].update(status=status,detail=observation.detail)
        actions._save(workspace,state)
        result['groups'][group_key]={'status':attempt['status'],'request_id':attempt.get('request_id'),'resources':dict(statuses)}
    return result
