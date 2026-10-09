"""Confirmed bucket-owned batches using the existing conditional Storage contract.

Every batch member is a previously confirmed exact object. Shared group receipts
stay in their durable group journal; per-member postflight uses immutable copies.
Unknown/missing results block replay. Versioned objects remain individual actions.
"""
from copy import deepcopy
from uuid import uuid4

from .actions import _scope, reconcile_action, _ReadAuthorizationTracker
from .executor import submit_bulk, bulk_groups, BulkJournalError, JournalError, _invalidate_contradicted_proofs
from .gateway import GatewayError
from .handlers.storage import Storage
from .journal import bulk_attempt_records, attempt_history
from .model import CleanupError


def _save(workspace,state):
    try:workspace.save_state(state)
    except Exception as error:
        raise JournalError('Cannot persist storage batch observations; stop all mutations') from error


def reconcile_storage_batches(gateway,plan,state,workspace,registry):
    """Reconcile exact positive item receipts, never infer success from absence."""
    changed=False
    authorization_error=None
    for _,attempt in list(bulk_attempt_records(state)):
        if (attempt.get('service'),attempt.get('operation'))!=('object_storage','batch_delete_objects'):continue
        keys=attempt.get('node_keys',[])
        evidence=attempt.get('resource_evidence',{})
        statuses=attempt.setdefault('resource_status',{})
        for key in keys:
            node=plan.nodes.get(key)
            record=state.records.get(key)
            if node is None or record is None or node.resource_type!='ObjectStorageObject':continue
            if (node.region!=attempt.get('node_regions',{}).get(key)
                    or node.compartment_id!=attempt.get('compartment_id')):
                record.update(status='unresolved',detail='Storage batch member scope or region changed')
                statuses[key]='unresolved';changed=True;continue
            if statuses.get(key)=='failed':
                # Exact failed item results are already persisted by Storage.
                failure=evidence.get(key,{}).get('failure') or {}
                record.update(status='failed',detail='Exact storage batch item failed; refresh before individual retry',
                              failure=deepcopy(failure))
                if failure.get('status_code') in (401,403):
                    authorization_error=GatewayError('object_storage','batch_delete_objects',
                        failure['status_code'], message=failure.get('message'))
                changed=True;continue
            if not isinstance(evidence.get(key),dict):
                record.update(status='unresolved',detail='Storage batch has no exact positive item receipt; replay blocked')
                statuses[key]='unresolved';changed=True;continue
            local=deepcopy(record)
            local['attempts']=[deepcopy(a) for a in attempt_history(state,key)]
            observation=reconcile_action(gateway,plan,node,local,registry)
            _invalidate_contradicted_proofs(state,node,observation,plan)
            if observation.status=='present':
                # A readable object cannot override a prior accepted request by
                # becoming eligible for a blind replay.
                status='pending' if statuses.get(key)!='deleted' else 'unresolved'
            else:status=observation.status
            record.update(status=status,lifecycle_state=observation.lifecycle_state,
                          detail=observation.detail,scheduled_at=observation.scheduled_at)
            statuses[key]=status;changed=True
        values=[statuses.get(key,'unresolved') for key in keys]
        if values and all(value=='deleted' for value in values):attempt['status']='deleted'
        elif values and all(value in ('deleted','failed') for value in values):attempt['status']='failed'
        else:attempt['status']='unresolved' if any(value=='unresolved' for value in values) else 'pending'
    if changed:_save(workspace,state)
    if authorization_error is not None:raise authorization_error


def try_storage_batch(gateway,plan,state,workspace,nodes,registry):
    """Submit at most one bounded ready object group, returning consumed keys."""
    if registry is None:return []
    candidates=[]
    for node in nodes:
        if node.resource_type!='ObjectStorageObject' or type(registry.handler_for(node)) is not Storage:continue
        if state.records.get(node.key,{}).get('attempts'):continue
        candidates.append(node)
    if len(candidates)<2:return []
    try:
        groups=[group for group in bulk_groups(plan,candidates,registry) if len(group)>1]
    except CleanupError:return []
    for group in groups:
        tracked=_ReadAuthorizationTracker(gateway)
        handler=registry.handler_for(group[0]);handler.bind_plan(plan.nodes.values())
        for node in group:_scope(gateway,plan,node)
        eligible=handler.batch_group(tracked,group,set(plan.compartments))
        if tracked.error is not None:raise tracked.error
        if eligible is None:continue
        try:
            submit_bulk(tracked,plan,group,str(uuid4()),registry=registry,
                        workspace=workspace,state=state)
        except BulkJournalError as error:
            raise JournalError('Storage batch journal failed; stop all mutations') from error
        if tracked.error is not None:raise tracked.error
        reconcile_storage_batches(gateway,plan,state,workspace,registry)
        return [node.key for node in group]
    return []
