"""One durable bulk attempt per group, with narrow resource history references.

Resource consumers must use resource_records rather than enumerate State.records.
Resolved attempt_history values are shared read-only views; update bulk attempts
through the executor's persistence boundary, never by modifying a resolved view.
Direct operation histories remain inline and are preserved unchanged.
"""
import hashlib

from .model import CleanupError

BULK_PREFIX = 'cleanup-bulk:'


def bulk_record_key(attempt_id):
    if not isinstance(attempt_id,str) or not attempt_id.strip():
        raise CleanupError('Bulk journal requires a nonempty attempt identity')
    return BULK_PREFIX + hashlib.sha256(attempt_id.encode('utf-8')).hexdigest()


def _group(key, record):
    reserved = key.startswith(BULK_PREFIX)
    marked = isinstance(record,dict) and record.get('record_type') == 'bulk_attempt'
    if not reserved and not marked:
        return None
    if not reserved or not marked or set(record) != {'record_type','attempt'}:
        raise CleanupError('Malformed reserved bulk journal record')
    attempt = record['attempt']
    if not isinstance(attempt,dict) or bulk_record_key(attempt.get('attempt_id')) != key:
        raise CleanupError('Bulk group key does not match its immutable attempt identity')
    nodes = attempt.get('node_keys')
    if (not isinstance(nodes,list) or not nodes or any(not isinstance(k,str) or not k for k in nodes)
            or len(set(nodes)) != len(nodes) or any(k.startswith(BULK_PREFIX) for k in nodes)):
        raise CleanupError('Malformed bulk group resource identities')
    return attempt


def resource_records(state):
    """Return only resources and validate all group references in linear time."""
    resources={};groups={}
    for key,record in state.records.items():
        attempt=_group(key,record)
        if attempt is None:resources[key]=record
        else:groups[key]=(attempt['attempt_id'],set(attempt['node_keys']))
    for node_key,record in resources.items():
        history=record.get('attempts',[])
        if not isinstance(history,list):raise CleanupError('Malformed resource attempt history')
        for item in history:
            if not isinstance(item,dict):raise CleanupError('Malformed resource attempt')
            if 'bulk_attempt' not in item:continue
            key=item['bulk_attempt']
            if set(item)!={'bulk_attempt','attempt_id'} or not isinstance(key,str) or key not in groups:
                raise CleanupError('Malformed or missing bulk history reference')
            token,nodes=groups[key]
            if item['attempt_id']!=token or node_key not in nodes:
                raise CleanupError('Bulk history reference does not match its resource group')
    return resources


def bulk_attempt_records(state):
    """Yield (internal group key, shared attempt) exactly once per group."""
    for key,record in state.records.items():
        attempt = _group(key,record)
        if attempt is not None:
            yield key,attempt


def attempt_history(state, node_key):
    """Yield each resource's inline or resolved bulk history without payload copies."""
    record = state.records.get(node_key,{})
    if _group(node_key,record) is not None:
        raise CleanupError('An internal bulk group is not a resource record')
    history = record.get('attempts',[])
    if not isinstance(history,list):
        raise CleanupError('Malformed resource attempt history')
    for item in history:
        if not isinstance(item,dict):
            raise CleanupError('Malformed resource attempt')
        if 'bulk_attempt' not in item:
            yield item
            continue
        if set(item) != {'bulk_attempt','attempt_id'}:
            raise CleanupError('Malformed bulk history reference')
        key = item['bulk_attempt']
        if not isinstance(key,str) or key not in state.records:
            raise CleanupError('Bulk history refers to a missing durable group')
        attempt = _group(key,state.records[key])
        if attempt is None or item['attempt_id'] != attempt['attempt_id'] or node_key not in attempt['node_keys']:
            raise CleanupError('Bulk history reference does not match its resource group')
        yield attempt
