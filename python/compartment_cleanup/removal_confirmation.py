"""Explicit operator acknowledgement of inaccessible scheduled resources.

An empty Search result is evidence to display, never an automatic deletion proof.
Acknowledgements bind an exact resource identity to the retained parent and tenancy.
"""
from copy import deepcopy
from datetime import datetime, timezone
import re

import oci

from .graph import compute_depths
from .inventory import _refresh_schedule, canonical_type
from .model import CleanupError, Observation

_KINDS = {'Key', 'Secret', 'Vault', 'Certificate', 'CertificateAuthority'}
_OCID = re.compile(r'ocid1\.[A-Za-z0-9_.-]{1,500}\Z')


def _identity(plan, node):
    return {'tenancy_id':plan.tenancy_id, 'parent_id':plan.parent_id,
            'identifier':node.key, 'resource_type':node.resource_type,
            'region':node.region, 'compartment_id':node.compartment_id}


def _matches_confirmation(plan, state, node):
    record = state.records.get(node.key, {})
    value = record.get('operator_confirmation')
    return (node.key != plan.parent_id and node.resource_type in _KINDS
            and node.compartment_id in plan.compartments
            and isinstance(value, dict)
            and value.get('identity') == _identity(plan, node)
            and value.get('answer') == 'YES' and value.get('source') == 'operator')


def _confirmed(plan, state, node):
    return (state.records.get(node.key, {}).get('status') == 'deleted'
            and _matches_confirmation(plan, state, node))


def retire_confirmed(plan, state):
    """Remove acknowledged targets from the active map, retaining all journals."""
    done = {key for key, node in plan.nodes.items() if _confirmed(plan, state, node)}
    for key in done:
        del plan.nodes[key]
    plan.edges = [edge for edge in plan.edges if edge.before not in done and edge.after not in done]
    plan.depths, _ = compute_depths(plan.nodes, plan.edges)


def _candidate(plan, node):
    failure = node.metadata.get('schedule_verification', {})
    if (node.key == plan.parent_id or node.resource_type not in _KINDS
            or node.compartment_id not in plan.compartments
            or not isinstance(failure, dict) or failure.get('status') != 'failed'
            or failure.get('observed_at') != plan.created_at):
        return False
    return (failure.get('http_status') == 404 or node.resource_type == 'Key'
            and failure.get('detail') in ('Owning vault is deleted; key deletion cannot be verified',
                                         'Known key vault identity is unavailable'))


def reconcile_removals(gateway, plan, state, interaction):
    """Read exact Search evidence, ask once, and record the operator's decision.

    Caller persists the updated state and plan before proceeding. No OCI writes
    occur here. A fresh successful typed read overrides an old acknowledgement.
    """
    if (gateway.tenancy_id != plan.tenancy_id or state.tenancy_id != plan.tenancy_id
            or state.parent_id != plan.parent_id):
        raise CleanupError('Removal confirmation scope differs from authenticated tenancy')
    candidates = []
    evidence = {}
    for key, node in list(plan.nodes.items()):
        if _matches_confirmation(plan, state, node):
            metadata = state.records[key]['operator_confirmation'].get('known_metadata', {})
            if isinstance(metadata, dict) and 'vault_id' in metadata and 'vault_id' not in node.metadata:
                from dataclasses import replace
                node = replace(node, metadata=dict(node.metadata, vault_id=metadata['vault_id']))
            checked = _refresh_schedule(gateway, node, set(plan.compartments), plan.created_at)
            observation = checked.metadata.get('schedule_observation')
            if isinstance(observation, dict) and observation.get('observed_at') == plan.created_at:
                if observation['lifecycle_state'] != 'DELETED':
                    from .executor import _invalidate_contradicted_proofs, _apply_observation
                    record = state.records[key]
                    old = record.pop('operator_confirmation')
                    record.setdefault('operator_confirmation_history', []).append(old)
                    record.pop('completion_basis', None)
                    live = Observation('pending' if observation['lifecycle_state'] in
                        ('PENDING_DELETION','SCHEDULING_DELETION','DELETING') else 'present',
                        node.compartment_id, observation['lifecycle_state'], observation['scheduled_at'],
                        None, 'Live resource read contradicts operator-confirmed removal')
                    _invalidate_contradicted_proofs(state, checked, live, plan)
                    _apply_observation(state, checked, live)
                    plan.nodes[key] = checked
                    node = checked
                    interaction.show('Resource is still readable; reopening ' + (node.display_name or key))
            if _matches_confirmation(plan, state, node):
                state.records[key].update(status='deleted', completion_basis='operator_confirmation',
                    detail='Operator confirmed already deleted; acknowledgement preserved')
                continue
        if not _candidate(plan, node) or not _OCID.fullmatch(key):
            continue
        details = oci.resource_search.models.StructuredSearchDetails(
            query="query all resources where identifier = '" + key + "'")
        try:
            rows = gateway.items('search', node.region, 'search_resources', {'search_details':details})
            if any(not isinstance(row, dict) or row.get('identifier') != key
                   or row.get('compartment_id') != node.compartment_id
                   or canonical_type(row.get('resource_type')) != node.resource_type for row in rows):
                raise CleanupError('Exact Search returned conflicting resource identity or scope')
        except Exception:
            interaction.show('Exact OCID Search failed for ' + (node.display_name or key)
                             + '; no absence result or confirmation inferred.')
            continue
        result = {'region':node.region, 'matches':len(rows), 'observed_at':plan.created_at}
        evidence[key] = {'search':result, 'resource_read':deepcopy(node.metadata['schedule_verification'])}
        interaction.show((node.display_name or key) + ' | ' + node.resource_type + ' | ' + node.region)
        interaction.show('OCID: ' + key)
        interaction.show('Resource read: ' + node.metadata['schedule_verification']['detail'])
        interaction.show('Exact OCID Search: ' + str(len(rows)) + ' matches. '
                         + ('Search still lists this identity; it may be stale.' if rows else
                            'Not found in Search; this alone does not prove deletion.'))
        candidates.append(node)
    if candidates and interaction.confirm_removed(candidates):
        for node in candidates:
            record = state.records.setdefault(node.key, {'attempts':[]})
            confirmation = dict(evidence[node.key], identity=_identity(plan, node), answer='YES',
                                source='operator', confirmed_at=datetime.now(timezone.utc).isoformat(),
                                known_metadata={k:node.metadata[k] for k in ('vault_id',) if k in node.metadata})
            record.update(status='deleted', completion_basis='operator_confirmation',
                          operator_confirmation=confirmation,
                          detail='Operator confirmed already deleted; no OCI deletion submitted')
        interaction.show('Recorded operator-confirmed removals; continuing the report.')
    retire_confirmed(plan, state)
