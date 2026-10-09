"""Search evidence inventory; SDK operations remain code-defined contracts.

Search's return allAdditionalFields clause is restricted to a single resource
kind (Oracle Search/Concepts/querysyntax.htm). The bounded all-resource queries
therefore preserve any returned additional_details without adding that clause.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import re

import oci

from .gateway import discover_scope
from .graph import compute_depths, validate_scope
from .journal import resource_records
from .model import CleanupError, Edge, Node, Plan, Probe, State, Observation, SCHEMA_VERSION, _json_value
from .handlers.scheduled import _utc

_COMPARTMENT = re.compile(r'ocid1\.compartment\.[a-z0-9]+\.[a-z0-9.-]*\.[a-zA-Z0-9_-]+\Z')
# Search names and service handler names are distinct explicit contracts.
_SEARCH_TYPES = {'DHCPOptions':'DhcpOptions', 'DnsResolver':'Resolver', 'VaultSecret':'Secret'}
_SCHEDULE_READS = {
    'Certificate':('certificates', 'get_certificate', 'certificate_id'),
    'CertificateAuthority':('certificates', 'get_certificate_authority', 'certificate_authority_id'),
    'Vault':('kms_vault', 'get_vault', 'vault_id'),
    'Key':('kms_management', 'get_key', 'key_id'),
    'Secret':('vault', 'get_secret', 'secret_id'),
}
_PENDING = {'pending', 'submitted', 'uncertain', 'unresolved', 'in_progress', 'ambiguous'}
_PENDING_LIFECYCLES = {'PENDING_DELETION', 'SCHEDULING_DELETION', 'DELETING'}


def canonical_type(search_type: str) -> str:
    """Translate only established Search aliases; unknown types stay visible."""
    return _SEARCH_TYPES.get(search_type, search_type)


def _blocked(node, reason):
    return replace(node, action='unresolved', blockers=tuple(sorted(set(node.blockers + (reason,)))))


def _classify(node, registry):
    # Registry classification deliberately discards untyped fields. Restore the
    # separate non-authorizing Search evidence after that policy has run.
    evidence = {k:deepcopy(v) for k,v in node.metadata.items()
                if k in ('search', 'search_regions', 'search_sightings', 'historical_inventory')}
    classified = registry.classify(node)
    return replace(classified, metadata=dict(classified.metadata, **evidence))


def _search_node(row, region, batch, registry):
    if type(row) is not dict:
        raise CleanupError('Malformed Search resource summary')
    _json_value(row)
    key, kind, owner = (row.get(k) for k in ('identifier', 'resource_type', 'compartment_id'))
    if (not isinstance(key, str) or not key.strip() or not isinstance(kind, str) or not kind.strip()
            or not isinstance(owner, str) or owner not in batch):
        raise CleanupError('Malformed or out-of-scope Search resource identity')
    for field in ('display_name', 'lifecycle_state'):
        if row.get(field) is not None and not isinstance(row[field], str):
            raise CleanupError('Malformed Search resource attribute')
    return _classify(Node(key, canonical_type(kind), region, owner, row.get('display_name') or '',
                          row.get('lifecycle_state') or '', '', 'unresolved',
                          {'search':deepcopy(row), 'search_regions':[region],
                           'search_sightings':{region:[deepcopy(row)]}}), registry)


def _merge(nodes, node):
    old = nodes.get(node.key)
    if old is None:
        nodes[node.key] = node
        return
    metadata = deepcopy(old.metadata)
    metadata['search_regions'] = sorted(set(metadata['search_regions'] + [node.region]))
    sightings = metadata['search_sightings'].setdefault(node.region, [])
    if node.metadata['search'] not in sightings:
        sightings.append(deepcopy(node.metadata['search']))
    merged = replace(old, metadata=metadata)
    if (old.resource_type, old.compartment_id) != (node.resource_type, node.compartment_id):
        merged = _blocked(merged, 'Conflicting Search identity or ownership')
    nodes[node.key] = merged


def _known_pending(node, record):
    unfinished = any(type(a) is dict and a.get('status') in {'attempting','uncertain','unresolved','pending'}
                     for a in record.get('attempts', []))
    if record.get('status') in {'deleted','completed'}:
        return unfinished
    return (record.get('status') in _PENDING or node.lifecycle_state in _PENDING_LIFECYCLES
            or node.metadata.get('scheduled_at') is not None or record.get('scheduled_at') is not None
            or bool(record.get('attempts')) and record.get('status') not in {'deleted', 'completed'})


def _refresh_schedule(gateway, node, scope, observed_at):
    """Only known scheduled identities receive target-specific service reads."""
    node = replace(node, metadata={k:deepcopy(v) for k,v in node.metadata.items() if k != 'schedule_observation'})
    contract = _SCHEDULE_READS.get(node.resource_type)
    if contract is None:
        return _blocked(node, 'Known pending identity has no targeted schedule read')
    try:
        endpoint = None
        if node.resource_type == 'Key':
            vault_id = node.metadata.get('vault_id')
            if not isinstance(vault_id, str) or not vault_id.startswith('ocid1.vault.'):
                raise CleanupError('Known key vault identity is unavailable')
            vault, _ = gateway.read('kms_vault', node.region, 'get_vault', {'vault_id':vault_id})
            if vault.get('id') != vault_id or vault.get('compartment_id') not in scope:
                raise CleanupError('Known key vault is outside live scope')
            endpoint = vault.get('management_endpoint')
            # Gateway binds this endpoint to the preceding authoritative vault
            # response and validates its region/realm. Search endpoints are unused.
            if not isinstance(endpoint, str) or not endpoint:
                raise CleanupError('Known key endpoint cannot be renewed')
        service, operation, parameter = contract
        row, _ = gateway.read(service, node.region, operation, {parameter:node.key}, endpoint=endpoint)
        if row.get('id') != node.key or row.get('compartment_id') != node.compartment_id or row.get('compartment_id') not in scope:
            raise CleanupError('Known schedule identity or ownership changed')
        if node.resource_type == 'Key' and row.get('vault_id') != node.metadata.get('vault_id'):
            raise CleanupError('Known key vault membership changed')
        lifecycle = row.get('lifecycle_state')
        if not isinstance(lifecycle, str) or not lifecycle:
            raise CleanupError('Known schedule lifecycle is unavailable')
        metadata = deepcopy(node.metadata)
        when = _utc(row.get('time_of_deletion'))
        if 'scheduled_at' in metadata and metadata['scheduled_at'] != when:
            metadata.setdefault('schedule_history', []).append({'scheduled_at':metadata['scheduled_at']})
        metadata['scheduled_at'] = when
        metadata['schedule_observation'] = {'lifecycle_state':lifecycle, 'scheduled_at':when, 'observed_at':observed_at}
        return replace(node, lifecycle_state=lifecycle, metadata=metadata)
    except Exception:
        return _blocked(node, 'Known schedule lacks authoritative in-scope verification')


def collect_inventory(gateway, parent_id: str, registry, previous: Plan | None = None, state=None) -> Plan:
    if not isinstance(parent_id, str) or not _COMPARTMENT.fullmatch(parent_id):
        raise CleanupError('Invalid retained compartment OCID')
    created_at = datetime.now(timezone.utc).isoformat()
    tenancy, home, regions, compartments = discover_scope(gateway, parent_id)
    compartments = dict(compartments)
    if any(not _COMPARTMENT.fullmatch(c) for c in compartments):
        raise CleanupError('Invalid discovered compartment OCID')
    if previous is not None:
        validate_scope(previous, parent_id)
        if previous.tenancy_id != tenancy:
            raise CleanupError('Previous plan belongs to another tenancy')
    if state is not None and (state.parent_id != parent_id or state.tenancy_id != tenancy):
        raise CleanupError('State belongs to another cleanup boundary')
    records = resource_records(state) if state is not None else {}
    nodes, probes = {}, []
    ordered = sorted(compartments)
    for region in regions:
        for offset in range(0, len(ordered), 50):
            batch = ordered[offset:offset + 50]
            try:
                values = ', '.join(f"'{c}'" for c in batch)
                details = oci.resource_search.models.StructuredSearchDetails(
                    query=f'query all resources where compartmentId IN ({values})')
                rows = gateway.items('search', region, 'search_resources', {'search_details':details})
                # Validate a complete paginated batch before accepting any node.
                found = [_search_node(row, region, batch, registry) for row in rows]
                if any((n.key in compartments) != (n.resource_type == 'Compartment') for n in found):
                    raise CleanupError('Search identity conflicts with authenticated compartment scope')
                for node in found:
                    node = replace(node, metadata=dict(node.metadata, search_observed_at=created_at))
                    _merge(nodes, node)
                probes.extend(Probe('search', region, c, 'complete', '') for c in batch)
                progress = getattr(gateway, 'progress', None)
                if progress is not None:
                    progress(f'Search found {len(found)} resources in {region} across {len(batch)} compartments')
            except Exception:
                probes.extend(Probe('search', region, c, 'failed', 'Search inventory failed') for c in batch)
    if previous is not None:
        for key, old in previous.nodes.items():
            record = records.get(key, {})
            pending = _known_pending(old, record)
            known_present = (record.get('status') in {'discovered','present'}
                             or not record and 'search' in old.metadata)
            if old.resource_type == 'Compartment' or not (pending or known_present
                    and old.lifecycle_state not in {'DELETED','TERMINATED','DETACHED'}):
                continue
            current = nodes.get(key)
            if old.compartment_id not in compartments:
                # Preserve the recorded boundary as explicitly historical evidence;
                # guided actions must revalidate every owner against live IAM.
                owner = old.compartment_id
                while owner not in compartments:
                    compartments[owner] = previous.compartments[owner]
                    probes.append(Probe('historical_scope', home, owner, 'failed', 'Pending identity owner absent from live hierarchy'))
                    owner = previous.compartments[owner]
            if current is None:
                kept = _classify(replace(old, metadata=deepcopy(old.metadata)), registry)
                kept = replace(kept, metadata={**deepcopy(old.metadata), **kept.metadata, 'historical_inventory':True})
            elif (current.resource_type, current.compartment_id) != (old.resource_type, old.compartment_id):
                metadata = dict(current.metadata, historical_pending=deepcopy(old.metadata))
                nodes[key] = _blocked(replace(current, metadata=metadata), 'Pending identity type or ownership changed')
                continue
            else:
                metadata = dict(deepcopy(old.metadata), **deepcopy(current.metadata))
                kept = replace(current, metadata=metadata)
            if 'scheduled_at' not in kept.metadata and record.get('scheduled_at') is not None:
                kept = replace(kept, metadata=dict(kept.metadata, scheduled_at=record['scheduled_at']))
            # A saved owner absent from live IAM must never authorize a GET chain.
            live_scope = set(getattr(gateway, 'cleanup_scope', ()))
            if kept.compartment_id not in live_scope:
                nodes[key] = _blocked(kept, 'Known identity is outside the live compartment scope')
            elif pending and kept.resource_type in _SCHEDULE_READS:
                nodes[key] = _refresh_schedule(gateway, kept, live_scope, created_at)
            elif current is None:
                nodes[key] = _blocked(kept, 'Previously known resource is absent from Search; current presence is unverified')
            else:
                nodes[key] = kept
    for key, node in list(nodes.items()):
        if (previous is None or key not in previous.nodes) and _known_pending(node, records.get(key, {})):
            nodes[key] = _refresh_schedule(gateway, node, set(gateway.cleanup_scope), created_at)
    probes.append(Probe('inventory_mode', home, parent_id, 'complete', 'search_inventory'))
    live_scope = set(gateway.cleanup_scope)
    for compartment, owner in compartments.items():
        search_node = nodes.get(compartment)
        metadata = deepcopy(search_node.metadata) if search_node else {}
        record = getattr(gateway, 'compartment_records', {}).get(compartment, {})
        nodes[compartment] = Node(compartment, 'Compartment', home, owner, record.get('name') or '',
                                  record.get('lifecycle_state') or 'ACTIVE', 'compartment',
                                  'retain' if compartment == parent_id else 'delete', metadata)
        if compartment not in live_scope:
            nodes[compartment] = _blocked(nodes[compartment], 'Historical compartment lacks live scope verification')
        elif search_node is not None and (search_node.compartment_id != owner
                or 'Conflicting Search identity or ownership' in search_node.blockers):
            if compartment == parent_id:
                nodes[compartment] = replace(nodes[compartment], blockers=('Conflicting Search compartment ownership',))
            else:
                nodes[compartment] = _blocked(nodes[compartment], 'Conflicting Search compartment ownership')
    edges = [Edge(key, node.compartment_id, 'Compartment containment') for key,node in nodes.items() if key != parent_id]
    depths, _ = compute_depths(nodes, edges)
    plan = Plan(SCHEMA_VERSION, tenancy, parent_id, home, created_at,
                compartments, nodes, edges, probes, depths, {})
    validate_scope(plan, parent_id)
    return plan


def reconcile_inventory_state(plan: Plan, state: State) -> State:
    """Retire contradicted completion proofs and copy fresh schedule observations.

    Search presence only retires evidence; typed reads confirm schedule changes.
    A marker from an earlier plan is evidence only. Only a successful GET from
    this collection carries the exact current plan timestamp.
    """
    validate_scope(plan, plan.parent_id)
    if state.parent_id != plan.parent_id or state.tenancy_id != plan.tenancy_id or state.schema_version != plan.schema_version:
        raise CleanupError('State belongs to another cleanup boundary')
    records = deepcopy(state.records)
    updated = State(state.schema_version, state.tenancy_id, state.parent_id, records)
    from .executor import _invalidate_contradicted_proofs
    for key, node in plan.nodes.items():
        search = node.metadata.get('search')
        if (node.metadata.get('search_observed_at') == plan.created_at and type(search) is dict
                and search.get('lifecycle_state') not in {'DELETED','TERMINATED','DETACHED'}
                and key in records):
            # Search can lag. Its positive sighting can conservatively retire an
            # old completion proof; it can never establish deletion or replay.
            prior_invalidations = len(records[key].get('proof_invalidations', []))
            _invalidate_contradicted_proofs(updated, node, Observation('present', node.compartment_id,
                search.get('lifecycle_state') or '', None, None, 'Fresh nonterminal Search sighting'), plan)
            if len(records[key].get('proof_invalidations', [])) > prior_invalidations:
                records[key].update(status='unresolved',
                    detail='Search sees this identity after earlier completion; typed verification is required')
        observation = node.metadata.get('schedule_observation')
        if (node.resource_type not in _SCHEDULE_READS or type(observation) is not dict
                or observation.get('observed_at') != plan.created_at):
            continue
        lifecycle = observation.get('lifecycle_state')
        if not isinstance(lifecycle, str) or not lifecycle or 'scheduled_at' not in observation:
            raise CleanupError('Malformed confirmed schedule observation')
        when = _utc(observation['scheduled_at'])
        record = records.setdefault(key, {})
        old = record.get('scheduled_at')
        if old is not None and old != when:
            history = record.get('schedule_history', [])
            if type(history) is not list:
                raise CleanupError('Schedule history is malformed')
            record['schedule_history'] = history + [{'scheduled_at':old,
                'status':record.get('status','unknown'), 'lifecycle_state':record.get('lifecycle_state','')}]
        record['lifecycle_state'] = lifecycle
        record['scheduled_at'] = when
        if lifecycle in _PENDING_LIFECYCLES:
            record['status'] = 'pending'
        elif lifecycle == 'DELETED':
            record['status'] = 'deleted'
        elif lifecycle in {'ACTIVE','ENABLED','DISABLED'} and record.get('status') == 'pending':
            record['status'] = 'present'
    return updated
