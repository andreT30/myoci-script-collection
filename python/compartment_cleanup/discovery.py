"""Read-only inventory, typed relationship evidence, and conservative report refresh."""
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
import re

import oci

from .gateway import discover_scope
from .graph import compute_depths, validate_scope
from .model import CleanupError, Edge, Node, Plan, Probe, SCHEMA_VERSION

_COMPARTMENT = re.compile(r'ocid1\.compartment\.[a-z0-9]+\.[a-z0-9.-]*\.[a-zA-Z0-9_-]+\Z')


def _blocked(node, reason):
    return replace(node, action='unresolved', blockers=tuple(sorted(set(node.blockers + (reason,)))))


def merge_nodes(search_nodes: list[Node], handler_nodes: list[Node]) -> dict[str, Node]:
    """Search duplicates may span regions; service identities are authoritative."""
    result = {}
    for node in sorted(search_nodes, key=lambda n: (n.key, n.region)):
        previous = result.get(node.key)
        if previous and (previous.resource_type, previous.compartment_id) != (node.resource_type, node.compartment_id):
            result[node.key] = _blocked(previous, 'Conflicting Search identity')
        elif not previous:
            result[node.key] = node
    authoritative = {}
    for node in handler_nodes:
        previous = authoritative.get(node.key)
        if previous and previous != node:
            authoritative[node.key] = _blocked(previous, 'Conflicting authoritative service identity')
        else:
            authoritative[node.key] = node
    result.update(authoritative)
    return result


def collapse_cascades(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, Node], list[Edge]]:
    """Collapse only explicitly verified, reciprocal membership with a safe owner.

    Member identities remain in the report. Edges retain their original evidence;
    the code-defined handler must reestablish membership from live OCI on execution.
    """
    result = dict(nodes)
    owners = {}
    scope = {key for key, node in nodes.items() if node.resource_type == 'Compartment'}
    for key, node in nodes.items():
        members = node.metadata.get('cascade_members')
        if members is not None and (not isinstance(members, list) or any(
                not isinstance(member, str) or member not in nodes
                or nodes[member].metadata.get('cascade_owner') != key
                or nodes[member].metadata.get('cascade_verified') is not True
                or nodes[member].blockers
                or (nodes[member].compartment_id != node.compartment_id
                    and not {nodes[member].compartment_id, node.compartment_id} <= scope)
                for member in members)):
            result[key] = _blocked(node, 'External or unverified cascade member')
    # A failed descendant invalidates every ancestor's cascade, regardless of
    # dictionary order or whether the unsafe membership has its own edge.
    parents = {}
    for key, node in nodes.items():
        members = node.metadata.get('cascade_members')
        if isinstance(members, list):
            for member in members:
                if isinstance(member, str) and member in nodes:
                    parents.setdefault(member, set()).add(key)
        owner = node.metadata.get('cascade_owner')
        if isinstance(owner, str) and owner in nodes and nodes[owner].resource_type != 'Compartment':
            parents.setdefault(key, set()).add(owner)

    def propagate_unsafe_members():
        pending = deque(key for key, node in result.items() if node.blockers or node.action == 'unresolved')
        visited = set(pending)
        while pending:
            member = pending.popleft()
            for owner in parents.get(member, ()):
                result[owner] = _blocked(result[owner], 'Unresolved cascade descendant')
                if owner not in visited:
                    visited.add(owner)
                    pending.append(owner)

    propagate_unsafe_members()
    for key, node in nodes.items():
        owner = node.metadata.get('cascade_owner')
        if owner is None and node.action != 'cascade':
            continue
        target = nodes.get(owner) if isinstance(owner, str) else None
        members = target.metadata.get('cascade_members', []) if target else []
        if (target is None or target.key == key or target.resource_type == 'Compartment'
                or result[target.key].action in {'retain', 'unresolved'} or result[target.key].blockers
                or node.metadata.get('cascade_verified') is not True
                or not isinstance(members, list) or key not in members):
            result[key] = _blocked(node, 'Unverified cascade membership or owner')
        else:
            owners[key] = owner
    # Resolve owner chains iteratively and reject cycles or unresolved ancestors.
    mapped = {}
    for key in owners:
        visited = set()
        current = key
        while current in owners and current not in visited:
            visited.add(current)
            current = owners[current]
        if current in visited or result[current].action == 'unresolved' or result[current].blockers:
            for member in visited:
                result[member] = _blocked(result[member], 'Cyclic or unresolved cascade owner')
        else:
            mapped[key] = current
    propagate_unsafe_members()
    for key, owner in mapped.items():
        if result[owner].action == 'unresolved' or result[owner].blockers:
            result[key] = _blocked(result[key], 'Unresolved cascade owner')
        elif result[key].action != 'unresolved':
            result[key] = replace(result[key], action='cascade')
    normalized = []
    seen = set()
    for edge in edges:
        before = mapped.get(edge.before, edge.before) if result.get(edge.before) and result[edge.before].action == 'cascade' else edge.before
        after = mapped.get(edge.after, edge.after) if result.get(edge.after) and result[edge.after].action == 'cascade' else edge.after
        if before != after:
            value = Edge(before, after, edge.evidence)
            if value not in seen:
                normalized.append(value)
                seen.add(value)
    return result, normalized


def _catalog(gateway, home):
    rows = gateway.items('identity', home, 'list_bulk_action_resource_types',
                         {'bulk_action_type': 'BULK_DELETE_RESOURCES'})
    catalog = {}
    for row in rows:
        name, keys = row.get('name'), row.get('metadata_keys')
        if (not isinstance(name, str) or not name or not isinstance(keys, list)
                or any(not isinstance(k, str) or not k for k in keys)
                or len(keys) != len(set(keys)) or name in catalog):
            raise CleanupError('Malformed bulk resource type catalog')
        catalog[name] = tuple(keys)
    return catalog


def _search_node(row, region, compartment):
    key, kind, owner = row.get('identifier'), row.get('resource_type'), row.get('compartment_id')
    if (not isinstance(key, str) or not key or not isinstance(kind, str) or not kind
            or not isinstance(owner, str) or owner != compartment):
        raise CleanupError('Malformed or out-of-scope Search resource identity')
    return Node(key, kind, region, owner, row.get('display_name') or '',
                row.get('lifecycle_state') or '', '', 'unresolved', {})


def _bulk_node(node, registry, catalog):
    handler = registry.handler_for(node)
    if not handler:
        return node
    name = handler.bulk_resource_types.get(node.resource_type)
    if name not in catalog:
        return node
    required = catalog[name]
    values = handler.bulk_metadata(node, required)
    # This mapping contains identifiers only, never SDK methods or endpoints.
    if not isinstance(values, dict) or any(k not in required for k in values):
        raise CleanupError('Invalid handler bulk metadata builder')
    if any(not isinstance(v, str) or not v for v in values.values()):
        raise CleanupError('Invalid bulk identifying metadata')
    metadata = dict(node.metadata, bulk_resource_type=name,
                    bulk_metadata=values, bulk_metadata_keys=list(required))
    return replace(node, metadata=metadata)


def discover(gateway, parent_id: str, registry, previous: Plan | None = None) -> Plan:
    if not isinstance(parent_id, str) or not _COMPARTMENT.fullmatch(parent_id):
        raise CleanupError('Invalid retained compartment OCID')
    tenancy, home, regions, compartments = discover_scope(gateway, parent_id)
    if previous is not None:
        validate_scope(previous, parent_id)
        if previous.tenancy_id != tenancy:
            raise CleanupError('Previous plan belongs to another tenancy')
    compartments = dict(compartments)
    probes = []
    try:
        bulk_types = _catalog(gateway, home)
        probes.append(Probe('bulk_catalog', home, parent_id, 'complete', ''))
    except Exception:
        bulk_types = {}
        probes.append(Probe('bulk_catalog', home, parent_id, 'failed', 'Bulk catalog could not be established'))
    search_nodes, service_nodes, edges = [], [], []
    for compartment in sorted(compartments):
        if not _COMPARTMENT.fullmatch(compartment):
            raise CleanupError('Invalid discovered compartment OCID')
        for region in regions:
            try:
                details = oci.resource_search.models.StructuredSearchDetails(
                    query=f"query all resources where compartmentId = '{compartment}'")
                rows = gateway.items('search', region, 'search_resources', {'search_details': details})
                search_nodes.extend(_search_node(row, region, compartment) for row in rows)
                probes.append(Probe('search', region, compartment, 'complete', ''))
            except Exception:
                probes.append(Probe('search', region, compartment, 'failed', 'Search inventory failed'))
            for name, handler in registry.handlers.items():
                try:
                    found, references, coverage = handler.discover(gateway, compartment, region)
                    classified = []
                    for node in found:
                        if node.compartment_id not in compartments or node.key in compartments:
                            raise CleanupError('Service returned an out-of-scope resource')
                        classified.append(registry.classify(node))
                    if any(p.compartment_id != compartment or p.region != region for p in coverage):
                        raise CleanupError('Invalid service coverage scope')
                    service_nodes.extend(classified)
                    edges.extend(references)
                    probes.extend(coverage)
                    if not coverage:
                        probes.append(Probe(name, region, compartment, 'failed', 'Service returned no discovery coverage'))
                except Exception:
                    probes.append(Probe(name, region, compartment, 'failed', 'Service inventory failed'))
    nodes = merge_nodes(search_nodes, service_nodes)
    authoritative_keys = {n.key for n in service_nodes}
    nodes = {key:_blocked(registry.classify(node), 'Search identity lacks authoritative service dependency evidence')
             if key not in authoritative_keys else node for key,node in nodes.items()}
    historical = {}
    if previous:
        # IAM list omission is ambiguous too. Only an explicit successful
        # terminal read proves a previously recorded child has disappeared.
        for compartment in set(previous.compartments) - set(compartments):
            try:
                record, _ = gateway.read('identity', home, 'get_compartment', {'compartment_id':compartment})
            except Exception:
                record = {}
            if record.get('id') == compartment and record.get('lifecycle_state') == 'DELETED':
                continue
            historical[compartment] = 'Previously recorded compartment lacks authoritative terminal verification'
            current = compartment
            while current not in compartments:
                compartments[current] = previous.compartments[current]
                current = previous.compartments[current]
            probes.append(Probe('historical_scope', home, compartment, 'failed', historical[compartment]))
        # Direct inspection is required even when both Search and list omit a
        # previously recorded resource. A 403/404 cannot establish its removal.
        for key, old in previous.nodes.items():
            if key in nodes or old.resource_type == 'Compartment':
                continue
            handler = registry.handler_for(old)
            try:
                observation = handler.inspect(gateway, registry.classify(old), set(compartments)) if handler else None
            except Exception:
                observation = None
            if observation and observation.status == 'deleted':
                continue
            if old.compartment_id not in compartments:
                # Preserve uncertain historical scope without targeting additions.
                current = old.compartment_id
                while current not in compartments:
                    compartments[current] = previous.compartments[current]
                    current = previous.compartments[current]
                probes.append(Probe('historical_scope', home, old.compartment_id, 'failed', 'Previously recorded compartment is absent from live hierarchy'))
            kept = registry.classify(old)
            if observation and observation.status in {'present','pending'} and observation.compartment_id == old.compartment_id:
                metadata = dict(kept.metadata)
                if observation.scheduled_at:
                    metadata['scheduled_at'] = observation.scheduled_at
                kept = replace(kept, lifecycle_state=observation.lifecycle_state, metadata=metadata)
                if observation.status == 'pending':
                    kept = replace(kept, blockers=tuple(sorted(set(kept.blockers + ('Deletion remains pending',)))))
            else:
                kept = _blocked(kept, 'Previously recorded resource lacks authoritative in-scope verification')
                if observation and isinstance(observation.compartment_id, str) and observation.compartment_id != old.compartment_id:
                    kept = replace(kept, metadata=dict(kept.metadata, observed_compartment_id=observation.compartment_id))
            if any(field in old.metadata for field in ('cascade_owner', 'cascade_members', 'cascade_verified')):
                # Observation contains lifecycle/ownership only. It cannot renew
                # proof of a complete live cascade set, even if individual
                # members were freshly discovered by another inventory call.
                kept = replace(kept, metadata={k:v for k,v in kept.metadata.items()
                                              if k not in {'cascade_members', 'cascade_verified'}})
                kept = _blocked(kept, 'Cascade membership requires fresh typed service discovery')
            nodes[key] = kept
        # Do not lose known references merely because inventory was incomplete.
        edges.extend(e for e in previous.edges if (e.before in nodes and e.after in nodes)
                     and (e.before not in authoritative_keys))
    for compartment, owner in compartments.items():
        record = getattr(gateway, 'compartment_records', {}).get(compartment, {})
        nodes[compartment] = Node(compartment, 'Compartment', home, owner,
                                  record.get('name',''), record.get('lifecycle_state','ACTIVE'),
                                  'compartment', 'retain' if compartment == parent_id else 'delete', {})
        if compartment in historical:
            nodes[compartment] = _blocked(nodes[compartment], historical[compartment])
    nodes = {key:_bulk_node(node, registry, bulk_types) for key,node in nodes.items()}
    for key, node in list(nodes.items()):
        if node.resource_type == 'Compartment':
            if key != parent_id:
                edges.append(Edge(key, compartments[key], 'Child compartment belongs to parent'))
            continue
        edges.append(Edge(key, node.compartment_id, 'Resource belongs to compartment'))
        handler = registry.handler_for(node)
        if handler:
            for field in handler.reference_fields:
                values = node.metadata.get(field)
                values = values if isinstance(values,list) else [values] if values else []
                for target in values:
                    if not isinstance(target,str) or target not in nodes:
                        nodes[key] = _blocked(nodes[key], f'External or unresolved typed reference: {field}')
                    elif target != key:
                        edges.append(Edge(key,target,f'Typed field: {field}'))
    # Explicit association edges must stay within the proven boundary.
    safe_edges = []
    for edge in edges:
        if edge.before not in nodes or edge.after not in nodes:
            for key in (edge.before, edge.after):
                if key in nodes:
                    nodes[key] = _blocked(nodes[key], 'External or unresolved association')
        elif edge not in safe_edges:
            safe_edges.append(edge)
    for probe in probes:
        if probe.status != 'complete':
            compartment = nodes[probe.compartment_id]
            # The protected parent keeps retain even when coverage is incomplete.
            nodes[compartment.key] = replace(compartment, blockers=tuple(sorted(set(compartment.blockers +
                (f'Incomplete {probe.service} discovery in {probe.region}',)))))
    nodes, safe_edges = collapse_cascades(nodes, safe_edges)
    depths, blockers = compute_depths(nodes, safe_edges)
    for key, reasons in blockers.items():
        nodes[key] = replace(nodes[key], blockers=tuple(sorted(set(nodes[key].blockers + reasons))))
    plan = Plan(SCHEMA_VERSION, tenancy, parent_id, home,
                datetime.now(timezone.utc).isoformat(), compartments, nodes,
                safe_edges, probes, depths, bulk_types)
    validate_scope(plan, parent_id)
    return plan


def compare_plan(saved: Plan, live: Plan) -> dict[str, list[str]]:
    """Report drift without mutating or expanding the approved executable set."""
    if saved.parent_id != live.parent_id or saved.tenancy_id != live.tenancy_id:
        raise CleanupError('Cannot compare plans from different boundaries')
    added = sorted(set(live.nodes) - set(saved.nodes))
    moved, changed = set(), set(saved.nodes) - set(live.nodes)
    for key in set(saved.nodes) & set(live.nodes):
        old, new = saved.nodes[key], live.nodes[key]
        old_owner = old.metadata.get('observed_compartment_id', old.compartment_id)
        new_owner = new.metadata.get('observed_compartment_id', new.compartment_id)
        if (old_owner,old.region) != (new_owner,new.region):
            moved.add(key)
        if (old.resource_type,old.action,old.metadata,old.blockers) != (new.resource_type,new.action,new.metadata,new.blockers):
            changed.add(key)
    old_edges, new_edges = set(saved.edges), set(live.edges)
    for edge in old_edges ^ new_edges:
        changed.update(k for k in (edge.before,edge.after) if k in saved.nodes)
    for key in set(saved.compartments) | set(live.compartments):
        if saved.compartments.get(key) != live.compartments.get(key):
            changed.add(key)
            if key in saved.compartments and key in live.compartments:
                moved.add(key)
    old_probes = {(p.service,p.region,p.compartment_id,p.status) for p in saved.probes}
    new_probes = {(p.service,p.region,p.compartment_id,p.status) for p in live.probes}
    changed.update(p[2] for p in old_probes ^ new_probes if p[2] in saved.nodes)
    return {'added':added, 'moved':sorted(moved), 'changed':sorted(changed)}
