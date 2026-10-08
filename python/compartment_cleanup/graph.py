"""Iterative dependency planning and validation of the recorded boundary."""
from collections import deque
from .model import CleanupError, Edge, Node, Plan, SCHEMA_VERSION


def validate_scope(plan: Plan, supplied_parent: str) -> set[str]:
    if plan.schema_version != SCHEMA_VERSION or type(plan.schema_version) is not int:
        raise CleanupError("Unsupported schema version")
    if supplied_parent != plan.parent_id or plan.parent_id == plan.tenancy_id:
        raise CleanupError("Retained parent does not match scope")
    scope = set(plan.compartments)
    if plan.parent_id not in scope or plan.tenancy_id in scope:
        raise CleanupError("Invalid compartment boundary")
    if plan.compartments[plan.parent_id] in scope:
        raise CleanupError("Retained parent has a cyclic parent link")
    # Walk each link once, caching successful paths; no recursion depth limit.
    verified = {plan.parent_id}
    for compartment in scope:
        path = set()
        current = compartment
        while current not in verified:
            if current not in scope or current in path:
                raise CleanupError("Compartment is disconnected or hierarchy is cyclic")
            path.add(current)
            current = plan.compartments[current]
        verified.update(path)
    parent = plan.nodes.get(plan.parent_id)
    if parent is None or parent.action != "retain" or parent.resource_type != "Compartment":
        raise CleanupError("Retained parent must have a protected compartment node")
    for key, node in plan.nodes.items():
        if key != node.key:
            raise CleanupError("Duplicate or mismatched node identity")
        if key == plan.parent_id:
            if node.compartment_id != plan.compartments[plan.parent_id]:
                raise CleanupError("Retained parent owner does not match hierarchy")
        elif node.compartment_id not in scope:
            raise CleanupError("Resource is outside the recorded compartment scope")
        if node.action == "retain" and key != plan.parent_id:
            raise CleanupError("Only the chosen parent may be retained")
        if node.resource_type == "Compartment" and key not in scope:
            raise CleanupError("Compartment node is outside the recorded scope")
    for edge in plan.edges:
        if edge.before not in plan.nodes or edge.after not in plan.nodes:
            raise CleanupError("Dependency references an external or unknown target")
    for probe in plan.probes:
        if probe.compartment_id not in scope:
            raise CleanupError("Discovery probe is outside recorded scope")
    return scope


def compute_depths(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, int], dict[str, tuple[str, ...]]]:
    successors = {key: set() for key in nodes}
    predecessors = {key: set() for key in nodes}
    reasons = {}
    for key, node in nodes.items():
        if key != node.key:
            raise CleanupError("Duplicate or mismatched node identity")
        if node.blockers or node.action == "unresolved":
            reasons[key] = set(node.blockers or ("Unresolved deletion method",))
    for edge in edges:
        if edge.before not in nodes or edge.after not in nodes:
            for key in (edge.before, edge.after):
                if key in nodes:
                    reasons.setdefault(key, set()).add(f"Dangling dependency: {edge.before} -> {edge.after} ({edge.evidence})")
            continue
        successors[edge.before].add(edge.after)
        predecessors[edge.after].add(edge.before)
    # Forward topological traversal leaves cycles and their downstream nodes.
    incoming = {key: len(value) for key, value in predecessors.items()}
    ready = deque(key for key, count in incoming.items() if count == 0)
    order = []
    while ready:
        key = ready.popleft()
        order.append(key)
        for after in successors[key]:
            incoming[after] -= 1
            if incoming[after] == 0:
                ready.append(after)
    for key, count in incoming.items():
        if count:
            reasons.setdefault(key, set()).add("Cycle or dependency downstream of a cycle")
    pending = deque(reasons)
    while pending:
        before = pending.popleft()
        for after in successors[before]:
            if after not in reasons:
                reasons[after] = {f"Blocked predecessor: {before}"}
                pending.append(after)
    depths = {}
    for key in reversed(order):
        if key in reasons or nodes[key].action == "retain":
            continue
        downstream = [depths[after] for after in successors[key] if after in depths]
        depths[key] = 1 + max(downstream, default=0)
    return depths, {key: tuple(sorted(value)) for key, value in reasons.items()}
