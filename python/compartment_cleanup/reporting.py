"""Readable scope, dependency order, coverage, and durable action progress."""
from datetime import datetime, timezone
import json

from .graph import compute_depths
from .model import Plan, State


def _display(value):
    return ''.join(char if char.isprintable() else '?' for char in str(value))


def _utc(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('missing timezone')
        return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except (AttributeError, TypeError, ValueError):
        return None


def render_report(plan: Plan, state: State) -> str:
    depths, blockers = compute_depths(plan.nodes, plan.edges)
    lines = [f'OCI cleanup; retained parent: {_display(plan.parent_id)}',
             f'Tenancy: {_display(plan.tenancy_id)}',
             'Coverage limitation: OCI has no universal resource inventory; this report covers recorded discovery probes only.',
             'Preserve this work directory until cleanup is finished.', '']
    pending = []

    def resource(key):
        node = plan.nodes[key]
        record = state.records.get(key, {})
        lines.append(f'  {_display(key)} | {_display(node.resource_type)} | {_display(node.display_name)} | method: {_display(node.handler)} / {_display(node.action)} | status: {_display(record.get("status", "discovered"))}')
        for edge in plan.edges:
            if edge.before == key:
                lines.append(f'    before {_display(edge.after)}: {_display(edge.evidence)}')
        if record.get('errors'):
            lines.append('    errors: ' + _display(json.dumps(record['errors'], ensure_ascii=False)))

    for depth in sorted(set(depths.values()), reverse=True):
        lines.append(f'Depth {depth}')
        for key in sorted(key for key, value in depths.items() if value == depth):
            resource(key)
        lines.append('')
    if blockers:
        lines.append('Unresolved nodes and blockers')
        for key in sorted(blockers):
            resource(key)
            for reason in blockers[key]:
                lines.append('    blocker: ' + _display(reason))
        lines.append('')
    cascade_members = [key for key, node in plan.nodes.items() if node.action == 'cascade' and key not in blockers]
    if cascade_members:
        lines.append('Cascade members; verify removal through their owner')
        for key in sorted(cascade_members):
            resource(key)
            lines.append('    cascade owner: ' + _display(plan.nodes[key].metadata.get('cascade_owner', 'unverified')))
        lines.append('')
    lines.append('Coverage probes and gaps')
    if not plan.probes:
        lines.append('  No discovery probes recorded; coverage is unverified.')
    for probe in plan.probes:
        lines.append(f'  {_display(probe.service)} / {_display(probe.region)} / {_display(probe.compartment_id)}: {_display(probe.status)}; {_display(probe.detail)}')
    lines.extend(['', 'Pending deletions and retained journal records'])
    for key, record in sorted(state.records.items()):
        if record.get('status') == 'pending':
            timestamp = _utc(record.get('scheduled_at'))
            shown = timestamp or 'unknown UTC schedule (verification required)'
            lines.append(f'  Cannot finish cleanup: {_display(key)} is pending deletion until {shown}; rerun after that time and verify its removal.')
            if timestamp:
                pending.append(timestamp)
        if key not in plan.nodes:
            lines.append(f'  {_display(key)}: absent from refreshed map; status {_display(record.get("status", "unresolved"))}; authoritative verification required. History preserved.')
            if record.get('errors'):
                lines.append('    errors: ' + _display(json.dumps(record['errors'], ensure_ascii=False)))
    if pending:
        earliest = min(pending, key=lambda value: datetime.fromisoformat(value.replace('Z', '+00:00')))
        lines.append('Next known revisit time: ' + earliest + '; an earliest known condition, not a promise of completion.')
    return '\n'.join(lines) + '\n'
