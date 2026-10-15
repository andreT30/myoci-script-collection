"""Readable scope, dependency order, coverage, and durable action progress."""
from datetime import datetime, timezone
import json

from .graph import compute_depths
from .model import Plan, State
from .journal import resource_records, bulk_attempt_records


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


def _schedule_failure(plan, node):
    value = node.metadata.get('schedule_verification') if node else None
    return (value if isinstance(value, dict) and value.get('status') == 'failed'
            and value.get('observed_at') == plan.created_at else None)


def _schedule_label(timestamp, failed, now):
    text = timestamp
    if failed:
        text += ' (last known schedule; verification failed)'
    if datetime.fromisoformat(timestamp.replace('Z', '+00:00')) <= now:
        text += '; scheduled time has passed; verify removal now'
    return text


def _revisit(dates, now):
    future = [date for date in dates
              if datetime.fromisoformat(date.replace('Z', '+00:00')) > now]
    if future:
        earliest = min(future, key=lambda date: datetime.fromisoformat(date.replace('Z', '+00:00')))
        return 'Next known revisit time: ' + earliest + '; verify removal on rerun.'
    if dates:
        return 'Scheduled times have passed; verify removal now. Elapsed time does not prove deletion.'
    return None


def render_report(plan: Plan, state: State, *, now=None) -> str:
    now = now or datetime.now(timezone.utc)
    depths, blockers = compute_depths(plan.nodes, plan.edges)
    lines = [f'OCI cleanup; retained parent: {_display(plan.parent_id)}',
             f'Tenancy: {_display(plan.tenancy_id)}',
             'Coverage limitation: OCI has no universal resource inventory; this report covers recorded discovery probes only.',
             'Preserve this work directory until cleanup is finished.', '']
    if any(p.service == 'inventory_mode' and p.detail == 'search' for p in plan.probes):
        lines.insert(3, 'Discovery: Search-visible resources and related children only; unindexed resources may be omitted. External dependency checks run before deletion.')
    if any(p.service == 'inventory_mode' and p.detail == 'search_inventory' for p in plan.probes):
        lines.insert(3, 'Discovery: Search inventory; unindexed resources may be omitted. Missing handlers are deletion capability gaps, not discovery failures.')
    pending = []

    def resource(key):
        node = plan.nodes[key]
        record = state.records.get(key, {})
        lines.append(f'  {_display(key)} | {_display(node.resource_type)} | {_display(node.display_name)} | method: {_display(node.handler)} / {_display(node.action)} | status: {_display(record.get("status", "discovered"))}')
        # Only identifying fields and disclosed retained-resource effects are
        # printable; nested configuration, tags and secret metadata stay private.
        for field in ('object_name', 'version_id', 'bucket_name', 'kms_key_id',
                      'vault_id', 'key_id', 'vcn_id', 'peer_id',
                      'issuer_certificate_authority_id', 'entity_id', 'cloud_resource_id',
                      'management_agent_id', 'log_group_id', 'os_bucket_name',
                      'stream_id', 'subnet_id', 'em_entities_compartment_id'):
            value = node.metadata.get(field)
            if isinstance(value, str) and value:
                lines.append(f'    {_display(field)}: {_display(value)}')
        for field in ('subnet_ids', 'network_security_group_ids', 'certificate_ids',
                      'trusted_certificate_authority_ids', 'backend_target_ids',
                      'reserved_public_ip_ids'):
            values = node.metadata.get(field)
            if isinstance(values, list):
                for value in values:
                    if isinstance(value, str):
                        lines.append(f'    Reference retained by this action {_display(field)}: {_display(value)}')
        volumes = node.metadata.get('preserved_volume_ids')
        if isinstance(volumes, list):
            for value in volumes:
                if isinstance(value, str):
                    lines.append('    Volume preserved by instance termination: ' + _display(value))
        ips = node.metadata.get('retained_public_ips')
        if isinstance(ips, list):
            for value in ips:
                if isinstance(value, dict) and isinstance(value.get('id'), str):
                    lines.append('    Reserved public IP retained and automatically unassigned: ' + _display(value['id']))
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
    failures = [n for n in plan.nodes.values() if _schedule_failure(plan, n)]
    lines.append('Schedule verification failures: ' + str(len(failures)))
    lines.extend(['', 'Pending deletions and retained journal records'])
    records = resource_records(state)
    confirmed = sum(r.get('status') == 'deleted' and r.get('completion_basis') == 'operator_confirmation'
                    for r in records.values())
    lines.append(f'Operator-confirmed removals: {confirmed}; local acknowledgements, not API deletion proofs.')
    # Discovery already contains typed service-confirmed schedules. Show them on
    # an initial report before an executor journal has recorded the first read.
    for key, node in plan.nodes.items():
        if node.lifecycle_state in {'PENDING_DELETION', 'SCHEDULING_DELETION', 'DELETING'} and records.get(key, {}).get('status', 'discovered') == 'discovered':
            records[key] = dict(records.get(key, {}), status='pending', scheduled_at=node.metadata.get('scheduled_at'))
    for key, record in sorted(records.items()):
        if record.get('status') == 'pending':
            timestamp = _utc(record.get('scheduled_at'))
            failed = _schedule_failure(plan, plan.nodes.get(key))
            if timestamp:
                label = _schedule_label(timestamp, failed, now)
                if not failed and datetime.fromisoformat(timestamp.replace('Z', '+00:00')) > now:
                    lines.append(f'  Cannot finish cleanup: {_display(key)} is pending deletion until {timestamp}; rerun after that time and verify its removal.')
                else:
                    lines.append(f'  Cannot finish cleanup: {_display(key)} | {label}.')
            elif (record.get('lifecycle_state') in ('PENDING_DELETION', 'SCHEDULING_DELETION')
                  or (plan.nodes.get(key) and plan.nodes[key].action == 'schedule')):
                lines.append(f'  Cannot finish cleanup: {_display(key)} has a pending scheduled deletion with unknown UTC schedule (verification required); rerun to verify its removal.')
            else:
                lines.append(f'  Cannot finish cleanup: {_display(key)} has an asynchronous deletion in progress; rerun to verify its removal.')
            if timestamp and not failed:
                pending.append(timestamp)
        if key not in plan.nodes:
            if record.get('completion_basis') == 'operator_confirmation' and record.get('status') == 'deleted':
                lines.append(f'  {_display(key)}: operator confirmed already deleted; acknowledgement and history preserved.')
            else:
                lines.append(f'  {_display(key)}: absent from refreshed map; status {_display(record.get("status", "unresolved"))}; authoritative verification required. History preserved.')
            if record.get('errors'):
                lines.append('    errors: ' + _display(json.dumps(record['errors'], ensure_ascii=False)))
    groups=list(bulk_attempt_records(state))
    if groups:
        lines.extend(['', 'Bulk attempts; IAM configured chunks: 20; Storage maximum group: 1000'])
        for _,attempt in groups:
            lines.append(f'  {_display(attempt["attempt_id"])} | {_display(attempt.get("operation", "unknown"))} | status: {_display(attempt.get("status", "unresolved"))}')
            for key,status in sorted(attempt.get('resource_status',{}).items()):
                lines.append(f'    {_display(key)}: {_display(status)}')
    revisit = _revisit(pending, now)
    if revisit:
        lines.append(revisit)
    return '\n'.join(lines) + '\n'


def render_terminal_summary(plan: Plan, state: State, *, width: int = 100, now=None) -> str:
    """Readable counts and all pending dates; detailed identities stay in artifacts."""
    from collections import Counter
    import textwrap

    now = now or datetime.now(timezone.utc)
    width = max(40, int(width))
    lines = []

    def line(value=''):
        safe = _display(value)
        lines.extend(textwrap.wrap(safe, width=width, subsequent_indent='  ',
                                   break_long_words=True, break_on_hyphens=False) or [''])

    def short(key):
        return '…' + _display(key)[-12:] if len(key) > 16 else _display(key)

    def counts(title, values):
        line(title)
        ordered = sorted(values.items(), key=lambda item: (-item[1], item[0]))
        for label, count in ordered[:8]:
            line(f'  {_display(label) or "global"}: {count}')
        if len(ordered) > 8:
            line(f'  … {len(ordered) - 8} more groups; see report.txt')

    records = resource_records(state)
    parent = plan.nodes.get(plan.parent_id)
    line('OCI cleanup')
    line('Retained parent: ' + (_display(parent.display_name) if parent and parent.display_name else short(plan.parent_id)))
    line('Supplied parent will be retained.')
    search = any(p.service == 'inventory_mode' and p.detail in {'search', 'search_inventory'} for p in plan.probes)
    line('Discovery: ' + ('Search inventory; unindexed resources may be omitted.' if search else 'Recorded discovery probes; coverage is limited to those probes.'))
    resources = [node for key, node in plan.nodes.items() if key != plan.parent_id]
    line(f'Scope: {len(plan.compartments)} compartments; {len(resources)} resources')
    counts('Resources by type', Counter(node.resource_type for node in resources))
    regional_counts = Counter()
    for node in resources:
        sightings = node.metadata.get('search_regions')
        regions = set(region for region in sightings if isinstance(region, str)) if isinstance(sightings, list) else set()
        regional_counts.update(regions or {node.region})
    counts('Resources by region (regional sightings)', regional_counts)
    counts('Resources by compartment', Counter(short(node.compartment_id) for node in resources))

    failed = [p for p in plan.probes if p.status != 'complete']
    line(f'Inventory coverage failures: {len(failed)}')
    grouped = Counter((p.service, p.region, p.status, _display(p.detail)) for p in failed)
    for (service, region, status, detail), count in sorted(grouped.items())[:8]:
        line(f'  {_display(service)} / {_display(region)}: {_display(status)} ({count}); {detail}')
    if len(grouped) > 8:
        line(f'  … {len(grouped) - 8} more failure groups; see report.txt')
    schedule_failures = [node for node in resources if _schedule_failure(plan, node)]
    line(f'Schedule verification failures: {len(schedule_failures)}')
    for node in schedule_failures[:8]:
        failure = _schedule_failure(plan, node)
        status = failure.get('http_status')
        line('  ' + (node.display_name or short(node.key)) + ' | ' + node.resource_type
             + ': ' + _display(failure.get('detail', 'Targeted schedule verification failed'))
             + (f' (HTTP {status})' if status else ''))
    if len(schedule_failures) > 8:
        line(f'  … {len(schedule_failures) - 8} more; see report.txt')
    unsupported = [node for node in resources if not node.handler and node.action not in ('retain', 'cascade')]
    line(f'Missing deletion handlers: {len(unsupported)}')
    unsupported_types = sorted(Counter(node.resource_type for node in unsupported).items())
    for kind, count in unsupported_types[:8]:
        line(f'  {_display(kind)}: {count}; manual action required')
    if len(unsupported_types) > 8:
        line(f'  … {len(unsupported_types) - 8} more types; see report.txt')
    failures = [(key, record) for key, record in records.items() if record.get('status') == 'failed']
    line(f'Deletion failures: {len(failures)}')
    grouped_errors = Counter(_display(json.dumps(record.get('errors', []), ensure_ascii=False)) for _, record in failures)
    for error, count in sorted(grouped_errors.items())[:8]:
        line(f'  {count}: {error}')
    if len(grouped_errors) > 8:
        line(f'  … {len(grouped_errors) - 8} more failure groups; see report.txt')

    confirmed = sum(r.get('status') == 'deleted' and r.get('completion_basis') == 'operator_confirmation'
                    for r in records.values())
    line(f'Operator-confirmed removals: {confirmed}')

    names = Counter(node.display_name for node in resources if node.display_name)
    pending = []
    pending_count = 0
    known_dates = []
    for key in sorted(set(plan.nodes) | set(records)):
        node = plan.nodes.get(key)
        record = records.get(key, {})
        implicit = node and node.lifecycle_state in {'PENDING_DELETION', 'SCHEDULING_DELETION', 'DELETING'} and record.get('status', 'discovered') == 'discovered'
        if record.get('status') != 'pending' and not implicit:
            continue
        stamp = _utc(record.get('scheduled_at') if not implicit else node.metadata.get('scheduled_at'))
        failed_schedule = _schedule_failure(plan, node)
        if stamp and not failed_schedule:
            known_dates.append(stamp)
        name = (node.display_name if node else record.get('display_name')) or short(key)
        kind = node.resource_type if node else record.get('resource_type', 'unknown type')
        region = node.region if node else record.get('region', '')
        if names.get(name, 0) > 1:
            name += ' [' + short(key) + ']'
        identity = f'{name} | {kind}' + (f' | {region}' if region else '')
        scheduled = (node and node.action == 'schedule') or record.get('lifecycle_state') in {'PENDING_DELETION', 'SCHEDULING_DELETION'}
        date = (_schedule_label(stamp, failed_schedule, now) if stamp else None) or ('unknown UTC schedule; verification required' if scheduled or implicit else 'asynchronous deletion; verification required')
        pending_count += 1
        pending.append(identity + ' | ' + date)
        if node is None:
            pending.append('  absent from inventory; history preserved')
    line('Pending deletions: ' + str(pending_count))
    if pending_count:
        line('Cleanup cannot finish until these resources are confirmed deleted.')
    for entry in pending:
        line('  ' + entry)
    revisit = _revisit(known_dates, now)
    if revisit:
        line(revisit)
    orphans = [(key, record) for key, record in records.items() if key not in plan.nodes and record.get('status') != 'pending']
    if orphans:
        line(f'Retained journal history absent from inventory: {len(orphans)}')
        for key, record in orphans[:8]:
            status = ('operator confirmed deleted' if record.get('completion_basis') == 'operator_confirmation'
                      and record.get('status') == 'deleted' else record.get('status', 'unresolved'))
            line(f'  {short(key)}: {_display(status)}; history preserved')
    return '\n'.join(lines) + '\n'
