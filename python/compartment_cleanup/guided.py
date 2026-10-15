"""Interactive cleanup driven by live service responses and durable outcomes."""
from collections import deque
from copy import deepcopy
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
import time

from .actions import prepare_action, submit_action, reconcile_action
from .dependencies import investigate_rejection, is_dependency_rejection
from .executor import JournalError, BulkJournalError, _scope_now, _apply_observation, _invalidate_contradicted_proofs
from .guided_bulk import eligible_group, submit_guided_bulk, reconcile_guided_bulk
from .guided_storage import try_storage_batch, reconcile_storage_batches
from .gateway import GatewayError
from .graph import validate_scope, compute_depths
from .journal import attempt_history, resource_records, bulk_attempt_records
from .model import CleanupError, Edge, Node, Observation, plan_to_dict, state_to_dict
from .reporting import render_report
from .removal_confirmation import retire_confirmed


def _safe(value):
    return ''.join(c if c.isprintable() else '?' for c in str(value))


def _save(workspace, state, plan=None):
    try:
        if plan is not None:
            plan.depths, _ = compute_depths(plan.nodes, plan.edges)
            workspace.save_plan(plan)
        workspace.save_state(state)
    except Exception as error:
        raise JournalError('Cannot persist guided cleanup; stop all mutations') from error


def _mark(state, node, observation, plan, *, typed=True):
    record = state.records.setdefault(node.key, {'attempts': [], 'status': 'discovered'})
    if typed:
        _invalidate_contradicted_proofs(state, node, observation, plan)
    previous = record.get('scheduled_at')
    if previous and previous != observation.scheduled_at:
        record.setdefault('schedule_history', []).append({
            'scheduled_at': previous, 'lifecycle_state': record.get('lifecycle_state'),
            'observed_at': datetime.now(timezone.utc).isoformat()})
    if observation.status == 'deleted':
        _apply_observation(state, node, observation)
    record.update(status=observation.status, lifecycle_state=observation.lifecycle_state,
                  detail=observation.detail, scheduled_at=observation.scheduled_at)


def _unfinished_attempt(state, key):
    for attempt in attempt_history(state, key):
        status = attempt.get('resource_status', {}).get(key, attempt.get('status'))
        if status not in ('failed', 'deleted', 'prepared'):
            return True
    return False


def _priority(plan, node):
    depth = 0
    owner = node.compartment_id
    seen = set()
    while owner in plan.compartments and owner != plan.parent_id and owner not in seen:
        seen.add(owner)
        depth += 1
        owner = plan.compartments[owner]
    phase = 3 if node.resource_type == 'Compartment' else 2 if node.resource_type == 'Policy' else 1
    return phase, -depth, node.region, node.resource_type, node.key


def _add_target(plan, state, gateway, node, current_scope):
    """Only add authenticated containment after the user approves the new target."""
    if node.key == plan.parent_id or node.compartment_id not in current_scope:
        raise CleanupError('Dependency is outside the approved compartment tree')
    if node.key in plan.nodes:
        old = plan.nodes[node.key]
        if (old.resource_type, old.region, old.compartment_id) != (
                node.resource_type, node.region, node.compartment_id):
            raise CleanupError('Dependency identity conflicts with the saved inventory')
        evidence = {k: old.metadata[k] for k in ('search', 'search_regions', 'search_sightings')
                    if k in old.metadata}
        plan.nodes[node.key] = replace(node, metadata=dict(node.metadata, **evidence))
        return
    owner = node.compartment_id
    chain = set()
    while owner not in plan.compartments:
        if owner in chain or owner not in current_scope:
            raise CleanupError('New dependency compartment ancestry is unresolved')
        chain.add(owner)
        parent = current_scope[owner]
        row = gateway.compartment_records.get(owner, {})
        plan.compartments[owner] = parent
        plan.nodes[owner] = Node(owner, 'Compartment', plan.home_region, parent,
                                row.get('name') or row.get('display_name') or '',
                                'ACTIVE', 'compartment', 'delete', {})
        state.records.setdefault(owner, {'status': 'discovered', 'attempts': []})
        plan.edges.append(Edge(owner, parent, 'Compartment containment'))
        owner = parent
    plan.nodes[node.key] = node
    plan.edges.append(Edge(node.key, node.compartment_id, 'Compartment containment'))
    state.records.setdefault(node.key, {'status': 'discovered', 'attempts': []})


def _investigate(gateway, plan, state, workspace, node, error, registry,
                 interaction, current_scope):
    interaction.show('Deletion rejected for ' + _safe(node.display_name or node.key)
                     + ': ' + _safe(getattr(error, 'message', None) or str(error)))
    findings = investigate_rejection(gateway, plan, node, error, registry)
    for finding in findings:
        dependency = finding.resource
        label = dependency.display_name or dependency.key if dependency else 'Unresolved dependency'
        interaction.show('  ' + _safe(label) + ': ' + _safe(finding.evidence)
                         + (' (outside the cleanup tree)' if finding.external else ''))
        if finding.guidance:
            interaction.show('  ' + _safe(finding.guidance))
    if not findings:
        interaction.show('No corroborated dependency was found. Keep this target for a later run.')
        return []
    choice = interaction.choose_dependency(node, findings)
    if choice == 'stop':
        raise KeyboardInterrupt
    if choice != 'handle':
        return []
    targets = []
    baseline = None
    for finding in findings:
        dep = finding.resource
        if dep is None or finding.external or dep.key == plan.parent_id:
            continue
        if dep.compartment_id not in current_scope:
            interaction.show('Outside dependency retained: ' + _safe(dep.key))
            continue
        if dep.key == node.key and dep.resource_type == 'Bucket' and node.resource_type == 'Bucket':
            if (dep.region, dep.compartment_id) == (node.region, node.compartment_id):
                baseline = dep
            continue
        if dep.key == node.key or any(e.before == node.key and e.after == dep.key
                                     and e.evidence == 'OCI dependency rejection' for e in plan.edges):
            interaction.show('Observed dependency cycle; skip this target and resolve it manually.')
            continue
        if dep.resource_type != 'Compartment' and registry.handler_for(dep) is None:
            interaction.show('No supported deletion method for ' + _safe(dep.resource_type)
                             + ': ' + _safe(dep.key))
            continue
        if all(t.key != dep.key for t in targets):
            targets.append(dep)
    new = [dep for dep in targets if dep.key not in plan.nodes]
    if new:
        preview_plan = replace(plan, nodes=dict(plan.nodes), compartments=dict(plan.compartments),
                               edges=list(plan.edges))
        preview_state = deepcopy(state)
        if baseline is not None:
            _add_target(preview_plan, preview_state, gateway, baseline, current_scope)
        supported = {}
        for dep in new:
            prepared = None
            try:
                _add_target(preview_plan, preview_state, gateway, dep, current_scope)
                prepared = prepare_action(gateway, preview_plan, dep, registry)
                supported[dep.key] = prepared.node
                interaction.show('Proposed operation for ' + _safe(dep.display_name or dep.key)
                                 + ': ' + _safe(prepared.service + '.' + prepared.operation)
                                 + ' in ' + _safe(dep.region))
                for effect in prepared.effects:
                    interaction.show('  ' + _safe(effect))
            except GatewayError as error:
                if error.status in (401, 403):
                    raise
                interaction.show('Cannot prepare dependency ' + _safe(dep.display_name or dep.key)
                                 + ': ' + _safe(error.message or str(error)))
            except CleanupError as error:
                interaction.show('Manual dependency action required for '
                                 + _safe(dep.display_name or dep.key) + ': ' + _safe(error))
            finally:
                if prepared is not None:
                    getattr(gateway, '_guided_prepared', {}).pop(id(prepared), None)
        targets = [supported.get(dep.key, dep) for dep in targets
                   if dep.key in plan.nodes or dep.key in supported]
        new = [dep for dep in targets if dep.key not in plan.nodes]
    if new and not interaction.confirm_targets(new):
        interaction.show('New dependency targets were not approved.')
        return []
    if baseline is not None:
        _add_target(plan, state, gateway, baseline, current_scope)
    for dep in targets:
        _add_target(plan, state, gateway, dep, current_scope)
        edge = Edge(dep.key, node.key, 'OCI dependency rejection')
        if edge not in plan.edges:
            plan.edges.append(edge)
    _save(workspace, state, plan)
    return targets


def execute_guided(plan, state, workspace, gateway, registry, supplied_parent,
                   wait_seconds=300, *, interaction, already_locked=False):
    """Never infer absence from a restricted inventory or replay unknown results."""
    plan_to_dict(plan)
    state_to_dict(state)
    validate_scope(plan, supplied_parent)
    if state.parent_id != plan.parent_id or state.tenancy_id != plan.tenancy_id:
        raise CleanupError('Journal scope differs from the saved inventory')
    lock = nullcontext() if already_locked else workspace.locked()
    with lock:
        workspace._writer()
        current_scope, moved = _scope_now(gateway, plan)
        if moved & set(plan.compartments):
            raise CleanupError('Compartment hierarchy changed; refresh the report before deletion')
        retire_confirmed(plan, state)
        state.records.setdefault(plan.parent_id, {'attempts': []}).update(status='retained')
        state.records[plan.parent_id].pop('verification', None)
        _save(workspace, state, plan)
        ordering_nodes = {k: registry.classify(n) if registry.handler_for(n) is not None else n
                          for k, n in plan.nodes.items()}
        depths, _ = compute_depths(ordering_nodes, plan.edges)
        queue = deque(n.key for n in sorted(plan.nodes.values(),
                      key=lambda n: (-depths.get(n.key, 0), _priority(plan, n)))
                      if n.key != plan.parent_id)
        waiting = {}
        for edge in plan.edges:
            if edge.after != plan.parent_id and edge.before in plan.nodes and edge.after in plan.nodes:
                waiting.setdefault(edge.after, set()).add(edge.before)
        tried = set()
        wait_remaining = wait_seconds
        bulk_observations = {}
        investigated_bulk = set()

        def wake_waiting():
            for owner_key, dependencies in waiting.items():
                if owner_key in queue or state.records.get(owner_key, {}).get('status') in ('deleted', 'prepared'):
                    continue
                if all(state.records.get(d, {}).get('status') in ('deleted', 'prepared')
                       for d in dependencies):
                    queue.append(owner_key)

        def queue_pending(pending_key, pending_signature):
            nonlocal wait_remaining
            if wait_remaining <= 0:
                return
            # Ready work continues regardless of the asynchronous wait budget.
            # Spend the budget only once the runnable queue has drained.
            runnable = any(state.records.get(q, {}).get('status') not in
                           ('pending', 'unresolved', 'deleted', 'prepared', 'blocked')
                           for q in queue)
            if not runnable:
                started = time.monotonic()
                time.sleep(min(1, wait_remaining))
                wait_remaining = max(0, wait_remaining - (time.monotonic() - started))
            if wait_remaining > 0:
                tried.discard(pending_signature)
                queue.append(pending_key)

        def reconcile_groups():
            reconcile_storage_batches(gateway, plan, state, workspace, registry)
            results = reconcile_guided_bulk(gateway, plan, state, workspace, registry)
            bulk_observations.update(results['resources'])
            wake_waiting()
            for member_key, error in results['errors'].items():
                request_id = error.request_id
                signature = (member_key, request_id, error.code)
                if signature in investigated_bulk:
                    continue
                investigated_bulk.add(signature)
                member = plan.nodes[member_key]
                if error.status in (401, 403):
                    raise CleanupError('OCI authentication or authorization failed; stop deletion')
                if is_dependency_rejection(error):
                    targets = _investigate(gateway, plan, state, workspace, member, error,
                                          registry, interaction, current_scope)
                    if targets:
                        waiting.setdefault(member_key, set()).update(d.key for d in targets)
                        queue.appendleft(member_key)
                        for dep in reversed(targets):
                            queue.appendleft(dep.key)
                else:
                    interaction.show('Cannot complete ' + _safe(member.display_name or member_key)
                                     + ': ' + _safe(error.message or str(error)))
            return results

        reconcile_groups()
        while queue:
            key = queue.popleft()
            node = plan.nodes[key]
            dependencies = waiting.get(key, set())
            if dependencies and not all(state.records.get(d, {}).get('status') in ('deleted', 'prepared')
                                        for d in dependencies):
                state.records.setdefault(key, {'attempts': []}).update(
                    status='blocked', detail='Waiting for confirmed dependency removal')
                _save(workspace, state)
                continue
            signature = (key, tuple(sorted((d, state.records.get(d, {}).get('status'))
                                            for d in dependencies)))
            if signature in tried:
                continue
            tried.add(signature)
            record = state.records.setdefault(key, {'status': 'discovered', 'attempts': []})
            if node.resource_type != 'Compartment' and registry.handler_for(node) is None:
                record.update(status='unresolved', detail='No supported deletion method; manual service action required')
                interaction.show('Manual action required: ' + _safe(node.display_name or key)
                                 + ' (' + _safe(node.resource_type) + ')')
                _save(workspace, state)
                continue
            poll_started = time.monotonic() if record.get('status') == 'pending' else None
            try:
                storage_history = node.resource_type == 'ObjectStorageObject' and any(
                    a.get('service') == 'object_storage' and a.get('operation') == 'batch_delete_objects'
                    for a in attempt_history(state, key))
                if storage_history:
                    reconcile_storage_batches(gateway, plan, state, workspace, registry)
                bulk_observation = bulk_observations.get(key)
                if bulk_observation and bulk_observation.status in ('pending', 'unresolved') and _unfinished_attempt(state, key):
                    reconcile_groups()
                    bulk_observation = bulk_observations.get(key)
                if storage_history:
                    observation = Observation(record.get('status', 'unresolved'), node.compartment_id,
                                              record.get('lifecycle_state', ''), None, None,
                                              record.get('detail', 'Exact storage batch remains unresolved'))
                elif bulk_observation and bulk_observation.status in ('deleted', 'pending', 'unresolved'):
                    observation = bulk_observation
                else:
                    observation = reconcile_action(gateway, plan, node, record, registry)
                _mark(state, node, observation, plan,
                      typed=not storage_history and observation is not bulk_observation)
                wake_waiting()
                _save(workspace, state)
                if poll_started is not None:
                    wait_remaining = max(0, wait_remaining - (time.monotonic() - poll_started))
                if observation.status in ('deleted', 'prepared', 'moved'):
                    continue
                if observation.status == 'pending':
                    interaction.show('Pending deletion: ' + _safe(node.display_name or key)
                                     + (' until ' + _safe(observation.scheduled_at) if observation.scheduled_at else ' (date unconfirmed)'))
                    # Multi-day schedules do not consume the synchronous wait budget.
                    if not observation.scheduled_at and node.action != 'schedule':
                        queue_pending(key, signature)
                    continue
                if _unfinished_attempt(state, key):
                    record.update(status='unresolved', detail='Earlier operation remains uncertain; verify it before replay')
                    interaction.show('Reconciliation required before another attempt: ' + _safe(node.display_name or key))
                    _save(workspace, state)
                    continue
                if observation.status != 'present':
                    interaction.show('Cannot verify target: ' + _safe(node.display_name or key)
                                     + ' — ' + _safe(observation.detail))
                    continue
                if node.resource_type == 'Compartment':
                    contents = [n.key for n in plan.nodes.values() if n.key != key
                                and (n.compartment_id == key or plan.compartments.get(n.key) == key)
                                and state.records.get(n.key, {}).get('status') not in ('deleted', 'prepared')]
                    if contents:
                        record.update(status='blocked', detail='Known contents or child compartments remain')
                        _save(workspace, state)
                        continue
                # Candidates retain the direct journal gate. A failed member can
                # re-enter only on its exact recorded per-member failure.
                candidates = []
                for candidate_key in (key, *queue):
                    candidate = plan.nodes[candidate_key]
                    if candidate_key in {n.key for n in candidates}:
                        continue
                    pending_dependencies = waiting.get(candidate_key, set())
                    if any(state.records.get(d, {}).get('status') not in ('deleted', 'prepared')
                           for d in pending_dependencies):
                        continue
                    if state.records.get(candidate_key, {}).get('status') in ('deleted', 'prepared', 'moved'):
                        continue
                    history = list(attempt_history(state, candidate_key))
                    if _unfinished_attempt(state, candidate_key):
                        continue
                    if history and any(a.get('resource_status', {}).get(candidate_key) != 'failed'
                                       for a in history):
                        continue
                    candidates.append(candidate)
                if node.resource_type == 'ObjectStorageObject':
                    consumed = try_storage_batch(gateway, plan, state, workspace, candidates, registry)
                    if consumed:
                        wake_waiting()
                    if key in consumed:
                        if state.records[key].get('status') == 'pending':
                            queue_pending(key, signature)
                        continue
                try:
                    group = (eligible_group(gateway, plan, candidates, registry)
                             if node.resource_type in ('Volume', 'BootVolume', 'VolumeBackup', 'BootVolumeBackup')
                             else [])
                except GatewayError as error:
                    if error.status in (401, 403):
                        raise
                    group = []
                except CleanupError:
                    group = []
                if len(group) > 1 and group[0].key == key:
                    interaction.show('Deleting ' + str(len(group)) + ' verified volume targets in '
                                     + _safe(node.region))
                    submit_guided_bulk(gateway, plan, state, workspace, group, registry)
                    reconcile_groups()
                    if bulk_observations[key].status == 'pending':
                        queue_pending(key, signature)
                    continue
                prepared = prepare_action(gateway, plan, node, registry)
                evidence = {k: node.metadata[k] for k in ('search', 'search_regions', 'search_sightings')
                            if k in node.metadata}
                safe = replace(prepared.node, metadata=dict(prepared.node.metadata, **evidence))
                plan.nodes[key] = safe
                _save(workspace, state, plan)
                interaction.show('Deleting ' + _safe(safe.display_name or key)
                                 + ' (' + _safe(safe.resource_type) + ') in ' + _safe(safe.region))
                for effect in prepared.effects:
                    interaction.show('  ' + _safe(effect))
                submit_action(gateway, workspace, state, prepared)
                observation = reconcile_action(gateway, plan, safe, state.records[key], registry)
                _mark(state, safe, observation, plan)
                wake_waiting()
                _save(workspace, state)
                if observation.status == 'pending' and not observation.scheduled_at and safe.action != 'schedule':
                    queue_pending(key, signature)
            except (JournalError, BulkJournalError):
                raise
            except GatewayError as error:
                if error.status in (401, 403):
                    raise CleanupError('OCI authentication or authorization failed; stop deletion') from error
                record.update(detail=_safe(getattr(error, 'message', None) or str(error)))
                if is_dependency_rejection(error):
                    targets = _investigate(gateway, plan, state, workspace, node, error,
                                          registry, interaction, current_scope)
                    if targets:
                        waiting.setdefault(key, set()).update(d.key for d in targets)
                        queue.appendleft(key)
                        for dep in reversed(targets):
                            queue.appendleft(dep.key)
                else:
                    interaction.show('Cannot complete ' + _safe(node.display_name or key)
                                     + ': ' + _safe(record['detail']))
                _save(workspace, state)
            except CleanupError as error:
                record.update(status='unresolved', detail=_safe(error))
                interaction.show('Action requires attention: ' + _safe(node.display_name or key)
                                 + ' — ' + _safe(error))
                _save(workspace, state)
        final_scope, final_moved = _scope_now(gateway, plan)
        incomplete = (bool(final_moved or set(final_scope) - set(plan.compartments))
                      or not plan.probes or any(p.status != 'complete' for p in plan.probes)
                      or any(k != plan.parent_id and r.get('status') not in ('deleted', 'prepared')
                             for k, r in resource_records(state).items())
                      or any(a.get('status') not in ('deleted', 'failed')
                             for _, a in bulk_attempt_records(state)))
        state.records[plan.parent_id]['verification'] = {'complete': not incomplete,
                                                        'mode': 'guided', 'coverage': 'Search and confirmed service outcomes'}
        _save(workspace, state)
        workspace.save_report(render_report(plan, state))
    return state
