"""Behavioral executor tests use typed resources and real durable artifacts."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from compartment_cleanup.discovery import discover
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.handlers.core import IAMPolicies, BlockBootVolumes
from compartment_cleanup.model import Node, CleanupError
from compartment_cleanup.store import Workspace, reconcile_state
from compartment_cleanup import executor
from simulator import Simulator
P = 'ocid1.compartment.oc1..parent'
T = 'ocid1.tenancy.oc1..tenancy'
R = 'region'

class ExecutionGateway(Simulator):

    def __init__(self):
        super().__init__(T, R, {P: T})
        self.deleted_compartments = {}
        self.after_write = None

    def items(self, service, region, operation, params, endpoint=None):
        if operation in ('list_region_subscriptions', 'list_compartments'):
            return super().items(service, region, operation, params, endpoint)
        self._event('items', service, region, operation, params, endpoint)
        if operation in ('list_bulk_action_resource_types', 'search_resources'):
            return []
        if operation == 'list_availability_domains':
            return [{'name': 'AD'}]
        kinds = {'list_policies': 'Policy', 'list_volumes': 'Volume'}
        return [dict(n.metadata, id=n.key, compartment_id=n.compartment_id, lifecycle_state=n.lifecycle_state) for n in self.resources.values() if n.resource_type == kinds.get(operation) and n.lifecycle_state not in ('DELETED', 'TERMINATED') and (not params.get('compartment_id') or n.compartment_id == params['compartment_id'])]

    def read(self, service, region, operation, params, endpoint=None):
        if operation == 'get_compartment' and params['compartment_id'] in self.deleted_compartments:
            return (dict(id=params['compartment_id'], compartment_id=self.deleted_compartments[params['compartment_id']], lifecycle_state='DELETED'), {})
        row, headers = super().read(service, region, operation, params, endpoint)
        return (row, dict(headers, etag='etag'))

    def write(self, service, region, operation, params, endpoint=None):
        self._event('write', service, region, operation, params, endpoint)
        key = next((v for k, v in params.items() if k.endswith('_id')))
        if operation == 'delete_compartment':
            if any((n.compartment_id == key and n.lifecycle_state not in ('DELETED', 'TERMINATED') for n in self.resources.values())):
                raise CleanupError('nonempty')
            self.deleted_compartments[key] = self.compartment_links.pop(key)
        else:
            self.resources[key] = replace(self.resources[key], lifecycle_state='TERMINATED' if self.resources[key].resource_type == 'Volume' else 'DELETED')
        if self.after_write:
            self.after_write()
        return (None, {'opc-request-id': 'trace-only'})

class ExecutorSupport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Workspace(Path(self.tmp.name))
        self.g = ExecutionGateway()
        self.registry = Registry({'policies': IAMPolicies(), 'blockstorage': BlockBootVolumes()})

    def add(self, key='volume', owner=P):
        self.g.add(Node(key, 'Volume', R, owner, key, 'AVAILABLE', '', 'unresolved', {}))

    def plan(self):
        p = discover(self.g, P, self.registry)
        s = reconcile_state(p, None)
        with self.workspace.locked():
            self.workspace.save_plan(p)
            self.workspace.save_state(s)
        return (p, s)

    def run_plan(self, p, s):
        return executor.execute(p, s, self.workspace, self.g, self.registry, P, wait_seconds=1)

class ExecutorTests(ExecutorSupport):

    def test_seven_level_real_volume_and_compartment_cleanup(self):
        owner = P
        for i in range(7):
            child = f'ocid1.compartment.oc1..level{i}'
            self.g.compartment_links[child] = owner
            owner = child
            self.add(f'volume{i}', owner)
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertEqual(self.g.compartment_links, {P: T})
        self.assertTrue(all((n.lifecycle_state == 'TERMINATED' for n in self.g.resources.values())))
        self.assertEqual(executor.cleanup_result(p, s), (f'Cleanup complete for the recorded discovery coverage; retained parent: {P}.', 0))

    def test_slow_initial_inventory_does_not_consume_runnable_cleanup_budget(self):
        self.add()
        p, s = self.plan()
        with patch.object(executor.time, 'monotonic', side_effect=[0] + [10] * 100), patch.object(executor.time, 'sleep') as sleep:
            s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        sleep.assert_not_called()

    def test_edited_parent_rejected_without_mutation(self):
        self.add()
        p, s = self.plan()
        p.nodes[P] = replace(p.nodes[P], action='delete')
        with self.assertRaises(CleanupError):
            self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))

    def test_added_resource_never_expands_executable_set(self):
        self.add()
        p, s = self.plan()
        self.add('new')
        s = self.run_plan(p, s)
        self.assertEqual(self.g.resources['new'].lifecycle_state, 'AVAILABLE')
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_moved_resource_never_mutated(self):
        self.add()
        p, s = self.plan()
        self.g.resources['volume'] = replace(self.g.resources['volume'], compartment_id=T)
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))

    def test_changed_hierarchy_never_deleted(self):
        c = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[c] = P
        self.add(owner=c)
        p, s = self.plan()
        self.g.compartment_links[c] = T
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_save_failure_before_submission_stops_every_write(self):
        self.add()
        self.add('second')
        p, s = self.plan()
        with patch.object(self.workspace, 'save_state', side_effect=CleanupError('disk')):
            with self.assertRaises(CleanupError):
                self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))

    def test_acceptance_crash_intent_is_saved_and_not_replayed(self):
        self.add()
        p, s = self.plan()

        def crash():
            raise KeyboardInterrupt()
        self.g.after_write = crash
        with self.assertRaises(KeyboardInterrupt):
            self.run_plan(p, s)
        _, s = self.workspace.load(P)
        self.assertEqual(s.records['volume']['attempts'][-1]['status'], 'attempting')
        self.g.after_write = None
        s = self.run_plan(p, s)
        self.assertEqual(s.records['volume']['status'], 'deleted')
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)

    def test_ambiguous_attempt_and_active_get_never_replayed(self):
        self.add()
        p, s = self.plan()
        s.records['volume']['attempts'] = [{'attempt_id': 'old', 'status': 'attempting'}]
        with self.workspace.locked():
            self.workspace.save_state(s)
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_active_reappearance_overrides_old_deleted_history(self):
        self.add()
        p, s = self.plan()
        s.records['volume']['status'] = 'deleted'
        s.records['volume']['attempts'] = [{'attempt_id': 'old', 'status': 'deleted'}]
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))

    def test_etag_change_at_submission_boundary_never_mutates(self):
        self.add()
        p, s = self.plan()
        original = self.g.read
        calls = [0]

        def changing(service, region, operation, params, endpoint=None):
            row, headers = original(service, region, operation, params, endpoint)
            if operation == 'get_volume':
                calls[0] += 1
                headers['etag'] = 'old' if calls[0] < 6 else 'changed'
            return (row, headers)
        self.g.read = changing
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))

    def test_local_failure_after_acceptance_stops_independent_branch(self):
        self.add('a')
        self.add('b')
        p, s = self.plan()
        save = self.workspace.save_state

        def failing(state):
            if any((e[0] == 'write' for e in self.g.events)):
                raise CleanupError('disk')
            save(state)
        with patch.object(self.workspace, 'save_state', side_effect=failing):
            with self.assertRaises(CleanupError):
                self.run_plan(p, s)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)

    def test_new_child_appears_before_compartment_delete_is_preserved(self):
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        self.add(owner=child)
        p, s = self.plan()
        original = self.g.write

        def add_child(*args, **kwargs):
            result = original(*args, **kwargs)
            self.g.compartment_links['ocid1.compartment.oc1..new'] = child
            return result
        self.g.write = add_child
        s = self.run_plan(p, s)
        self.assertIn(child, self.g.compartment_links)
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_failed_applicable_probe_prevents_child_delete(self):
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        self.add(owner=child)
        p, s = self.plan()
        original_write = self.g.write
        original_items = self.g.items

        def write(*args, **kwargs):
            result = original_write(*args, **kwargs)
            self.g.probe_failed = True
            return result

        def items(service, region, operation, params, endpoint=None):
            if getattr(self.g, 'probe_failed', False) and operation == 'list_volumes' and (params.get('compartment_id') == child):
                raise CleanupError('denied inventory')
            return original_items(service, region, operation, params, endpoint)
        self.g.write = write
        self.g.items = items
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' and e[3] == 'delete_compartment' for e in self.g.events)))
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_resource_added_after_last_delete_prevents_child_delete(self):
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        self.add(owner=child)
        p, s = self.plan()
        original = self.g.write

        def add_resource(*args, **kwargs):
            result = original(*args, **kwargs)
            self.add('new', child)
            return result
        self.g.write = add_resource
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' and e[3] == 'delete_compartment' for e in self.g.events)))
        self.assertEqual(self.g.resources['new'].lifecycle_state, 'AVAILABLE')
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_direct_intent_save_failure_at_exact_write_boundary_never_mutates(self):
        self.add()
        plan, state = self.plan()
        original = self.workspace.save_state
        def save(current):
            if current.records.get('volume', {}).get('attempts'):
                raise CleanupError('intent disk failure')
            original(current)
        with patch.object(self.workspace, 'save_state', side_effect=save):
            with self.assertRaises(executor.JournalError):
                self.run_plan(plan, state)
        self.assertFalse(any(event[0] == 'write' for event in self.g.events))

    def test_invalid_wait_rejected_without_writes(self):
        p, s = self.plan()
        with self.assertRaises(CleanupError):
            executor.execute(p, s, self.workspace, self.g, self.registry, P, wait_seconds=0)
if __name__ == '__main__':
    unittest.main()

class IntegratedGateway(ExecutionGateway):

    def __init__(self):
        super().__init__()
        from test_scheduled import ScheduledGateway
        from simulator import StorageSimulator
        self.certs = ScheduledGateway()
        self.certs.tenancy_id = T
        self.certs.home_region = R
        self.certs.regions = [R]
        self.certs.compartment_links = self.compartment_links
        self.certs.cleanup_scope = {P}
        self.storage = StorageSimulator()
        self.storage_list_calls = []
        self.storage.bucket['compartment_id'] = P
        self.catalog = []
        self.partial = False

    def items(self, service, region, operation, params, endpoint=None):
        if service == 'object_storage':
            self.storage_list_calls.append(operation)
            if operation == 'list_buckets' and (not self.storage.bucket or params['compartment_id'] != P):
                return []
            return self.storage.items(service, region, operation, params, endpoint)
        if service in ('certificates', 'kms_vault', 'kms_management', 'vault'):
            return self.certs.items(service, region, operation, params, endpoint)
        if operation == 'list_bulk_action_resource_types':
            return list(self.catalog)
        return super().items(service, region, operation, params, endpoint)

    def read(self, service, region, operation, params, endpoint=None):
        if service == 'object_storage':
            return self.storage.read(service, region, operation, params, endpoint)
        if service in ('certificates', 'kms_vault', 'kms_management', 'vault'):
            return self.certs.read(service, region, operation, params, endpoint)
        return super().read(service, region, operation, params, endpoint)

    def write(self, service, region, operation, params, endpoint=None):
        if service == 'object_storage':
            return self.storage.write(service, region, operation, params, endpoint)
        if service == 'certificates':
            return self.certs.write(service, region, operation, params, endpoint)
        if operation == 'bulk_delete_resources':
            self._event('write', service, region, operation, params, endpoint)
            rows = []
            for i, item in enumerate(params['bulk_delete_resources_details'].resources):
                failed = self.partial and i == 1
                if not failed:
                    self.resources.pop(item.identifier)
                rows.append({'identifier': item.identifier, 'entity_type': item.entity_type, 'action_type': 'FAILED' if failed else 'DELETED'})
            wr = 'wr' + str(len(self.work_requests))
            self.work_requests[wr] = {'id': wr, 'compartment_id': params['compartment_id'], 'status': 'FAILED' if self.partial else 'SUCCEEDED', 'resources': rows, 'errors': [], 'logs': []}
            return (None, {'opc-workrequest-id': wr})
        return super().write(service, region, operation, params, endpoint)

class IntegratedExecutorTests(ExecutorSupport):

    def setUp(self):
        super().setUp()
        self.g = IntegratedGateway()

    def test_pending_certificate_independent_volume_advances(self):
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        self.g.certs.add('Certificate', 'certificate', owner=child)
        self.registry = Registry({'scheduled': ScheduledResources(), 'blockstorage': BlockBootVolumes()})
        self.add()
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertEqual(self.g.resources['volume'].lifecycle_state, 'TERMINATED')
        self.assertEqual(s.records['certificate']['status'], 'pending')
        self.assertIn(child, self.g.compartment_links)
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_cyclic_ca_prerequisites_are_preserved(self):
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        self.registry = Registry({'scheduled': ScheduledResources()})
        self.g.certs.add('CertificateAuthority', 'one', owner=P, issuer_certificate_authority_id='two')
        self.g.certs.add('CertificateAuthority', 'two', owner=P, issuer_certificate_authority_id='one')
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.certs.events)))
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_unresolved_external_certificate_prerequisite_is_preserved(self):
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        self.registry = Registry({'scheduled': ScheduledResources()})
        self.g.certs.add('Certificate', 'cert', owner=P)
        lb = 'ocid1.loadbalancer.oc1..foreign'
        self.g.certs.add('LoadBalancer', lb, owner=T, listeners={'tls': {'ssl_configuration': {'certificate_ids': ['cert']}}})
        self.g.certs.extra['list_associations'] = [{'id': 'a', 'compartment_id': P, 'certificates_resource_id': 'cert', 'associated_resource_id': lb, 'association_type': 'CERTIFICATE', 'lifecycle_state': 'ACTIVE'}]
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.certs.events)))
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_storage_observation_snapshot_never_authorizes_writes_and_clears_on_error(self):
        from compartment_cleanup.handlers.storage import Storage
        from test_storage import obj
        handler = Storage(now=lambda: self.g.storage.now)
        self.registry = Registry({'storage': handler})
        self.g.storage.inventory['list_objects'] = [obj('one')]
        p, _ = self.plan()
        handler.bind_plan(list(p.nodes.values()))
        node = next(node for node in p.nodes.values() if node.resource_type == 'ObjectStorageObject')
        with self.assertRaisesRegex(RuntimeError, 'read pass failed'):
            with handler.observation_pass():
                observation = handler.inspect(self.g, node, {P})
                with self.assertRaises(CleanupError):
                    handler.submit(self.g, node, observation, 'attempt')
                with self.assertRaises(CleanupError):
                    handler.submit_group(self.g, [node], {P}, 'attempt')
                raise RuntimeError('read pass failed')
        self.assertIsNone(handler._observation_cache)
        self.assertFalse(any(event[0] == 'write' for event in self.g.storage.events))

    def test_thousand_object_execute_bounds_complete_inventory_reads(self):
        from compartment_cleanup.handlers.storage import Storage
        from test_storage import obj
        self.registry = Registry({'storage': Storage(now=lambda: self.g.storage.now)})
        self.g.storage.inventory['list_objects'] = [obj(str(i)) for i in range(1000)]
        p, s = self.plan()
        self.g.storage.events.clear()
        self.g.storage_list_calls.clear()
        s = executor.execute(p, s, self.workspace, self.g, self.registry, P, wait_seconds=300)
        counts = {operation: sum(event[3] == operation for event in self.g.storage.events)
                  for operation in ('list_objects', 'list_object_versions')}
        self.assertLessEqual(max(counts.values()), 12, counts)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        self.assertGreaterEqual(sum(event[3] == 'head_object' for event in self.g.storage.events), 1000)
        self.g.storage.events.clear()
        self.g.storage_list_calls.clear()
        s = executor.execute(p, s, self.workspace, self.g, self.registry, P, wait_seconds=300)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        self.assertLessEqual(self.g.storage_list_calls.count('list_buckets'), 12)


    def test_storage_preparation_then_batch_then_bucket_complete(self):
        from compartment_cleanup.handlers.storage import Storage
        from test_storage import obj
        self.registry = Registry({'storage': Storage(now=lambda: self.g.storage.now)})
        self.g.storage.inventory['list_objects'] = [obj('one'), obj('two')]
        self.g.storage.bucket['object_lifecycle_policy_etag'] = 'policy-etag'
        self.g.storage.policy['items'] = [{'name': 'expiry', 'action': 'DELETE', 'is_enabled': True, 'time_amount': 1, 'time_unit': 'DAYS', 'target': 'objects'}]
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertIsNone(self.g.storage.bucket)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        writes = [e[3] for e in self.g.storage.events if e[0] == 'write']
        self.assertEqual(writes, ['delete_object_lifecycle_policy', 'batch_delete_objects', 'delete_bucket'])

    def test_partial_bulk_preserves_success_and_failed_retry_history(self):
        self.add('a')
        self.add('b')
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        self.g.partial = True
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertEqual(s.records['a']['status'], 'deleted')
        self.assertEqual(s.records['b']['status'], 'failed')
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)
        self.assertEqual(len(s.records['a']['attempts']), 1)
        self.g.partial = False
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        self.assertEqual(len(s.records['a']['attempts']), 1)
        self.assertEqual(len(s.records['b']['attempts']), 2)

    def test_moved_in_external_compartment_is_never_executable(self):
        self.add()
        p, s = self.plan()
        external = 'ocid1.compartment.oc1..foreign'
        self.g.compartment_links[external] = P
        self.add('foreign', external)
        s = self.run_plan(p, s)
        self.assertFalse(any((e[0] == 'write' for e in self.g.events)))
        self.assertEqual(self.g.cleanup_scope, {P})
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

class ResumeExecutorTests(ExecutorSupport):

    def test_purged_terminal_volume_retains_positive_proof(self):
        self.add()
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.g.resources.pop('volume')
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)

    def test_no_terminal_proof_absence_stays_unresolved(self):
        self.add()
        p, s = self.plan()
        self.g.resources.pop('volume')
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 2)

    def test_pending_async_advances_within_budget(self):
        self.add()
        p, s = self.plan()
        original = self.g.write

        def pending(*args, **kwargs):
            result = original(*args, **kwargs)
            self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='TERMINATING')
            return result
        self.g.write = pending

        def mature(seconds):
            self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='TERMINATED')
        with patch.object(executor.time, 'sleep', side_effect=mature):
            s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)

    def test_unknown_current_schedule_clears_old_schedule(self):
        from compartment_cleanup.model import Observation
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        n = ScheduledResources().classify(Node('cert', 'Certificate', R, P, '', 'ACTIVE', '', 'schedule', {}))
        from compartment_cleanup.model import State
        s = State(1, T, P, {'cert': {'status': 'pending', 'scheduled_at': '2026-10-01T00:00:00Z', 'attempts': []}})
        executor._apply_observation(s, n, Observation('pending', P, 'PENDING_DELETION', None, None, ''))
        self.assertIsNone(s.records['cert']['scheduled_at'])
        self.assertEqual(s.records['cert']['schedule_history'][0]['scheduled_at'], '2026-10-01T00:00:00Z')

class RouteGateway(ExecutionGateway):

    def __init__(self):
        super().__init__()
        from test_network import NetworkTests
        fixture = NetworkTests()
        fixture.setUp()
        fixture.routes()
        self.network = fixture.g
        self.network.compartment_links = self.compartment_links
        self.network.tenancy_id = T
        self.network.home_region = R
        self.network.resources = {k: replace(n, compartment_id=P) for k, n in self.network.resources.items()}
        for rows in self.network.rows.values():
            for row in rows:
                row['compartment_id'] = P

    def items(self, service, region, operation, params, endpoint=None):
        if service == 'identity' and operation in ('list_region_subscriptions', 'list_compartments', 'list_bulk_action_resource_types') or operation == 'search_resources':
            return super().items(service, region, operation, params, endpoint)
        return [row for row in self.network.items(service, region, operation, params, endpoint) if row.get('lifecycle_state') not in ('TERMINATED', 'DELETED')]

    def read(self, service, region, operation, params, endpoint=None):
        if operation == 'get_compartment':
            return super().read(service, region, operation, params, endpoint)
        return self.network.read(service, region, operation, params, endpoint)

    def write(self, service, region, operation, params, endpoint=None):
        self._event('write', service, region, operation, params, endpoint)
        if operation == 'update_route_table':
            n = self.network.resources['rt']
            self.network.resources['rt'] = replace(n, metadata=dict(n.metadata, route_rules=[]))
            self.network.rows['list_route_tables'][0]['route_rules'] = []
        else:
            key = next((v for k, v in params.items() if k.endswith('_id')))
            keys = [key]
            if key == 'v':
                keys += ['rt', 'sl', 'dh', 'resolver', 'view']
            for k in keys:
                self.network.resources[k] = replace(self.network.resources[k], lifecycle_state='TERMINATED' if k not in ('resolver', 'view') else 'DELETED')
                for rows in self.network.rows.values():
                    for row in rows:
                        if row['id'] == k:
                            row['lifecycle_state'] = self.network.resources[k].lifecycle_state
        return (None, {'opc-request-id': 'trace'})

class RouteExecutorTests(ExecutorSupport):

    def setUp(self):
        super().setUp()
        self.g = RouteGateway()
        from compartment_cleanup.handlers.network import Networks, RoutePreparations
        self.registry = Registry({'network': Networks(), 'network_routes': RoutePreparations()})

    def test_route_preparation_and_vcn_cascade_progress(self):
        p, s = self.plan()
        s = self.run_plan(p, s)
        self.assertEqual(self.g.network.resources['v'].lifecycle_state, 'TERMINATED')
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        self.assertEqual([e[3] for e in self.g.events if e[0] == 'write'], ['update_route_table', 'delete_internet_gateway', 'delete_vcn'])

    def test_cascade_child_404_requires_durable_fresh_membership(self):
        p, s = self.plan()
        s = self.run_plan(p, s)
        for key in ('rt', 'sl', 'dh', 'resolver', 'view'):
            self.g.network.resources.pop(key)
        for op, rows in self.g.network.rows.items():
            self.g.network.rows[op] = [r for r in rows if r.get('id') not in ('rt', 'sl', 'dh', 'resolver', 'view')]
        s = self.run_plan(p, s)
        self.assertEqual(executor.cleanup_result(p, s)[1], 0)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 3)

class ReviewScheduledResumeTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = IntegratedGateway()
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        self.registry = Registry({'scheduled': ScheduledResources()})
        original = self.g.read
        def read(service, region, operation, params, endpoint=None):
            try:
                return original(service, region, operation, params, endpoint)
            except CleanupError as error:
                if str(error) == 'Missing identity':
                    raise executor.GatewayError(service, operation, 404) from error
                raise
        self.g.read = read

    def test_completed_certificate_purge_reuses_positive_history(self):
        row = self.g.certs.add('Certificate', 'cert', owner=P)
        plan, state = self.plan()
        row['lifecycle_state'] = 'DELETED'
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.certs.rows.pop((R, 'Certificate', 'cert'))
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)

    def test_completed_unreplicated_secret_purge_reuses_positive_history(self):
        self.g.certs.add('Vault', 'vault', owner=T, management_endpoint='https://verified.endpoint', vault_type='DEFAULT', is_primary=True)
        self.g.certs.add('Key', 'key', owner=T, vault_id='vault', protection_mode='HSM', is_primary=True)
        row = self.g.certs.add('Secret', 'secret', owner=P, vault_id='vault', key_id='key', is_replica=False)
        plan, state = self.plan()
        row['lifecycle_state'] = 'DELETED'
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.certs.rows.pop((R, 'Secret', 'secret'))
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)

    def test_certificate_purge_with_denied_typed_inventory_stays_unresolved(self):
        row = self.g.certs.add('Certificate', 'cert', owner=P)
        plan, state = self.plan()
        row['lifecycle_state'] = 'DELETED'
        state = self.run_plan(plan, state)
        self.g.certs.rows.pop((R, 'Certificate', 'cert'))
        original = self.g.items
        def denied(service, region, operation, params, endpoint=None):
            if operation == 'list_certificates':
                raise executor.GatewayError(service, operation, 403)
            return original(service, region, operation, params, endpoint)
        self.g.items = denied
        state = self.run_plan(plan, state)
        self.assertNotEqual(state.records['cert']['status'], 'deleted')
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)

class AnalyticsExecutionGateway(ExecutionGateway):
    def __init__(self):
        super().__init__()
        from test_logging_analytics import AnalyticsGateway
        self.analytics = AnalyticsGateway()
        self.analytics.tenancy_id = T
        self.analytics.compartment_links = self.compartment_links
        self.analytics.cleanup_scope = {P}
    def read(self, service, region, operation, params, endpoint=None):
        if service in ('log_analytics', 'service_connector'):
            try:
                return self.analytics.read(service, region, operation, params, endpoint)
            except KeyError as error:
                raise executor.GatewayError(service, operation, 404) from error
        return super().read(service, region, operation, params, endpoint)
    def items(self, service, region, operation, params, endpoint=None):
        if service in ('log_analytics', 'service_connector'):
            return self.analytics.items(service, region, operation, params, endpoint)
        return super().items(service, region, operation, params, endpoint)
    def write(self, service, region, operation, params, endpoint=None):
        if service in ('log_analytics', 'service_connector'):
            return self.analytics.write(service, region, operation, params, endpoint)
        return super().write(service, region, operation, params, endpoint)

class ReviewAnalyticsResumeTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = AnalyticsExecutionGateway()
        from compartment_cleanup.handlers.logging_analytics import LoggingAnalytics
        self.registry = Registry({'logging_analytics': LoggingAnalytics()})
    def test_completed_manual_entity_purge_reuses_positive_history(self):
        self.g.analytics.add('LogAnalyticsEntity', 'entity', owner=P)
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.analytics.rows.pop(('LogAnalyticsEntity', 'entity'))
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
    def test_reappeared_manual_entity_wins_prior_terminal_history(self):
        self.g.analytics.add('LogAnalyticsEntity', 'entity', owner=P)
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.analytics.rows[('LogAnalyticsEntity', 'entity')][1]['lifecycle_state'] = 'ACTIVE'
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(len([e for e in self.g.analytics.events if e[0] == 'write']), 1)

    def test_ineligible_live_entity_invalidates_completion_before_later_absence(self):
        self.g.analytics.add('LogAnalyticsEntity', 'entity', owner=P)
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.analytics.rows[('LogAnalyticsEntity', 'entity')][1]['lifecycle_state'] = 'ACTIVE'
        self.g.analytics.add('ServiceConnector', 'external', owner=T,
                             target={'kind': 'loggingAnalytics', 'log_group_id': 'group'})
        state = self.run_plan(plan, state)
        self.assertTrue(state.records['entity'].get('proof_invalidations'))
        self.g.analytics.rows.pop(('LogAnalyticsEntity', 'entity'))
        self.g.analytics.rows.pop(('ServiceConnector', 'external'))
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(sum(event[0] == 'write' for event in self.g.analytics.events), 1)

    def test_entity_purge_with_active_external_producer_stays_unresolved(self):
        self.g.analytics.add('LogAnalyticsEntity', 'entity', owner=P)
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.analytics.rows.pop(('LogAnalyticsEntity', 'entity'))
        self.g.analytics.add('ServiceConnector', 'external', owner=T,
                             target={'kind': 'loggingAnalytics', 'log_group_id': 'group'})
        state = self.run_plan(plan, state)
        self.assertNotEqual(state.records['entity']['status'], 'deleted')
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)

class ReviewProofTests(ExecutorSupport):
    def test_nonterminal_foreign_or_malformed_proof_never_proves_absence(self):
        from copy import deepcopy
        self.add()
        plan, original = self.plan()
        self.g.resources.pop('volume')
        proof = {
            'node_key': 'volume', 'resource_type': 'Volume',
            'compartment_id': P, 'region': R,
            'lifecycle_state': 'TERMINATED',
            'observed_at': '2026-10-08T00:00:00+00:00',
        }
        for changes in (
            {'lifecycle_state': 'ACTIVE'}, {'region': 'foreign'},
            {'observed_at': 'not a timestamp'},
            {'observed_at': '2999-01-01T00:00:00+00:00'},
            {'observed_at': '2026-10-08T00:00:00'},
        ):
            with self.subTest(changes=changes):
                state = deepcopy(original)
                state.records['volume']['terminal_observation'] = dict(proof, **changes)
                state = self.run_plan(plan, state)
                self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
                self.assertNotEqual(state.records['volume']['status'], 'deleted')

    def test_positive_proof_captures_region_and_preserves_original_timestamp(self):
        self.add()
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        proof = dict(state.records['volume']['terminal_observation'])
        self.assertEqual(proof['region'], R)
        self.g.resources.pop('volume')
        state = self.run_plan(plan, state)
        self.assertEqual(state.records['volume']['terminal_observation'], proof)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)

    def test_policy_purged_after_positive_deleted_remains_complete(self):
        self.g.add(Node('policy', 'Policy', R, P, '', 'ACTIVE', '', 'unresolved', {}))
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.resources.pop('policy')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)

    def test_compartment_purged_after_positive_deleted_remains_complete(self):
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        self.add(owner=child)
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.deleted_compartments.clear()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 2)

    def test_purged_policy_denied_inventory_remains_unresolved(self):
        self.g.add(Node('policy', 'Policy', R, P, '', 'ACTIVE', '', 'unresolved', {}))
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.resources.pop('policy')
        original = self.g.items
        def denied(service, region, operation, params, endpoint=None):
            if operation == 'list_policies':
                raise executor.GatewayError(service, operation, 403)
            return original(service, region, operation, params, endpoint)
        self.g.items = denied
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)

    def test_purged_compartment_reappearing_under_another_parent_wins_history(self):
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.deleted_compartments.clear()
        self.g.compartment_links[child] = T
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(state.records[child]['status'], 'moved')

    def test_persistently_rejected_direct_request_attempts_once_per_run(self):
        self.add()
        plan, state = self.plan()
        writes = []
        original = self.g.write
        def reject(service, region, operation, params, endpoint=None):
            writes.append(operation)
            raise executor.GatewayError(service, operation, 412, 'NoEtagMatch')
        self.g.write = reject
        state = self.run_plan(plan, state)
        self.assertEqual(writes, ['delete_volume'])
        self.assertEqual(len(state.records['volume']['attempts']), 1)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.g.write = original
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)

    def test_direct_precondition_rejection_retries_fresh_on_later_run(self):
        self.add()
        plan, state = self.plan()
        original = self.g.write
        rejected = [False]
        def reject_once(service, region, operation, params, endpoint=None):
            if not rejected[0]:
                rejected[0] = True
                self.g._event('write', service, region, operation, params, endpoint)
                raise executor.GatewayError(service, operation, 412, 'NoEtagMatch')
            return original(service, region, operation, params, endpoint)
        self.g.write = reject_once
        state = self.run_plan(plan, state)
        self.assertEqual(state.records['volume']['attempts'][0]['status'], 'failed')
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        original_read = self.g.read
        def refreshed(service, region, operation, params, endpoint=None):
            row, headers = original_read(service, region, operation, params, endpoint)
            if operation == 'get_volume':
                headers['etag'] = 'new-etag'
            return row, headers
        self.g.read = refreshed
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        attempts = state.records['volume']['attempts']
        self.assertEqual(attempts[0]['params']['if_match'], 'etag')
        self.assertEqual(attempts[1]['params']['if_match'], 'new-etag')
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0]['status'], 'failed')
        self.assertEqual(attempts[1]['status'], 'deleted')
        self.assertNotEqual(attempts[0]['attempt_id'], attempts[1]['attempt_id'])

class ReviewBulkPollingTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = IntegratedGateway()
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        self.add()
        original = self.g.write
        def pending(service, region, operation, params, endpoint=None):
            result = original(service, region, operation, params, endpoint)
            if operation == 'bulk_delete_resources':
                wr = self.g.work_requests[result[1]['opc-workrequest-id']]
                wr['status'] = 'IN_PROGRESS'
                for row in wr['resources']:
                    row['action_type'] = 'IN_PROGRESS'
            return result
        self.g.write = pending

    def test_pending_group_with_missing_gets_advances_inside_budget(self):
        plan, state = self.plan()
        ticks = [0.0]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds)
            ticks[0] += seconds
            for wr in self.g.work_requests.values():
                wr['status'] = 'SUCCEEDED'
                for row in wr['resources']:
                    row['action_type'] = 'DELETED'
        with patch.object(executor.time, 'monotonic', side_effect=lambda: ticks[0]), patch.object(executor.time, 'sleep', side_effect=sleep):
            state = executor.execute(plan, state, self.workspace, self.g, self.registry, P, wait_seconds=6)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.assertEqual(sleeps, [5])
        self.assertEqual(len([e for e in self.g.events if e[3] == 'get_work_request']), 2)

    def test_pending_original_group_missing_from_refresh_fails_closed(self):
        plan, state = self.plan()
        ticks = [0.0]
        def sleep(seconds):
            ticks[0] += seconds
        with patch.object(executor.time, 'monotonic', side_effect=lambda: ticks[0]), patch.object(executor.time, 'sleep', side_effect=sleep):
            state = executor.execute(plan, state, self.workspace, self.g, self.registry, P, wait_seconds=1)
        refreshed = discover(self.g, P, self.registry)
        self.assertNotIn('volume', refreshed.nodes)
        with self.workspace.locked():
            self.workspace.save_plan(refreshed)
        with self.assertRaises(CleanupError):
            self.run_plan(refreshed, state)
        self.assertEqual(sum(event[0] == 'write' for event in self.g.events), 1)

    def test_pending_group_timeout_uses_only_remaining_budget(self):
        plan, state = self.plan()
        ticks = [0.0]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds)
            ticks[0] += seconds
        with patch.object(executor.time, 'monotonic', side_effect=lambda: ticks[0]), patch.object(executor.time, 'sleep', side_effect=sleep):
            state = executor.execute(plan, state, self.workspace, self.g, self.registry, P, wait_seconds=6)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(sleeps, [5, 1])
        self.assertEqual(ticks[0], 6)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)

class OtherDirectExecutionGateway(ExecutionGateway):
    def items(self, service, region, operation, params, endpoint=None):
        kind = {'list_instances': 'Instance', 'list_load_balancers': 'LoadBalancer',
                'list_network_load_balancers': 'NetworkLoadBalancer'}.get(operation)
        if kind:
            self._event('items', service, region, operation, params, endpoint)
            return [dict(node.metadata, id=node.key, compartment_id=node.compartment_id,
                         lifecycle_state=node.lifecycle_state)
                    for node in self.resources.values()
                    if node.resource_type == kind and node.compartment_id == params['compartment_id']
                    and node.lifecycle_state not in ('DELETED', 'TERMINATED')]
        return super().items(service, region, operation, params, endpoint)
    def write(self, service, region, operation, params, endpoint=None):
        result = super().write(service, region, operation, params, endpoint)
        if operation == 'terminate_instance':
            key = params['instance_id']
            self.resources[key] = replace(self.resources[key], lifecycle_state='TERMINATED')
        return result

class ReviewOtherDirectResumeTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = OtherDirectExecutionGateway()
    def test_completed_instance_purge_reuses_positive_history(self):
        from compartment_cleanup.handlers.core import ComputeInstances
        self.registry = Registry({'compute': ComputeInstances()})
        self.g.add(Node('instance', 'Instance', R, P, '', 'RUNNING', '', 'unresolved', {'availability_domain': 'AD'}))
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.resources.pop('instance')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
    def test_completed_load_balancer_purge_reuses_positive_history(self):
        from compartment_cleanup.handlers.load_balancers import LoadBalancers
        from test_load_balancers import payload
        self.registry = Registry({'load_balancers': LoadBalancers()})
        self.g.add(Node('subnet', 'Subnet', R, P, '', 'AVAILABLE', '', 'unresolved', {'vcn_id': 'vcn'}))
        self.g.add(Node('nsg', 'NetworkSecurityGroup', R, P, '', 'AVAILABLE', '', 'unresolved', {'vcn_id': 'vcn'}))
        metadata = payload('LoadBalancer')
        metadata['listeners'] = {}
        metadata['backend_sets'] = {}
        key = 'ocid1.loadbalancer.oc1.region.lb'
        self.g.add(Node(key, 'LoadBalancer', R, P, '', 'ACTIVE', '', 'unresolved', metadata))
        plan, state = self.plan()
        self.g.resources[key] = replace(self.g.resources[key], lifecycle_state='DELETED')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.resources.pop(key)
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)

class ReviewProofInvalidationTests(ExecutorSupport):
    def test_direct_positive_proof_cannot_revive_after_reappearance(self):
        self.add()
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='AVAILABLE')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.g.resources.pop('volume')
        with self.workspace.locked():
            _, state = self.workspace.load(P)
        for _ in range(2):
            state = self.run_plan(plan, state)
            self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)
        self.assertEqual(state.records['volume']['attempts'][0]['status'], 'deleted')

class ReviewBulkProofInvalidationTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = IntegratedGateway()
    def test_contradicted_member_isolated_and_refresh_gets_distinct_new_group(self):
        self.add('one')
        self.add('two')
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        original = list(executor.attempt_history(state, 'one'))[0]
        original_args = original['resources']
        self.add('one')
        state = self.run_plan(plan, state)
        self.assertTrue(state.records['one'].get('proof_invalidations'))
        self.assertNotIn('proof_invalidations', state.records['two'])
        self.assertEqual(state.records['two']['status'], 'deleted')
        self.assertEqual(list(executor.attempt_history(state, 'one'))[0]['resources'], original_args)
        fresh = discover(self.g, P, self.registry)
        state = reconcile_state(fresh, state)
        with self.workspace.locked():
            self.workspace.save_plan(fresh)
        state = self.run_plan(fresh, state)
        self.assertEqual(executor.cleanup_result(fresh, state)[1], 0)
        attempts = list(executor.attempt_history(state, 'one'))
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0]['attempt_id'], attempts[1]['attempt_id'])
        self.assertEqual(len(list(executor.attempt_history(state, 'two'))), 1)

    def test_old_shared_deleted_event_cannot_revive_after_reappearance(self):
        self.add()
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertNotIn('terminal_observation', state.records['volume'])
        self.add()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.g.resources.pop('volume')
        with self.workspace.locked():
            _, state = self.workspace.load(P)
        for _ in range(2):
            state = self.run_plan(plan, state)
            self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(len([e for e in self.g.events if e[0] == 'write']), 1)

class ReviewLoadBalancerProofInvalidationTests(ExecutorSupport):
    def test_old_exact_delete_work_request_cannot_revive_after_reappearance(self):
        from compartment_cleanup.handlers.load_balancers import LoadBalancers
        from test_load_balancers import payload
        self.g = OtherDirectExecutionGateway()
        self.registry = Registry({'load_balancers': LoadBalancers()})
        self.g.add(Node('subnet', 'Subnet', R, P, '', 'AVAILABLE', '', 'unresolved', {'vcn_id': 'vcn'}))
        self.g.add(Node('nsg', 'NetworkSecurityGroup', R, P, '', 'AVAILABLE', '', 'unresolved', {'vcn_id': 'vcn'}))
        metadata = payload('LoadBalancer')
        metadata['listeners'] = {}
        metadata['backend_sets'] = {}
        key = 'ocid1.loadbalancer.oc1.region.lb'
        self.g.add(Node(key, 'LoadBalancer', R, P, '', 'ACTIVE', '', 'unresolved', metadata))
        plan, state = self.plan()
        self.g.resources[key] = replace(self.g.resources[key], lifecycle_state='DELETED')
        state.records[key]['attempts'] = [{'attempt_id': 'original', 'request_id': 'work', 'status': 'deleted'}]
        self.g.work_requests['work'] = {'id': 'work', 'compartment_id': P, 'load_balancer_id': key,
                                       'type': 'DeleteLoadBalancer', 'lifecycle_state': 'SUCCEEDED', 'error_details': []}
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        state.records[key].pop('terminal_observation', None)
        self.g.resources[key] = replace(self.g.resources[key], lifecycle_state='ACTIVE')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.g.resources.pop(key)
        with self.workspace.locked():
            _, state = self.workspace.load(P)
        for _ in range(2):
            state = self.run_plan(plan, state)
            self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertFalse(any(event[0] == 'write' for event in self.g.events))

class ReviewInvalidationSafetyTests(ExecutorSupport):
    def test_explicit_refresh_allows_new_action_after_completed_identity_reappears(self):
        self.add()
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='AVAILABLE')
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        fresh = discover(self.g, P, self.registry)
        state = reconcile_state(fresh, state)
        with self.workspace.locked():
            self.workspace.save_plan(fresh)
        state = self.run_plan(fresh, state)
        self.assertEqual(executor.cleanup_result(fresh, state)[1], 0)
        attempts = state.records['volume']['attempts']
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0]['attempt_id'], attempts[1]['attempt_id'])
        self.g.resources.pop('volume')
        state = self.run_plan(fresh, state)
        self.assertEqual(executor.cleanup_result(fresh, state)[1], 0)

    def test_invalidation_cannot_claim_an_ambiguous_attempt_completed(self):
        from datetime import datetime, timezone
        self.add()
        plan, state = self.plan()
        state.records['volume']['attempts'] = [{'attempt_id': 'uncertain', 'status': 'unresolved'}]
        state.records['volume']['proof_invalidations'] = [{
            'observed_at': datetime.now(timezone.utc).isoformat(), 'plan_created_at': plan.created_at,
            'attempt_ids': ['uncertain'], 'completed_attempt_ids': ['uncertain'],
            'terminal_observed_at': None, 'owner_attempt_ids': []}]
        with self.assertRaises(CleanupError):
            self.run_plan(plan, state)
        self.assertFalse(any(event[0] == 'write' for event in self.g.events))

    def test_malformed_invalidation_fails_before_mutation(self):
        self.add()
        plan, state = self.plan()
        state.records['volume']['proof_invalidations'] = [{'attempt_ids': 'invalid'}]
        with self.assertRaises(CleanupError):
            self.run_plan(plan, state)
        self.assertFalse(any(event[0] == 'write' for event in self.g.events))

    def test_refresh_cannot_drop_absent_contradicted_identity_from_completion(self):
        self.add()
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='AVAILABLE')
        state = self.run_plan(plan, state)
        self.g.resources.pop('volume')
        fresh = discover(self.g, P, self.registry)
        self.assertNotIn('volume', fresh.nodes)
        state = reconcile_state(fresh, state)
        with self.workspace.locked():
            self.workspace.save_plan(fresh)
        state = self.run_plan(fresh, state)
        self.assertEqual(executor.cleanup_result(fresh, state)[1], 2)
        self.assertEqual(sum(event[0] == 'write' for event in self.g.events), 1)

    def test_initial_present_without_terminal_event_does_not_invalidate(self):
        self.add()
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertNotIn('proof_invalidations', state.records['volume'])

class ReviewStorageInvalidationTests(ExecutorSupport):
    def setUp(self):
        super().setUp()
        self.g = IntegratedGateway()
        from compartment_cleanup.handlers.storage import Storage
        self.registry = Registry({'storage': Storage(now=lambda: self.g.storage.now)})

    def test_refreshed_changed_object_gets_new_exact_batch_and_bucket_actions(self):
        from copy import deepcopy
        from test_storage import obj
        bucket = deepcopy(self.g.storage.bucket)
        self.g.storage.inventory['list_objects'] = [obj('one'), obj('two')]
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.g.storage.bucket = bucket
        changed = obj('one')
        changed['etag'] = 'changed-etag'
        self.g.storage.inventory['list_objects'] = [changed]
        state = self.run_plan(plan, state)
        fresh = discover(self.g, P, self.registry)
        state = reconcile_state(fresh, state)
        with self.workspace.locked():
            self.workspace.save_plan(fresh)
        state = self.run_plan(fresh, state)
        self.assertEqual(executor.cleanup_result(fresh, state)[1], 0)
        self.assertEqual(sum(event[0] == 'write' for event in self.g.storage.events), 4)
        key = next(node.key for node in fresh.nodes.values() if node.metadata.get('object_name') == 'one')
        history = list(executor.attempt_history(state, key))
        self.assertEqual(len(history), 2)
        self.assertNotEqual(history[0]['attempt_id'], history[1]['attempt_id'])

    def test_changed_etag_presence_invalidates_old_batch_and_owner_evidence(self):
        from copy import deepcopy
        from test_storage import obj
        bucket = deepcopy(self.g.storage.bucket)
        self.g.storage.inventory['list_objects'] = [obj('one'), obj('two')]
        plan, state = self.plan()
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 0)
        self.g.storage.bucket = bucket
        changed = obj('one')
        changed['etag'] = 'changed-etag'
        self.g.storage.inventory['list_objects'] = [changed]
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        key = next(node.key for node in plan.nodes.values() if node.metadata.get('object_name') == 'one')
        self.assertTrue(state.records[key].get('proof_invalidations'))
        self.g.storage.inventory['list_objects'] = []
        self.g.storage.bucket = None
        with self.workspace.locked():
            _, state = self.workspace.load(P)
        state = self.run_plan(plan, state)
        self.assertEqual(executor.cleanup_result(plan, state)[1], 2)
        self.assertEqual(sum(event[0] == 'write' for event in self.g.storage.events), 2)
