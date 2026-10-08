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
        self.storage.bucket['compartment_id'] = P
        self.catalog = []
        self.partial = False

    def items(self, service, region, operation, params, endpoint=None):
        if service == 'object_storage':
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
