"""Offline CLI tests use the real planner, journal, executor and typed handlers."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from compartment_cleanup import cli
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.handlers.core import BlockBootVolumes, IAMPolicies
from compartment_cleanup.model import Node
from compartment_cleanup.store import Workspace
from test_executor import ExecutionGateway, P, R


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.g = ExecutionGateway()
        self.registry = Registry({'policies': IAMPolicies(), 'blockstorage': BlockBootVolumes()})
        self.factory = patch.object(cli, 'build_gateway', return_value=self.g).start()
        self.addCleanup(patch.stopall)
        patch.object(cli, 'build_registry', return_value=self.registry).start()
        self.output = StringIO()

    def run_cli(self, mode='--report', extra=()):
        with redirect_stdout(self.output), redirect_stderr(self.output):
            return cli.main([mode, '--compartment-id', P, '--work-dir', str(self.path), *extra])

    def test_invalid_flags_never_construct_gateway(self):
        cases = [[], ['--report', '--delete'], ['--delete'],
                 ['--delete', '--confirm-parent', 'wrong'],
                 ['--report', '--wait-seconds', 'nan'],
                 ['--report', '--wait-seconds', 'inf'],
                 ['--report', '--wait-seconds', '0'],
                 ['--report', '--compartment-id', 'bad']]
        for args in cases:
            with self.subTest(args=args), redirect_stdout(self.output), redirect_stderr(self.output):
                result = cli.main(['--compartment-id', P, '--work-dir', str(self.path), *args])
                self.assertNotEqual(result, 0)
        self.factory.assert_not_called()

    def test_help_never_constructs_gateway(self):
        with redirect_stdout(self.output):
            self.assertEqual(cli.main(['--help']), 0)
        self.factory.assert_not_called()

    def test_report_only_preserves_history_and_never_writes_oci(self):
        self.g.add(Node('volume', 'Volume', R, P, 'disk', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        w = Workspace(self.path)
        with w.locked():
            p, s = w.load(P)
            s.records['volume']['schedule_history'] = [{'scheduled_at': '2026-10-09T00:00:00Z'}]
            w.save_state(s)
        self.assertEqual(self.run_cli(), 0)
        _, current = w.load(P)
        self.assertEqual(current.records['volume']['schedule_history'], s.records['volume']['schedule_history'])
        self.assertFalse(any(event[0] == 'write' for event in self.g.events))
        self.assertIn(str(self.path / 'state.json'), self.output.getvalue())
        self.assertIn('Preserve the entire work directory', self.output.getvalue())

    def test_failed_probe_exits_two(self):
        self.g.deny('search', R, 'search_resources')
        self.assertEqual(self.run_cli(), 2)

    def test_missing_malformed_or_mismatched_pair_is_fatal(self):
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P]), 1)
        self.assertEqual(self.run_cli(), 0)
        original = (self.path / 'state.json').read_text()
        for bad in ('{', original.replace(P, 'ocid1.compartment.oc1..other')):
            (self.path / 'state.json').write_text(bad)
            self.assertEqual(self.run_cli(), 1)
        (self.path / 'state.json').unlink()
        self.assertEqual(self.run_cli(), 1)

    def test_load_and_execution_share_one_exclusive_lock(self):
        self.assertEqual(self.run_cli(), 0)
        real_load = Workspace.load
        real_execute = cli.execute
        intervals = []

        def load(workspace, parent):
            workspace._writer()
            intervals.append(workspace._lock_fd)
            return real_load(workspace, parent)

        def execute(plan, state, workspace, *args, **kwargs):
            workspace._writer()
            self.assertEqual(workspace._lock_fd, intervals[-1])
            with self.assertRaises(Exception):
                with Workspace(self.path).locked():
                    pass
            return real_execute(plan, state, workspace, *args, **kwargs)

        with patch.object(Workspace, 'load', load), patch.object(cli, 'execute', execute):
            self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)

    def test_report_refresh_invalidates_old_terminal_proof_before_discovery(self):
        self.g.add(Node('volume', 'Volume', R, P, 'disk', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)
        old = Workspace(self.path).load(P)[1]
        self.g.resources['volume'] = replace(self.g.resources['volume'], lifecycle_state='AVAILABLE')
        self.assertEqual(self.run_cli(), 0)
        p, s = Workspace(self.path).load(P)
        self.assertIn('volume', p.nodes)
        self.assertTrue(s.records['volume']['proof_invalidations'])
        self.assertEqual(s.records['volume']['attempts'], old.records['volume']['attempts'])
        self.assertNotEqual(s.records['volume']['status'], 'deleted')
        self.assertFalse(s.records[P].get('verification', {}).get('complete'))

    def test_initial_pending_date_clear_and_identical_delete_after_removal(self):
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        from test_executor import IntegratedGateway
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        self.registry = Registry({'scheduled': ScheduledResources()})
        cli.build_registry.return_value = self.registry
        row = self.g.certs.add('Certificate', 'certificate', owner=P,
                               time_of_deletion='2026-10-20T12:34:56Z')
        row['lifecycle_state'] = 'PENDING_DELETION'
        self.assertEqual(self.run_cli(), 0)
        self.assertIn('certificate is pending deletion until 2026-10-20T12:34:56Z', self.output.getvalue())
        command = ['--confirm-parent', P, '--wait-seconds', '1']
        self.assertEqual(self.run_cli('--delete', command), 2)
        row.pop('time_of_deletion')
        self.assertEqual(self.run_cli(), 0)
        _, state = Workspace(self.path).load(P)
        self.assertIsNone(state.records['certificate']['scheduled_at'])
        self.assertEqual(state.records['certificate']['schedule_history'][0]['scheduled_at'], '2026-10-20T12:34:56Z')
        self.assertNotIn('until 2026-10-20', (self.path / 'report.txt').read_text())
        row['lifecycle_state'] = 'DELETED'
        self.assertEqual(self.run_cli('--delete', command), 0)
        del self.g.certs.rows[(R, 'Certificate', 'certificate')]
        original_read = self.g.read
        from compartment_cleanup.gateway import GatewayError

        def missing(service, region, operation, params, endpoint=None):
            if operation == 'get_certificate':
                raise GatewayError(service, operation, 404, 'NotAuthorizedOrNotFound')
            return original_read(service, region, operation, params, endpoint)

        self.g.read = missing
        self.assertEqual(self.run_cli(), 0)
        p, state = Workspace(self.path).load(P)
        self.assertNotIn('certificate', p.nodes)
        self.assertEqual(state.records['certificate']['status'], 'deleted')
        self.assertFalse(any(event[0] == 'write' for event in self.g.certs.events))

    def test_report_safe_identifiers_and_asynchronous_pending_without_date(self):
        from compartment_cleanup.model import State, Observation
        from compartment_cleanup.reporting import render_report
        from compartment_cleanup.executor import _apply_observation
        self.g.add(Node('volume', 'Volume', R, P, 'disk', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        p, s = Workspace(self.path).load(P)
        p.nodes['volume'] = replace(p.nodes['volume'], metadata={
            'object_name': 'exact/name', 'version_id': 'version-1',
            'kms_key_id': 'external-key', 'preserved_volume_ids': ['external-volume'],
            'subnet_ids': ['external-subnet'], 'log_group_id': 'external-log-group',
            'backend_target_ids': ['external-backend'],
            'retained_public_ips': [{'id': 'reserved-ip', 'private_ip_id': 'private-ip'}],
            'secret_content': 'must-not-print'})
        _apply_observation(s, p.nodes['volume'], Observation('pending', P, 'TERMINATING', None, None, ''))
        text = render_report(p, s)
        for value in ('exact/name', 'version-1', 'external-key', 'external-volume', 'reserved-ip',
                      'external-subnet', 'external-log-group', 'external-backend'):
            self.assertIn(value, text)
        self.assertNotIn('must-not-print', text)
        self.assertIn('asynchronous deletion', text)
        self.assertNotIn('pending deletion until unknown', text)

    def test_auth_arguments_and_actual_registry_dispatch(self):
        from compartment_cleanup.handlers.storage import Storage
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        from compartment_cleanup.handlers.network import Networks, RoutePreparations
        from compartment_cleanup.handlers.core import ComputeInstances
        from compartment_cleanup.handlers.logging_analytics import LoggingAnalytics
        from compartment_cleanup.handlers.load_balancers import LoadBalancers
        # Recover the actual factory while retaining only the external OCI double.
        patch.stopall()
        self.factory = patch.object(cli, 'build_gateway', return_value=self.g).start()
        handlers = cli.build_registry()
        expected = (Storage, ScheduledResources, Networks, RoutePreparations,
                    ComputeInstances, LoggingAnalytics, LoadBalancers,
                    IAMPolicies, BlockBootVolumes)
        self.assertEqual({type(h) for h in handlers.handlers.values()}, set(expected))
        for h in handlers.handlers.values():
            for kind in h.resource_types:
                self.assertIs(handlers.handler_for(Node(kind, kind, R, P, '', '', '', 'unresolved', {})), h)
        for mode in ('api_key', 'instance_principal'):
            self.run_cli(extra=['--auth', mode, '--config-file', '/tmp/operator-config',
                                '--profile', 'OPERATOR', '--bootstrap-region', 'bootstrap'])
            self.factory.assert_called_with(mode, '/tmp/operator-config', 'OPERATOR', 'bootstrap')
        self.assertFalse(any(e[0] == 'write' for e in self.g.events))

    def test_report_refresh_retains_original_shared_bulk_records(self):
        from test_executor import IntegratedGateway
        from compartment_cleanup.journal import bulk_attempt_records
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        self.g.add(Node('one', 'Volume', R, P, '', 'AVAILABLE', '', 'unresolved', {}))
        self.g.add(Node('two', 'Volume', R, P, '', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        command = ['--confirm-parent', P, '--wait-seconds', '1']
        self.assertEqual(self.run_cli('--delete', command), 0)
        before = Workspace(self.path).load(P)[1]
        groups = dict(bulk_attempt_records(before))
        self.assertEqual(len(groups), 1)
        self.assertEqual(self.run_cli(), 0)
        p, after = Workspace(self.path).load(P)
        self.assertEqual(dict(bulk_attempt_records(after)), groups)
        for key in ('one', 'two'):
            self.assertEqual(before.records[key]['attempts'], after.records[key]['attempts'])
            self.assertNotIn(key, p.nodes)
        self.assertEqual(self.run_cli('--delete', command), 0)

    def test_fresh_report_accepts_new_current_hierarchy(self):
        self.assertEqual(self.run_cli(), 0)
        child = 'ocid1.compartment.oc1..addition'
        self.g.compartment_links[child] = P
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 2)
        self.assertIn(child, self.g.compartment_links)
        self.assertEqual(self.run_cli(), 0)
        p, s = Workspace(self.path).load(P)
        self.assertIn(child, p.compartments)
        from compartment_cleanup.model import plan_to_dict, plan_from_dict, state_to_dict, state_from_dict
        self.assertEqual(plan_from_dict(plan_to_dict(p)), p)
        self.assertEqual(state_from_dict(state_to_dict(s)), s)
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)

    def test_report_refresh_clears_stale_plan_date_before_initial_pending_fallback(self):
        from compartment_cleanup.model import Observation
        from compartment_cleanup.executor import _apply_observation
        from compartment_cleanup.reporting import render_report
        self.assertEqual(self.run_cli(), 0)
        p, s = Workspace(self.path).load(P)
        node = Node('cert', 'Certificate', R, P, '', 'PENDING_DELETION', 'scheduled', 'schedule',
                    {'scheduled_at': '2020-01-01T00:00:00Z'})
        p.nodes['cert'] = node
        _apply_observation(s, node, Observation('pending', P, 'PENDING_DELETION', None, None, ''))
        text = render_report(p, s)
        self.assertNotIn('pending deletion until 2020', text)
        self.assertIn('unknown UTC schedule', text)

    def test_report_delete_partial_report_then_identical_delete_after_schedule(self):
        from compartment_cleanup.handlers.scheduled import ScheduledResources
        from test_executor import IntegratedGateway
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        cli.build_registry.return_value = Registry({'scheduled': ScheduledResources(), 'blockstorage': BlockBootVolumes()})
        row = self.g.certs.add('Certificate', 'certificate', owner=P)
        self.g.add(Node('disk', 'Volume', R, P, '', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        command = ['--confirm-parent', P, '--wait-seconds', '1']
        self.assertEqual(self.run_cli('--delete', command), 2)
        self.assertEqual(self.g.resources['disk'].lifecycle_state, 'TERMINATED')
        self.assertEqual(self.run_cli(), 0)
        self.assertIn('certificate is pending deletion until 2026-10-20T12:34:56Z', (self.path / 'report.txt').read_text())
        row['lifecycle_state'] = 'DELETED'
        self.assertEqual(self.run_cli('--delete', command), 0)
        self.assertEqual(sum(e[0] == 'write' for e in self.g.certs.events), 1)
        _, state = Workspace(self.path).load(P)
        self.assertEqual(len(state.records['certificate']['attempts']), 1)

    def test_storage_refresh_keeps_removal_proofs_without_resurrecting_children(self):
        from compartment_cleanup.handlers.storage import Storage
        from test_executor import IntegratedGateway
        from compartment_cleanup.gateway import GatewayError
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        cli.build_registry.return_value = Registry({'storage': Storage()})
        from test_storage import obj
        self.g.storage.inventory['list_objects'] = [obj(f'object-{i}') for i in range(30)]
        self.assertEqual(self.run_cli(), 0)
        # Discovery plus one observation pass; no per-object full bucket scans.
        self.assertLessEqual(self.g.storage_list_calls.count('list_objects'), 3)
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)
        old = Workspace(self.path).load(P)[1]
        original = self.g.read

        def absent(service, region, operation, params, endpoint=None):
            if operation == 'get_bucket':
                raise GatewayError(service, operation, 404, 'NotAuthorizedOrNotFound')
            return original(service, region, operation, params, endpoint)

        self.g.read = absent
        self.assertEqual(self.run_cli(), 0)
        p, current = Workspace(self.path).load(P)
        self.assertEqual(set(p.nodes), {P})
        for key, record in old.records.items():
            if record.get('record_type') == 'bulk_attempt':
                self.assertEqual(current.records[key], record)
            elif key != P:
                self.assertEqual(current.records[key]['attempts'], record['attempts'])
                self.assertEqual(current.records[key]['status'], 'deleted')

    def test_already_locked_executor_requires_actual_lock_ownership(self):
        from compartment_cleanup.executor import execute
        from compartment_cleanup.model import CleanupError
        self.assertEqual(self.run_cli(), 0)
        workspace = Workspace(self.path)
        plan, state = workspace.load(P)
        with self.assertRaises(CleanupError):
            execute(plan, state, workspace, self.g, self.registry, P,
                    wait_seconds=1, already_locked=True)
        self.assertFalse(any(e[0] == 'write' for e in self.g.events))

    def test_contradicted_absent_history_stays_visible_and_incomplete(self):
        self.g.add(Node('disk', 'Volume', R, P, '', 'AVAILABLE', '', 'unresolved', {}))
        self.assertEqual(self.run_cli(), 0)
        command = ['--confirm-parent', P, '--wait-seconds', '1']
        self.assertEqual(self.run_cli('--delete', command), 0)
        self.g.resources['disk'] = replace(self.g.resources['disk'], lifecycle_state='AVAILABLE')
        self.assertEqual(self.run_cli(), 0)
        old = Workspace(self.path).load(P)[1]
        self.g.resources.pop('disk')
        self.assertEqual(self.run_cli(), 0)
        self.assertEqual(self.run_cli('--delete', command), 2)
        _, state = Workspace(self.path).load(P)
        self.assertEqual(state.records['disk']['attempts'], old.records['disk']['attempts'])
        self.assertTrue(state.records['disk']['proof_invalidations'])
        self.assertIn('disk', (self.path / 'report.txt').read_text())
        self.assertNotEqual(state.records['disk']['status'], 'deleted')

    def test_report_retains_pending_iam_members_until_exact_group_completion(self):
        from test_executor import IntegratedGateway
        from compartment_cleanup.discovery import discover
        from compartment_cleanup.executor import submit_bulk
        from compartment_cleanup.store import reconcile_state
        from compartment_cleanup.journal import bulk_attempt_records
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        cli.build_registry.return_value = self.registry
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        original = Node('one', 'Volume', R, P, '', 'AVAILABLE', '', 'unresolved', {})
        self.g.add(original)
        workspace = Workspace(self.path)
        plan = discover(self.g, P, self.registry)
        state = reconcile_state(plan, None)
        with workspace.locked():
            workspace.save_plan(plan)
            workspace.save_state(state)
            result = submit_bulk(self.g, plan, [plan.nodes['one']], 'review-token',
                                 registry=self.registry, workspace=workspace, state=state)
        self.g.resources['one'] = replace(original, lifecycle_state='TERMINATED')
        request = self.g.work_requests[result.request_id]
        request['status'] = 'IN_PROGRESS'
        self.assertEqual(self.run_cli(), 0)
        refreshed, journal = workspace.load(P)
        self.assertIn('one', refreshed.nodes)
        self.assertEqual(next(iter(dict(bulk_attempt_records(journal)).values()))['work_request']['status'], 'IN_PROGRESS')
        self.assertEqual(sum(e[0] == 'write' for e in self.g.events), 1)
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '0.001']), 2)
        request['status'] = 'SUCCEEDED'
        self.g.resources.pop('one')
        self.assertEqual(self.run_cli(), 0)
        refreshed, journal = workspace.load(P)
        self.assertNotIn('one', refreshed.nodes)
        self.assertEqual(journal.records['one']['attempts'], state.records['one']['attempts'])
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)
        self.assertEqual(sum(e[0] == 'write' for e in self.g.events), 1)

    def test_pending_original_child_scope_survives_deleted_compartment_refresh(self):
        from test_executor import IntegratedGateway
        from compartment_cleanup.discovery import discover
        from compartment_cleanup.executor import submit_bulk
        from compartment_cleanup.store import reconcile_state
        self.g = IntegratedGateway()
        self.factory.return_value = self.g
        cli.build_registry.return_value = self.registry
        self.g.catalog = [{'name': 'Volume', 'metadata_keys': []}]
        child = 'ocid1.compartment.oc1..child'
        self.g.compartment_links[child] = P
        original = Node('one', 'Volume', R, child, '', 'AVAILABLE', '', 'unresolved', {})
        self.g.add(original)
        workspace = Workspace(self.path)
        plan = discover(self.g, P, self.registry)
        state = reconcile_state(plan, None)
        with workspace.locked():
            workspace.save_plan(plan)
            workspace.save_state(state)
            result = submit_bulk(self.g, plan, [plan.nodes['one']], 'child-token',
                                 registry=self.registry, workspace=workspace, state=state)
        self.g.resources['one'] = replace(original, lifecycle_state='TERMINATED')
        self.g.deleted_compartments[child] = self.g.compartment_links.pop(child)
        request = self.g.work_requests[result.request_id]
        request['status'] = 'IN_PROGRESS'
        self.assertEqual(self.run_cli(), 2)
        refreshed, journal = workspace.load(P)
        self.assertEqual(refreshed.compartments[child], P)
        self.assertIn(child, refreshed.nodes)
        self.assertIn('one', refreshed.nodes)
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '0.001']), 2)
        request['status'] = 'SUCCEEDED'
        self.g.resources.pop('one')
        self.assertEqual(self.run_cli(), 0)
        refreshed, journal = workspace.load(P)
        self.assertNotIn(child, refreshed.compartments)
        self.assertNotIn('one', refreshed.nodes)
        self.assertEqual(journal.records['one']['attempts'], state.records['one']['attempts'])
        self.assertEqual(self.run_cli('--delete', ['--confirm-parent', P, '--wait-seconds', '1']), 0)
        self.assertEqual(sum(e[0] == 'write' for e in self.g.events), 1)
