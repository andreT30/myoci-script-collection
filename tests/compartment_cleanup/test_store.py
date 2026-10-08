"""Real filesystem/process tests for journal durability and conservative refresh."""
import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from compartment_cleanup.model import CleanupError, Node, Edge, Probe, State, plan_from_dict
from test_graph import payload
try:
    from compartment_cleanup.store import Workspace, reconcile_state
    from compartment_cleanup.reporting import render_report
except ModuleNotFoundError:
    Workspace = None


def contender(path, queue):
    try:
        with Workspace(Path(path)).locked():
            queue.put('acquired')
    except CleanupError:
        queue.put('refused')


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(Workspace, 'workspace persistence is not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.workspace = Workspace(self.path)
        self.plan = plan_from_dict(payload())
        self.state = State(1, 'tenancy', 'parent', {})

    def save(self):
        with self.workspace.locked():
            self.workspace.save_plan(self.plan)
            self.workspace.save_state(self.state)

    def test_refresh_preserves_pending_and_absent_records_without_aliasing(self):
        self.state.records = {'cert': {'status': 'pending', 'scheduled_at': '2026-10-10T12:00:00Z',
                                      'attempts': [{'token': 'original'}], 'history': [{'status': 'failed'}]}}
        result = reconcile_state(self.plan, self.state)
        self.assertEqual(result.records['cert'], {'status': 'pending', 'scheduled_at': '2026-10-10T12:00:00Z',
                                                'attempts': [{'token': 'original'}], 'history': [{'status': 'failed'}]})
        result.records['cert']['attempts'].append({})
        self.assertEqual(len(self.state.records['cert']['attempts']), 1)
        self.assertEqual(result.records['parent']['status'], 'discovered')

    def test_refresh_rejects_different_scope_and_invalid_schema(self):
        for state in [State(1, 'other', 'parent', {}), State(1, 'tenancy', 'other', {}), State(2, 'tenancy', 'parent', {})]:
            with self.subTest(state=state), self.assertRaises(CleanupError):
                reconcile_state(self.plan, state)

    def test_round_trip_and_private_permissions(self):
        self.save()
        plan, state = self.workspace.load('parent')
        self.assertEqual(plan.parent_id, 'parent')
        self.assertEqual(state.records, {})
        for name in ['plan.json', 'state.json']:
            self.assertEqual((self.path / name).stat().st_mode & 0o777, 0o600)

    def test_writes_require_the_workspace_lock(self):
        for operation in [lambda: self.workspace.save_plan(self.plan), lambda: self.workspace.save_state(self.state),
                          lambda: self.workspace.save_report('report')]:
            with self.assertRaises(CleanupError):
                operation()

    def test_save_rejects_scope_change_without_replacing_artifacts(self):
        self.save()
        plan_before = (self.path / 'plan.json').read_bytes()
        state_before = (self.path / 'state.json').read_bytes()
        self.plan.tenancy_id = 'different'
        with self.workspace.locked():
            with self.assertRaises(CleanupError):
                self.workspace.save_plan(self.plan)
            with self.assertRaises(CleanupError):
                self.workspace.save_state(State(1, 'different', 'parent', {}))
        self.assertEqual((self.path / 'plan.json').read_bytes(), plan_before)
        self.assertEqual((self.path / 'state.json').read_bytes(), state_before)

    def test_load_rejects_wrong_parent_and_cross_tenancy_state(self):
        self.save()
        with self.assertRaises(CleanupError):
            self.workspace.load('other')
        data = json.loads((self.path / 'state.json').read_text())
        data['tenancy_id'] = 'other'
        (self.path / 'state.json').write_text(json.dumps(data))
        with self.assertRaises(CleanupError):
            self.workspace.load('parent')

    def test_load_rejects_truncated_duplicate_nonfinite_and_unknown_json(self):
        self.save()
        valid = (self.path / 'state.json').read_text()
        for raw in ['{', valid.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                    valid.replace('"records": {}', '"records": {"x": {"v": NaN}}'),
                    valid.replace('"schema_version": 1', '"schema_version": 2'),
                    valid.replace('"records": {}', '"records": {}, "extra": true')]:
            with self.subTest(raw=raw):
                (self.path / 'state.json').write_text(raw)
                with self.assertRaises(CleanupError):
                    self.workspace.load('parent')

    def test_failed_replace_preserves_previous_json_and_cleans_temporary_file(self):
        self.save()
        before = (self.path / 'state.json').read_bytes()
        self.state.records['new'] = {'status': 'attempting'}
        with self.workspace.locked(), patch('compartment_cleanup.store.os.replace', side_effect=OSError('disk fault')):
            with self.assertRaises(CleanupError):
                self.workspace.save_state(self.state)
        self.assertEqual((self.path / 'state.json').read_bytes(), before)
        self.assertEqual({p.name for p in self.path.iterdir()}, {'plan.json', 'state.json', '.lock'})

    def test_symlink_artifacts_and_lock_are_refused(self):
        external = self.path / 'external'
        external.write_text('unchanged')
        for name in ['plan.json', 'state.json', 'report.txt', '.lock']:
            with self.subTest(name=name):
                link = self.path / name
                link.unlink(missing_ok=True)
                link.symlink_to(external)
                with self.assertRaises(CleanupError):
                    with self.workspace.locked():
                        if name == 'plan.json': self.workspace.save_plan(self.plan)
                        if name == 'state.json': self.workspace.save_state(self.state)
                        if name == 'report.txt': self.workspace.save_report('changed')
                link.unlink()
        self.assertEqual(external.read_text(), 'unchanged')

    def test_symlink_read_is_refused(self):
        self.save()
        original = self.path / 'original'
        (self.path / 'state.json').rename(original)
        (self.path / 'state.json').symlink_to(original)
        with self.assertRaises(CleanupError):
            self.workspace.load('parent')

    def test_second_process_refused_then_acquires_after_release(self):
        ctx = multiprocessing.get_context('spawn')
        def run():
            queue = ctx.Queue()
            process = ctx.Process(target=contender, args=(str(self.path), queue))
            process.start()
            answer = queue.get(timeout=10)
            process.join(timeout=10)
            self.assertEqual(process.exitcode, 0)
            queue.close()
            return answer
        with self.workspace.locked():
            self.assertEqual(run(), 'refused')
        self.assertEqual(run(), 'acquired')

    def test_reports_descending_depth_pending_evidence_and_coverage(self):
        self.plan.nodes.update({'prerequisite': Node('prerequisite', 'Example', 'r', 'parent', '', 'ACTIVE', 'example', 'delete', {}),
                                'cert': Node('cert', 'Certificate', 'r', 'parent', 'bad\x1b[31m\nname', 'ACTIVE', 'cert', 'schedule', {}),
                                'unknown': Node('unknown', 'Unknown', 'r', 'parent', '', '', '', 'unresolved', {}, ('outside\x1b[31m',))})
        self.plan.edges = [Edge('cert', 'prerequisite', 'consumer before issuer')]
        self.plan.probes = [Probe('example', 'r', 'parent', 'failed', 'permission\rdenied')]
        self.state.records = {'cert': {'status': 'pending', 'scheduled_at': '2026-10-10T12:00:00+00:00'},
                              'missing': {'status': 'unresolved', 'errors': ['bad\x07value']}}
        report = render_report(self.plan, self.state)
        self.assertLess(report.index('Depth 2'), report.index('Depth 1'))
        for required in ['cert', 'schedule', 'consumer before issuer', 'unknown', 'outside', 'failed',
                         '2026-10-10T12:00:00Z', 'retained parent: parent', 'missing',
                         'Preserve this work directory until cleanup is finished.', 'universal']:
            self.assertIn(required, report)
        self.assertNotIn('\x1b', report)
        self.assertNotIn('\r', report)
        self.assertNotIn('\x07', report)


if __name__ == '__main__':
    unittest.main()
