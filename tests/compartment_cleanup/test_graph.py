"""Behavior tests for deletion direction and the saved scope boundary."""
import copy
import unittest

try:
    from compartment_cleanup.model import Node, Edge, CleanupError, plan_from_dict, plan_to_dict
    from compartment_cleanup.graph import compute_depths, validate_scope
except ModuleNotFoundError:
    Node = None


def node(key, compartment="parent", action="delete"):
    return Node(key, "Example", "r", compartment, "", "ACTIVE", "example", action, {})


def payload():
    return {"schema_version": 1, "tenancy_id": "tenancy", "parent_id": "parent",
            "home_region": "r", "created_at": "2026-10-08T12:00:00Z",
            "compartments": {"parent": "tenancy", "child": "parent"},
            "nodes": {"parent": {"key": "parent", "resource_type": "Compartment", "region": "r",
                      "compartment_id": "tenancy", "display_name": "", "lifecycle_state": "ACTIVE",
                      "handler": "identity", "action": "retain", "metadata": {}, "blockers": []}},
            "edges": [], "probes": [], "depths": {}, "bulk_types": {}}


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(Node, "versioned model and graph are not implemented")

    def test_seven_levels_are_deleted_deepest_first(self):
        nodes = {str(i): node(str(i)) for i in range(1, 8)}
        depths, blockers = compute_depths(nodes, [Edge(str(i), str(i-1), "dependency") for i in range(2, 8)])
        self.assertEqual(depths, {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7})
        self.assertEqual(blockers, {})

    def test_disconnected_nodes_are_leaves(self):
        self.assertEqual(compute_depths({"a": node("a"), "b": node("b")}, []), ({"a": 1, "b": 1}, {}))

    def test_diamond_uses_longest_successor_path(self):
        nodes = {k: node(k) for k in "abcd"}
        edges = [Edge(a, b, "dependency") for a, b in [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")]]
        self.assertEqual(compute_depths(nodes, edges), ({"a": 3, "b": 2, "c": 2, "d": 1}, {}))

    def test_cycle_blocks_downstream_but_not_independent_branch(self):
        nodes = {k: node(k) for k in "abcd"}
        depths, blockers = compute_depths(nodes, [Edge("a", "b", "ref"), Edge("b", "a", "ref"), Edge("b", "c", "ref")])
        self.assertEqual(depths, {"d": 1})
        self.assertEqual(set(blockers), {"a", "b", "c"})

    def test_dangling_dependency_blocks_existing_endpoint_and_successors(self):
        depths, blockers = compute_depths({"a": node("a"), "b": node("b")}, [Edge("missing", "a", "external"), Edge("a", "b", "ref")])
        self.assertEqual(depths, {})
        self.assertEqual(set(blockers), {"a", "b"})

    def test_unresolved_node_blocks_prerequisite(self):
        depths, blockers = compute_depths({"a": node("a", action="unresolved"), "b": node("b")}, [Edge("a", "b", "ref")])
        self.assertEqual(depths, {})
        self.assertEqual(set(blockers), {"a", "b"})

    def test_iterative_graph_exceeds_recursion_limit(self):
        nodes = {str(i): node(str(i)) for i in range(2000)}
        depths, blockers = compute_depths(nodes, [Edge(str(i), str(i-1), "ref") for i in range(1, 2000)])
        self.assertEqual(depths["1999"], 2000)
        self.assertEqual(blockers, {})

    def test_protected_parent_never_gets_runnable_depth(self):
        depths, blockers = compute_depths({"parent": node("parent", action="retain"), "a": node("a")}, [])
        self.assertEqual(depths, {"a": 1})
        self.assertEqual(blockers, {})

    def test_plan_round_trip_retains_scope_and_tuple_fields(self):
        data = payload()
        data["bulk_types"] = {"Example": ["id", "region"]}
        plan = plan_from_dict(data)
        self.assertEqual(validate_scope(plan, "parent"), {"parent", "child"})
        self.assertEqual(plan.bulk_types["Example"], ("id", "region"))
        self.assertEqual(plan_to_dict(plan), data)

    def test_rejects_schema_and_scope_edits(self):
        changes = [lambda d: d.update(schema_version=2), lambda d: d.update(schema_version=True),
                   lambda d: d.update(surprise=True),
                   lambda d: d["nodes"]["parent"].update(action="delete"),
                   lambda d: d["nodes"]["parent"].update(extra="x"),
                   lambda d: d["compartments"].update(child="external"),
                   lambda d: d["compartments"].update(parent="child"),
                   lambda d: d["nodes"].update(duplicate=copy.deepcopy(d["nodes"]["parent"])),
                   lambda d: d["nodes"]["parent"].update(compartment_id="external"),
                   lambda d: d.update(edges=[{"before": "external", "after": "parent", "evidence": "ref"}]),
                   lambda d: d.update(depths={"parent": -1}),
                   lambda d: d.update(created_at="yesterday")]
        for change in changes:
            with self.subTest(change=change):
                data = payload()
                change(data)
                with self.assertRaises(CleanupError):
                    plan_from_dict(data)

    def test_state_schema_round_trip_and_identity_guard(self):
        from compartment_cleanup import model
        self.assertTrue(hasattr(model, "state_from_dict"), "state serialization is missing")
        data = {"schema_version": 1, "tenancy_id": "tenancy", "parent_id": "parent",
                "records": {"cert": {"status": "pending", "scheduled_at": "2026-10-10T12:00:00Z", "attempts": []}}}
        self.assertEqual(model.state_to_dict(model.state_from_dict(data)), data)
        for change in [lambda d: d.update(schema_version=2), lambda d: d.update(extra=True),
                       lambda d: d.update(records=[]), lambda d: d["records"].update(cert="invalid"),
                       lambda d: d.update(parent_id="tenancy")]:
            invalid = copy.deepcopy(data)
            change(invalid)
            with self.assertRaises(CleanupError):
                model.state_from_dict(invalid)

    def test_child_key_distinguishes_same_named_objects_and_versions(self):
        from compartment_cleanup import model
        self.assertTrue(hasattr(model, "child_key"), "deterministic child identity is missing")
        key = model.child_key("object", "r", "bucket", "name", "version")
        self.assertEqual(key, model.child_key("object", "r", "bucket", "name", "version"))
        self.assertNotEqual(key, model.child_key("object", "r", "other", "name", "version"))
        self.assertNotEqual(key, model.child_key("object", "r", "bucket", "name", "other"))
        self.assertNotEqual(model.child_key("a", "b", "c", "d:e", "f"),
                            model.child_key("a", "b", "c", "d", "e:f"))
        self.assertEqual(len(key.removeprefix("sha256:")), 64)

    def test_nested_retained_parent_has_external_owner(self):
        data = payload()
        data["compartments"]["parent"] = "external_owner"
        data["nodes"]["parent"]["compartment_id"] = "external_owner"
        self.assertEqual(validate_scope(plan_from_dict(data), "parent"), {"parent", "child"})

    def test_supplied_parent_must_match_saved_scope(self):
        with self.assertRaises(CleanupError):
            validate_scope(plan_from_dict(payload()), "other")


if __name__ == "__main__":
    unittest.main()
