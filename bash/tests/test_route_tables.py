"""Run the route-table scripts against a local OCI CLI stand-in (no network)."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


BASH_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = ("copy_route_table.sh", "preview_route_table.sh")
CONFIG = {
    "SOURCE_RT": "source-rt",
    "DEST_COMPARTMENT": "target-compartment",
    "DEST_VCN": "target-vcn",
    "DEST_NAME": 'target "route" table',
    "OLD_NAT": "old-nat",
    "NEW_NAT": "new-nat",
    "OLD_SGW": "old-sgw",
    "NEW_SGW": "new-sgw",
}
RULES = [
    {"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
     "network-entity-id": "old-nat", "route-type": "STATIC", "description": "egress"},
    {"destination": "all-services", "destination-type": "SERVICE_CIDR_BLOCK",
     "network-entity-id": "old-sgw", "description": None},
    {"cidr-block": "10.1.0.0/16", "network-entity-id": "keep-drg"},
    {"destination": "10.0.0.0/16", "network-entity-id": "local-vcn", "route-type": "LOCAL"},
]
EXPECTED = [
    {"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK",
     "networkEntityId": "new-nat", "description": "egress"},
    {"destination": "all-services", "destinationType": "SERVICE_CIDR_BLOCK",
     "networkEntityId": "new-sgw"},
    {"destination": "10.1.0.0/16", "destinationType": "CIDR_BLOCK",
     "networkEntityId": "keep-drg"},
]
FAKE_OCI = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open("calls.jsonl", "a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args[:3] == ["network", "route-table", "get"]:
    if os.environ.get("GET_FAIL"):
        sys.exit(1)
    print(pathlib.Path("fixture.json").read_text())
elif args[:3] == ["network", "route-table", "create"]:
    path = args[args.index("--route-rules") + 1].removeprefix("file://")
    pathlib.Path("submitted.json").write_text(pathlib.Path(path).read_text())
    if os.environ.get("CREATE_FAIL"):
        sys.exit(1)
    print("created-rt")
else:
    sys.exit(2)
'''


class RouteTableTests(unittest.TestCase):
    def run_script(self, name, rules=None, extra_env=None, raw=None):
        task = tempfile.TemporaryDirectory()
        self.addCleanup(task.cleanup)
        directory = Path(task.name)
        executable = directory / "oci"
        executable.write_text(FAKE_OCI)
        executable.chmod(0o700)
        source = {"data": {"id": "source-rt", "route-rules": RULES if rules is None else rules}}
        (directory / "fixture.json").write_text(json.dumps(source) if raw is None else raw)
        env = {**os.environ, **CONFIG, "PATH": f"{directory}:{os.environ['PATH']}",
               **(extra_env or {})}
        result = subprocess.run(["bash", str(BASH_DIR / name)], cwd=directory,
                                env=env, text=True, capture_output=True)
        calls = directory / "calls.jsonl"
        return result, directory, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    def test_copy_submits_transformed_rules_and_reports_created_id(self):
        result, directory, calls = self.run_script(SCRIPTS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((directory / "submitted.json").read_text()), EXPECTED)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], ["network", "route-table", "get", "--rt-id", "source-rt", "--output", "json"])
        create = calls[1]
        for flag, value in (("--compartment-id", "target-compartment"),
                            ("--vcn-id", "target-vcn"), ("--display-name", CONFIG["DEST_NAME"]),
                            ("--wait-for-state", "AVAILABLE"), ("--query", "data.id")):
            self.assertEqual(create[create.index(flag) + 1], value)
        self.assertIn("--raw-output", create)
        self.assertIn("Created route table: created-rt", result.stdout)

    def test_preview_only_reads_and_saves_source_and_complete_request(self):
        result, directory, calls = self.run_script(SCRIPTS[1])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], "get")
        self.assertFalse((directory / "submitted.json").exists())
        self.assertEqual(json.loads((directory / "source-route-table.json").read_text())["data"]["route-rules"], RULES)
        request = directory / "destination-route-table.json"
        self.assertEqual(json.loads(request.read_text()), {
            "compartmentId": "target-compartment", "vcnId": "target-vcn",
            "displayName": CONFIG["DEST_NAME"], "routeRules": EXPECTED,
        })
        self.assertEqual(request.stat().st_mode & 0o777, 0o600)

    def test_missing_gateway_mapping_stops_before_creation_or_export(self):
        for script in SCRIPTS:
            for gateway in ("old-nat", "old-sgw"):
                with self.subTest(script=script, gateway=gateway):
                    rules = [rule for rule in RULES if rule["network-entity-id"] != gateway]
                    result, directory, calls = self.run_script(script, rules=rules)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("was not found", result.stderr)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse((directory / "destination-route-table.json").exists())

    def test_get_failure_or_invalid_json_never_creates(self):
        for script in SCRIPTS:
            for options in ({"extra_env": {"GET_FAIL": "1"}}, {"raw": "invalid json"}):
                with self.subTest(script=script, options=options):
                    result, directory, calls = self.run_script(script, **options)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse((directory / "submitted.json").exists())

    def test_unconfigured_or_empty_value_stops_before_oci(self):
        for script in SCRIPTS:
            for value in ("REPLACE_ME", ""):
                with self.subTest(script=script, value=value):
                    result, _, calls = self.run_script(script, extra_env={"SOURCE_RT": value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(calls, [])

    def test_failed_create_does_not_report_success(self):
        result, _, _ = self.run_script(SCRIPTS[0], extra_env={"CREATE_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Created route table:", result.stdout)


if __name__ == "__main__":
    unittest.main()
