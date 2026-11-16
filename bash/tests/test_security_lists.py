"""Exercise security-list copying locally without access to OCI."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


BASH_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = ("copy_security_list.sh", "preview_security_list.sh")
CONFIG = {
    "SOURCE_SL": "source-sl",
    "DEST_COMPARTMENT": "target-compartment",
    "DEST_VCN": "target-vcn",
    "DEST_NAME": 'target "security" list',
}
SOURCE = {
    "data": {
        "id": "source-sl",
        "freeform-tags": {"source-only": "not copied"},
        "ingress-security-rules": [
            {"source": "10.0.0.0/16", "source-type": "CIDR_BLOCK", "protocol": "6",
             "is-stateless": False, "description": "web", "icmp-options": None,
             "tcp-options": {"source-port-range": {"min": 1024, "max": 65535},
                             "destination-port-range": {"min": 443, "max": 443}}},
            {"source": "10.0.0.0/16", "source-type": "CIDR_BLOCK", "protocol": "1",
             "is-stateless": True, "icmp-options": {"type": 3, "code": 0}},
        ],
        "egress-security-rules": [
            {"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK", "protocol": "17",
             "is-stateless": False, "description": None,
             "udp-options": {"source-port-range": None,
                             "destination-port-range": {"min": 53, "max": 53}}},
        ],
    }
}
EXPECTED = {
    "compartmentId": "target-compartment", "vcnId": "target-vcn",
    "displayName": 'target "security" list',
    "ingressSecurityRules": [
        {"source": "10.0.0.0/16", "sourceType": "CIDR_BLOCK", "protocol": "6",
         "isStateless": False, "description": "web",
         "tcpOptions": {"sourcePortRange": {"min": 1024, "max": 65535},
                        "destinationPortRange": {"min": 443, "max": 443}}},
        {"source": "10.0.0.0/16", "sourceType": "CIDR_BLOCK", "protocol": "1",
         "isStateless": True, "icmpOptions": {"type": 3, "code": 0}},
    ],
    "egressSecurityRules": [
        {"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "protocol": "17",
         "isStateless": False, "udpOptions": {"destinationPortRange": {"min": 53, "max": 53}}},
    ],
}
FAKE_OCI = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open("calls.jsonl", "a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args[:3] == ["network", "security-list", "get"]:
    if os.environ.get("GET_FAIL"):
        sys.exit(1)
    print(pathlib.Path("fixture.json").read_text())
elif args[:3] == ["network", "security-list", "create"]:
    path = args[args.index("--from-json") + 1].removeprefix("file://")
    pathlib.Path("submitted.json").write_text(pathlib.Path(path).read_text())
    if os.environ.get("CREATE_FAIL"):
        sys.exit(1)
    print("created-sl")
else:
    sys.exit(2)
'''


class SecurityListTests(unittest.TestCase):
    def run_script(self, script, source=SOURCE, extra_env=None, raw=None):
        task = tempfile.TemporaryDirectory()
        self.addCleanup(task.cleanup)
        directory = Path(task.name)
        executable = directory / "oci"
        executable.write_text(FAKE_OCI)
        executable.chmod(0o700)
        (directory / "fixture.json").write_text(json.dumps(source) if raw is None else raw)
        env = {**os.environ, **CONFIG, "PATH": f"{directory}:{os.environ['PATH']}",
               **(extra_env or {})}
        result = subprocess.run(["bash", str(BASH_DIR / script)], cwd=directory,
                                env=env, text=True, capture_output=True)
        calls_path = directory / "calls.jsonl"
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        return result, directory, calls

    def test_copy_preserves_nested_rules_false_and_zero(self):
        result, directory, calls = self.run_script(SCRIPTS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((directory / "submitted.json").read_text()), EXPECTED)
        self.assertEqual(calls[0], ["network", "security-list", "get",
                                   "--security-list-id", "source-sl", "--output", "json"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][calls[1].index("--wait-for-state") + 1], "AVAILABLE")
        self.assertEqual(calls[1][calls[1].index("--query") + 1], "data.id")
        self.assertIn("--raw-output", calls[1])
        self.assertIn("Created security list: created-sl", result.stdout)

    def test_preview_exports_complete_request_without_creation(self):
        result, directory, calls = self.run_script(SCRIPTS[1])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], "get")
        for filename, expected in (("source-security-list.json", SOURCE),
                                   ("destination-security-list.json", EXPECTED)):
            path = directory / filename
            self.assertEqual(json.loads(path.read_text()), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse((directory / "submitted.json").exists())
        self.assertIn('"ingress": 2', result.stdout)
        self.assertIn('"egress": 1', result.stdout)

    def test_empty_rule_arrays_are_preserved(self):
        source = {"data": {"ingress-security-rules": [], "egress-security-rules": []}}
        for script in SCRIPTS:
            with self.subTest(script=script):
                result, directory, _ = self.run_script(script, source=source)
                self.assertEqual(result.returncode, 0, result.stderr)
                filename = "submitted.json" if script == SCRIPTS[0] else "destination-security-list.json"
                request = json.loads((directory / filename).read_text())
                self.assertEqual(request["ingressSecurityRules"], [])
                self.assertEqual(request["egressSecurityRules"], [])

    def test_failed_reads_or_malformed_rules_never_create_or_export(self):
        for script in SCRIPTS:
            for options in ({"extra_env": {"GET_FAIL": "1"}}, {"raw": "invalid json"},
                            {"source": {"data": {}}},
                            {"source": {"data": {"ingress-security-rules": {}, "egress-security-rules": []}}}):
                with self.subTest(script=script, options=options):
                    result, directory, calls = self.run_script(script, **options)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse((directory / "submitted.json").exists())
                    self.assertFalse((directory / "destination-security-list.json").exists())

    def test_empty_or_unconfigured_values_stop_before_oci(self):
        for script in SCRIPTS:
            for variable in CONFIG:
                for value in ("", "REPLACE_ME"):
                    with self.subTest(script=script, variable=variable, value=value):
                        result, _, calls = self.run_script(script, extra_env={variable: value})
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(calls, [])

    def test_failed_create_does_not_report_success(self):
        result, _, calls = self.run_script(SCRIPTS[0], extra_env={"CREATE_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("Created security list:", result.stdout)


if __name__ == "__main__":
    unittest.main()
