import csv
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "python" / "oci_tenancy_inventory.py"
SPEC = importlib.util.spec_from_file_location("oci_tenancy_inventory", SCRIPT)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_ocid_region_maps_region_keys_and_global_resources(self):
        known = {"fra": "eu-frankfurt-1"}
        self.assertEqual(
            inventory.ocid_region("ocid1.instance.oc1.fra.example", known),
            "eu-frankfurt-1",
        )
        self.assertEqual(
            inventory.ocid_region("ocid1.compartment.oc1..example", known), "GLOBAL"
        )

    def test_item_to_row_preserves_non_base_fields_as_metadata(self):
        item = {
            "identifier": "ocid1.instance.oc1.fra.example",
            "compartment-id": "ocid1.compartment.oc1..example",
            "resource-type": "Instance",
            "lifecycle-state": "RUNNING",
            "display-name": "web-1",
            "freeform-tags": {"Owner": "Team A"},
            "defined-tags": {"Operations": {"CostCenter": "42"}},
        }

        row = inventory.item_to_row(item, "eu-frankfurt-1", {"fra": "eu-frankfurt-1"})
        metadata = json.loads(row["metadata_json"])

        self.assertEqual(row["resource_ocid"], item["identifier"])
        self.assertEqual(row["region"], "eu-frankfurt-1")
        self.assertEqual(row["lifecycle_state"], "RUNNING")
        self.assertEqual(metadata["display-name"], "web-1")
        self.assertEqual(metadata["freeform-tags"]["Owner"], "Team A")
        self.assertEqual(metadata["inventory-search-region"], "eu-frankfurt-1")
        self.assertNotIn("identifier", metadata)

    def test_search_region_follows_pagination(self):
        args = types.SimpleNamespace(profile=None, config_file=None, auth=None)
        responses = [
            {"data": {"items": [{"identifier": "one"}]}, "opc-next-page": "next"},
            {"data": {"items": [{"identifier": "two"}]}},
        ]

        with mock.patch.object(inventory, "run_oci", side_effect=responses) as run_oci:
            items = inventory.search_region("ocid1.tenancy.oc1..example", "uk-london-1", args)

        self.assertEqual([item["identifier"] for item in items], ["one", "two"])
        self.assertEqual(run_oci.call_count, 2)
        second_command = run_oci.call_args_list[1].args[0]
        self.assertEqual(second_command[-2:], ["--page", "next"])

    def test_parse_tag_selectors_supports_all_tag_types_and_deduplicates(self):
        selectors = inventory.parse_tag_selectors(
            [
                "freeform:Owner,defined:Operations.CostCenter",
                "system:orcl-cloud.free-tier-retain",
                "freeform:Owner",
            ]
        )
        self.assertEqual(
            [selector.header for selector in selectors],
            [
                "freeform:Owner",
                "defined:Operations.CostCenter",
                "system:orcl-cloud.free-tier-retain",
            ],
        )

    def test_collect_tag_selection_is_limited_to_two_unique_tags(self):
        with self.assertRaisesRegex(ValueError, "maximum of 2"):
            inventory.parse_tag_selectors(
                [
                    "freeform:Owner",
                    "defined:Operations.CostCenter",
                    "freeform:Environment",
                ],
                maximum=2,
            )

    def test_add_tag_columns_keeps_metadata_and_extracts_two_tags(self):
        metadata = {
            "freeform-tags": {"Owner": "Team A"},
            "defined-tags": {"Operations": {"CostCenter": "42"}},
        }
        row = {
            "resource_ocid": "ocid1.instance.oc1.fra.example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "resource_type": "Instance",
            "region": "eu-frankfurt-1",
            "lifecycle_state": "RUNNING",
            "metadata_json": json.dumps(metadata),
        }
        selectors = inventory.parse_tag_selectors(
            ["freeform:Owner", "defined:Operations.CostCenter"], maximum=2
        )

        output = inventory.add_tag_columns([row], selectors)

        self.assertEqual(output[0]["metadata_json"], row["metadata_json"])
        self.assertEqual(output[0]["freeform:Owner"], "Team A")
        self.assertEqual(output[0]["defined:Operations.CostCenter"], "42")

    def test_collect_command_writes_metadata_and_tag_columns_together(self):
        args = types.SimpleNamespace(
            tenancy_id="ocid1.tenancy.oc1..example",
            output="inventory.csv",
            tag=["freeform:Owner", "defined:Operations.CostCenter"],
            profile=None,
            config_file=None,
            auth=None,
            bootstrap_region=None,
        )
        row = {
            "resource_ocid": "ocid1.instance.oc1.fra.example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "resource_type": "Instance",
            "region": "eu-frankfurt-1",
            "lifecycle_state": "RUNNING",
            "metadata_json": json.dumps(
                {
                    "freeform-tags": {"Owner": "Team A"},
                    "defined-tags": {"Operations": {"CostCenter": "42"}},
                }
            ),
        }
        subscriptions = [{"region-name": "eu-frankfurt-1", "region-key": "FRA"}]

        with (
            mock.patch.object(inventory.shutil, "which", return_value="/usr/bin/oci"),
            mock.patch.object(
                inventory, "list_region_subscriptions", return_value=subscriptions
            ),
            mock.patch.object(inventory, "collect_rows", return_value=([row], 0)),
            mock.patch.object(inventory, "write_csv") as write_csv,
        ):
            result = inventory.collect_command(args)

        self.assertEqual(result, 0)
        written_rows = write_csv.call_args.args[2]
        self.assertEqual(
            write_csv.call_args.args[1],
            [
                *inventory.BASE_COLUMNS,
                "freeform:Owner",
                "defined:Operations.CostCenter",
            ],
        )
        self.assertEqual(written_rows[0]["metadata_json"], row["metadata_json"])
        self.assertEqual(written_rows[0]["freeform:Owner"], "Team A")
        self.assertEqual(written_rows[0]["defined:Operations.CostCenter"], "42")

    def test_recreate_with_tags_adds_selected_columns(self):
        metadata = {
            "freeform-tags": {"Owner": "Team A"},
            "defined-tags": {"Operations": {"CostCenter": 42}},
            "system-tags": {"orcl-cloud": {"free-tier-retain": True}},
        }
        row = {
            "resource_ocid": "ocid1.instance.oc1.fra.example",
            "compartment_id": "ocid1.compartment.oc1..example",
            "resource_type": "Instance",
            "region": "eu-frankfurt-1",
            "lifecycle_state": "RUNNING",
            "metadata_json": json.dumps(metadata),
        }
        selectors = inventory.parse_tag_selectors(
            [
                "freeform:Owner",
                "defined:Operations.CostCenter",
                "system:orcl-cloud.free-tier-retain",
                "freeform:Missing",
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.csv"
            destination = Path(directory) / "destination.csv"
            inventory.write_csv(source, inventory.BASE_COLUMNS, [row])

            count = inventory.recreate_with_tags(
                source, destination, selectors, keep_metadata=False
            )

            with destination.open(newline="", encoding="utf-8") as handle:
                output = list(csv.DictReader(handle))

        self.assertEqual(count, 1)
        self.assertNotIn("metadata_json", output[0])
        self.assertEqual(output[0]["freeform:Owner"], "Team A")
        self.assertEqual(output[0]["defined:Operations.CostCenter"], "42")
        self.assertEqual(output[0]["system:orcl-cloud.free-tier-retain"], "true")
        self.assertEqual(output[0]["freeform:Missing"], "")


if __name__ == "__main__":
    unittest.main()
