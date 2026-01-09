#!/usr/bin/env python3
"""
OCI Bulk Tag Edit helper

Prompts for:
  - compartment OCID
  - tag namespace
  - tag key
  - tag value

Then:
  1) Fetches supported bulk-edit resource types from:
       oci iam tag bulk-edit-tags-resource-type list
     (parses: data.items[]."resource-type", data.items[]."metadata-keys")

  2) Searches resources in the given compartment using:
       oci search resource structured-search --query-text 'query all resources where compartmentId="..."'
     (parses: data.items[]."identifier", data.items[]."resource-type", plus optional metadata sources)

     Pagination: uses opc-next-page + --page/--limit (no --all)

  3) Builds:
       - resources.json: JSON array [{id, resourceType, metadata?}, ...] containing ONLY
         resources whose search "resource-type" matches supported "resource-type".
       - bulkedit.json: JSON array of bulk edit operations based on tag namespace/key/value.

  4) Runs:
       oci iam tag bulk-edit --bulk-edit-operations file://bulkedit.json --resources file://resources.json --compartment-id <ocid>

Notes:
  - This works with the hyphenated-key JSON structures you provided.
  - Many search resource-types may be unsupported and will be excluded (by design).
"""

import json
import os
import shlex
import subprocess
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple


# ------------------------- subprocess helpers -------------------------

def run_cmd(cmd: List[str]) -> str:
    """Run command, return stdout, raise with stderr/stdout on failure."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {shlex.join(cmd)}\n"
            f"STDOUT:\n{p.stdout}\n"
            f"STDERR:\n{p.stderr}\n"
        )
    return p.stdout


def prompt_required(label: str) -> str:
    v = input(label).strip()
    if not v:
        raise ValueError(f"Missing value for: {label}")
    return v


# ------------------------- OCI JSON parsers -------------------------

def get_supported_resource_types() -> Tuple[Set[str], Dict[str, List[str]]]:
    """
    Parse output like:
    {
      "data": {
        "items": [
          {"metadata-keys": [], "resource-type": "KafkaCluster"},
          ...
        ]
      }
    }

    Returns:
      supported_types: set of "resource-type"
      meta_keys_by_type: dict { "resource-type": ["key1", ...] }
    """
    out = run_cmd(["oci", "iam", "tag", "bulk-edit-tags-resource-type", "list", "--output", "json"])
    payload = json.loads(out)

    supported: Set[str] = set()
    meta_keys_by_type: Dict[str, List[str]] = {}

    data = payload.get("data", {})
    items = data.get("items", []) if isinstance(data, dict) else []

    for it in items:
        if not isinstance(it, dict):
            continue
        rtype = it.get("resource-type")
        mkeys = it.get("metadata-keys", [])
        if rtype:
            supported.add(rtype)
            meta_keys_by_type[rtype] = mkeys if isinstance(mkeys, list) else []

    return supported, meta_keys_by_type


def search_resources_in_compartment(compartment_ocid: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """
    Parse output like:
    {
      "data": {
        "items": [
          {"identifier": "...", "resource-type": "ManagementAgent", ...},
          ...
        ]
      },
      "opc-next-page": "..."
    }

    Uses pagination with --page/--limit (no --all).
    """
    query_text = f'query all resources where compartmentId="{compartment_ocid}"'

    all_items: List[Dict[str, Any]] = []
    page: Optional[str] = None

    while True:
        cmd = [
            "oci", "search", "resource", "structured-search",
            "--query-text", query_text,
            "--limit", str(limit),
            "--output", "json"
        ]
        if page:
            cmd.extend(["--page", page])

        out = run_cmd(cmd)
        payload = json.loads(out)

        data = payload.get("data", {})
        items = data.get("items", []) if isinstance(data, dict) else []
        for it in items:
            if isinstance(it, dict):
                all_items.append(it)

        page = payload.get("opc-next-page")
        if not page:
            break

    return all_items


# ------------------------- builders -------------------------

def build_resources_payload(
    search_items: List[Dict[str, Any]],
    supported_types: Set[str],
    meta_keys_by_type: Dict[str, List[str]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Creates resources.json payload:
      [
        {"id": "<identifier>", "resourceType": "<resource-type>", "metadata": {... optional ...}},
        ...
      ]

    Matching rule:
      search item "resource-type" must exactly match a supported "resource-type".

    Metadata:
      Only included when supported list says metadata-keys are required for that type.
      Values are attempted from:
        - item["additional-details"]
        - item["identity-context"]
      Missing required keys are reported.
    """
    kept: List[Dict[str, Any]] = []

    skipped_missing = 0
    skipped_unsupported = 0
    required_md_missing_vals = 0

    # For reporting:
    search_type_counts = Counter()
    kept_type_counts = Counter()

    for it in search_items:
        identifier = it.get("identifier")
        rtype = it.get("resource-type")

        if rtype:
            search_type_counts[rtype] += 1

        if not identifier or not rtype:
            skipped_missing += 1
            continue

        if rtype not in supported_types:
            skipped_unsupported += 1
            continue

        entry: Dict[str, Any] = {"id": identifier, "resourceType": rtype}

        req_keys = meta_keys_by_type.get(rtype, [])
        if req_keys:
            md: Dict[str, Any] = {}
            addl = it.get("additional-details") if isinstance(it.get("additional-details"), dict) else {}
            ident_ctx = it.get("identity-context") if isinstance(it.get("identity-context"), dict) else {}

            for k in req_keys:
                val = None
                if k in addl:
                    val = addl.get(k)
                elif k in ident_ctx:
                    val = ident_ctx.get(k)

                if val is not None:
                    md[k] = val
                else:
                    required_md_missing_vals += 1

            entry["metadata"] = md

        kept.append(entry)
        kept_type_counts[rtype] += 1

    report = {
        "search_total": len(search_items),
        "kept_total": len(kept),
        "skipped_missing_identifier_or_type": skipped_missing,
        "skipped_unsupported_type": skipped_unsupported,
        "required_metadata_values_missing": required_md_missing_vals,
        "distinct_search_types": len(search_type_counts),
        "distinct_kept_types": len(kept_type_counts),
        "top_search_types": search_type_counts.most_common(20),
        "top_kept_types": kept_type_counts.most_common(20),
        "unsupported_types_sample": [
            rt for rt, _ in search_type_counts.most_common(200) if rt not in supported_types
        ][:30],
    }

    return kept, report


def build_bulkedit_operations(tag_namespace: str, tag_key: str, tag_value: str) -> List[Dict[str, Any]]:
    """
    bulkedit.json content for --bulk-edit-operations.
    """
    return [{
        "operationType": "ADD_OR_SET",
        "definedTags": {
            tag_namespace: {
                tag_key: tag_value
            }
        }
    }]


# ------------------------- main -------------------------

def main() -> int:
    try:
        compartment_ocid = prompt_required("Compartment OCID: ")
        tag_namespace = prompt_required("Tag Namespace: ")
        tag_key = prompt_required("Tag Key: ")
        tag_value = prompt_required("Tag Value: ")

        resources_file = "resources.json"
        bulkedit_file = "bulkedit.json"

        print("\nLoading supported bulk-edit resource types...")
        supported, meta_keys_by_type = get_supported_resource_types()
        print(f"Supported resource types: {len(supported)}")
        if not supported:
            raise RuntimeError("Supported resource type list is empty; cannot proceed.")

        print("\nSearching resources in compartment (paginated)...")
        search_items = search_resources_in_compartment(compartment_ocid)
        print(f"Search items returned: {len(search_items)}")

        print("\nMatching search resource-type to supported list and building resources payload...")
        resources_payload, report = build_resources_payload(search_items, supported, meta_keys_by_type)

        # Print a concise report
        print("\nReport:")
        print(f"  Search total items: {report['search_total']}")
        print(f"  Kept (supported) items: {report['kept_total']}")
        print(f"  Skipped missing id/type: {report['skipped_missing_identifier_or_type']}")
        print(f"  Skipped unsupported type: {report['skipped_unsupported_type']}")
        if report["required_metadata_values_missing"]:
            print(f"  Warning: missing required metadata values: {report['required_metadata_values_missing']}")

        print("\nTop resource-types in Search (first 20):")
        for rt, n in report["top_search_types"]:
            status = "OK" if rt in supported else "UNSUPPORTED"
            print(f"  {rt:40} {n:6d}  {status}")

        print("\nTop resource-types kept for bulk-edit (first 20):")
        for rt, n in report["top_kept_types"]:
            print(f"  {rt:40} {n:6d}")

        if not resources_payload:
            print("\nNo resources in this compartment match the supported bulk-edit types.")
            print("Nothing to do.")
            return 0

        bulk_ops = build_bulkedit_operations(tag_namespace, tag_key, tag_value)

        with open(resources_file, "w", encoding="utf-8") as f:
            json.dump(resources_payload, f, indent=2)
        with open(bulkedit_file, "w", encoding="utf-8") as f:
            json.dump(bulk_ops, f, indent=2)

        print(f"\nWrote {resources_file} with {len(resources_payload)} resources.")
        print(f"Wrote {bulkedit_file} with {len(bulk_ops)} operation(s).")

        print("\nSubmitting bulk edit...")
        out = run_cmd([
            "oci", "iam", "tag", "bulk-edit",
            "--bulk-edit-operations", f"file://{os.path.abspath(bulkedit_file)}",
            "--resources", f"file://{os.path.abspath(resources_file)}",
            "--compartment-id", compartment_ocid,
            "--output", "json"
        ])

        resp = json.loads(out)

        work_request_id = (
            resp.get("opc-work-request-id")
            or resp.get("opcWorkRequestId")
            or resp.get("work-request-id")
        )

        print("Bulk tag update request submitted successfully.")

        if work_request_id:
            print(f"Work request OCID: {work_request_id}")

        print("The operation runs asynchronously and may take a few minutes to complete.")
        print("You can verify completion by checking tags on the affected resources.")

        return 0

    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
