#!/usr/bin/env python3
"""Collect an OCI tenancy resource inventory and extract selected tag columns.

The collector uses the OCI CLI Resource Search service in every subscribed
region.  It writes the common resource attributes as CSV columns and preserves
all other Resource Search attributes (including tags) in ``metadata_json``. It
can also extract up to two selected tags into columns during the same run.

Run without arguments for an interactive menu, or use one of these commands:

    python3 oci_tenancy_inventory.py collect
    python3 oci_tenancy_inventory.py extract-tags

Only resource types indexed by OCI Resource Search and visible to the current
identity can be returned.  The OCI CLI must already be installed/configured.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


BASE_COLUMNS = (
    "resource_ocid",
    "compartment_id",
    "resource_type",
    "region",
    "lifecycle_state",
    "metadata_json",
)
TENANCY_OCID_RE = re.compile(r"^ocid1\.tenancy\.[^.]+\.[^.]*\..+$")
COMMON_FIELDS = {
    "identifier",
    "resource-id",
    "resourceId",
    "compartment-id",
    "compartmentId",
    "compartment_id",
    "resource-type",
    "resourceType",
    "resource_type",
    "region",
    "lifecycle-state",
    "lifecycleState",
    "lifecycle_state",
}


class OciCommandError(RuntimeError):
    """An OCI CLI invocation failed."""

    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str, stderr: str) -> None:
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Command failed ({returncode}): {shlex.join(cmd)}\n"
            f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        )


@dataclass(frozen=True)
class TagSelector:
    kind: str
    key: str
    namespace: Optional[str] = None

    @property
    def header(self) -> str:
        if self.kind in ("defined", "system"):
            return f"{self.kind}:{self.namespace}.{self.key}"
        return f"{self.kind}:{self.key}"


def get_any(data: Mapping[str, Any], names: Iterable[str], default: Any = "") -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def prompt_value(label: str, default: Optional[str] = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("Value is required.")


def prompt_tenancy_ocid() -> str:
    while True:
        value = prompt_value("Tenancy OCID", required=True)
        if TENANCY_OCID_RE.match(value):
            return value
        print("Enter a tenancy OCID beginning with 'ocid1.tenancy.'.")


def run_command(cmd: Sequence[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise OciCommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc.stdout


def add_global_options(cmd: List[str], args: argparse.Namespace, region: Optional[str] = None) -> None:
    if region:
        cmd.extend(["--region", region])
    if args.profile:
        cmd.extend(["--profile", args.profile])
    if args.config_file:
        cmd.extend(["--config-file", args.config_file])
    if args.auth:
        cmd.extend(["--auth", args.auth])


def run_oci(
    command: Sequence[str], args: argparse.Namespace, region: Optional[str] = None
) -> Dict[str, Any]:
    cmd = ["oci", *command, "--output", "json"]
    add_global_options(cmd, args, region=region)
    try:
        payload = json.loads(run_command(cmd))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"OCI CLI returned invalid JSON for: {shlex.join(cmd)}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"OCI CLI returned an unexpected JSON value for: {shlex.join(cmd)}")
    return payload


def extract_items(payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data", [])
    if isinstance(data, dict):
        data = data.get("items", [])
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def list_region_subscriptions(
    tenancy_id: str, args: argparse.Namespace
) -> List[Dict[str, Any]]:
    payload = run_oci(
        ["iam", "region-subscription", "list", "--tenancy-id", tenancy_id, "--all"],
        args,
        region=args.bootstrap_region,
    )
    subscriptions = extract_items(payload)
    subscriptions.sort(
        key=lambda item: (
            not bool(get_any(item, ("is-home-region", "isHomeRegion"), False)),
            str(get_any(item, ("region-name", "regionName"))).lower(),
        )
    )
    return subscriptions


def subscription_region(subscription: Mapping[str, Any]) -> str:
    return str(get_any(subscription, ("region-name", "regionName"))).strip()


def region_key_map(subscriptions: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for subscription in subscriptions:
        name = subscription_region(subscription)
        key = str(get_any(subscription, ("region-key", "regionKey"))).strip()
        if name:
            result[name.lower()] = name
        if name and key:
            result[key.lower()] = name
    return result


def search_region(
    tenancy_id: str, region: str, args: argparse.Namespace
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    page: Optional[str] = None
    while True:
        command = [
            "search",
            "resource",
            "structured-search",
            "--tenant-id",
            tenancy_id,
            "--query-text",
            "query all resources",
            "--limit",
            "1000",
        ]
        if page:
            command.extend(["--page", page])
        payload = run_oci(command, args, region=region)
        items.extend(extract_items(payload))
        next_page = get_any(payload, ("opc-next-page", "opcNextPage"), None)
        page = str(next_page).strip() if next_page else None
        if not page:
            return items


def ocid_region(resource_ocid: str, known_regions: Mapping[str, str]) -> str:
    parts = resource_ocid.split(".")
    if len(parts) < 5 or parts[0] != "ocid1":
        return ""
    encoded_region = parts[3].strip()
    if not encoded_region:
        return "GLOBAL"
    return known_regions.get(encoded_region.lower(), encoded_region)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def item_to_row(
    item: Mapping[str, Any], search_region: str, known_regions: Mapping[str, str]
) -> Dict[str, str]:
    resource_ocid = str(get_any(item, ("identifier", "resource-id", "resourceId"))).strip()
    metadata = {key: value for key, value in item.items() if key not in COMMON_FIELDS}
    metadata["inventory-search-region"] = search_region
    explicit_region = str(get_any(item, ("region",))).strip()
    return {
        "resource_ocid": resource_ocid,
        "compartment_id": str(
            get_any(item, ("compartment-id", "compartmentId", "compartment_id"))
        ).strip(),
        "resource_type": str(
            get_any(item, ("resource-type", "resourceType", "resource_type"))
        ).strip(),
        "region": explicit_region or ocid_region(resource_ocid, known_regions) or search_region,
        "lifecycle_state": str(
            get_any(item, ("lifecycle-state", "lifecycleState", "lifecycle_state"))
        ).strip(),
        "metadata_json": compact_json(metadata),
    }


def collect_rows(
    tenancy_id: str,
    subscriptions: Sequence[Mapping[str, Any]],
    args: argparse.Namespace,
) -> Tuple[List[Dict[str, str]], int]:
    known_regions = region_key_map(subscriptions)
    by_resource: Dict[Tuple[str, str], Dict[str, str]] = {}
    duplicate_count = 0
    for subscription in subscriptions:
        region = subscription_region(subscription)
        if not region:
            continue
        print(f"Searching {region}...", file=sys.stderr)
        items = search_region(tenancy_id, region, args)
        print(f"  {len(items)} searchable resources returned", file=sys.stderr)
        for item in items:
            row = item_to_row(item, region, known_regions)
            if not row["resource_ocid"]:
                continue
            key = (row["resource_ocid"], row["resource_type"])
            if key in by_resource:
                duplicate_count += 1
                continue
            by_resource[key] = row
    rows = sorted(
        by_resource.values(),
        key=lambda row: (row["region"], row["resource_type"], row["resource_ocid"]),
    )
    return rows, duplicate_count


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_tag_selector(value: str) -> TagSelector:
    value = value.strip()
    if not value:
        raise ValueError("Tag selector cannot be empty.")
    if value.startswith("freeform:"):
        key = value[len("freeform:") :].strip()
        if not key:
            raise ValueError(f"Free-form tag selector has no key: {value!r}")
        return TagSelector("freeform", key)
    if value.startswith("defined:") or value.startswith("system:"):
        kind, qualified_key = value.split(":", 1)
        namespace, separator, key = qualified_key.partition(".")
        if not separator or not namespace.strip() or not key.strip():
            raise ValueError(
                f"{kind.title()} tag selector must be {kind}:NAMESPACE.KEY: {value!r}"
            )
        return TagSelector(kind, key.strip(), namespace.strip())
    raise ValueError(
        f"Unknown tag selector {value!r}; use freeform:KEY, "
        "defined:NAMESPACE.KEY, or system:NAMESPACE.KEY."
    )


def parse_tag_selectors(
    values: Iterable[str], maximum: Optional[int] = None
) -> List[TagSelector]:
    selectors: List[TagSelector] = []
    seen = set()
    for value in values:
        for part in value.split(","):
            selector = parse_tag_selector(part)
            if selector.header not in seen:
                seen.add(selector.header)
                selectors.append(selector)
    if not selectors:
        raise ValueError("At least one tag selector is required.")
    if maximum is not None and len(selectors) > maximum:
        raise ValueError(f"A maximum of {maximum} tag selectors is allowed.")
    return selectors


def metadata_tag_map(metadata: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    names = {
        "freeform": ("freeform-tags", "freeformTags", "freeform_tags"),
        "defined": ("defined-tags", "definedTags", "defined_tags"),
        "system": ("system-tags", "systemTags", "system_tags"),
    }
    value = get_any(metadata, names[kind], {})
    return value if isinstance(value, dict) else {}


def render_tag_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return compact_json(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def extract_tag_value(metadata: Mapping[str, Any], selector: TagSelector) -> str:
    tags = metadata_tag_map(metadata, selector.kind)
    if selector.kind == "freeform":
        return render_tag_value(tags.get(selector.key))
    namespace = tags.get(selector.namespace, {})
    if not isinstance(namespace, dict):
        return ""
    return render_tag_value(namespace.get(selector.key))


def add_tag_columns(
    rows: Iterable[Mapping[str, str]], selectors: Sequence[TagSelector]
) -> List[Dict[str, str]]:
    output_rows: List[Dict[str, str]] = []
    for row in rows:
        output_row = dict(row)
        try:
            metadata = json.loads(output_row.get("metadata_json") or "{}")
        except json.JSONDecodeError as exc:
            resource_ocid = output_row.get("resource_ocid", "unknown resource")
            raise ValueError(f"Invalid metadata_json for {resource_ocid}: {exc}") from exc
        if not isinstance(metadata, dict):
            resource_ocid = output_row.get("resource_ocid", "unknown resource")
            raise ValueError(f"metadata_json for {resource_ocid} is not an object.")
        for selector in selectors:
            output_row[selector.header] = extract_tag_value(metadata, selector)
        output_rows.append(output_row)
    return output_rows


def prompt_optional_tag_selectors(maximum: int = 2) -> List[TagSelector]:
    print("Tag formats: freeform:KEY, defined:NAMESPACE.KEY, system:NAMESPACE.KEY")
    values: List[str] = []
    for number in range(1, maximum + 1):
        value = prompt_value(f"Tag {number} to extract (blank to finish)")
        if not value:
            break
        values.append(value)
    return parse_tag_selectors(values, maximum=maximum) if values else []


def recreate_with_tags(
    source: Path,
    destination: Path,
    selectors: Sequence[TagSelector],
    keep_metadata: bool,
) -> int:
    rows: List[Dict[str, str]] = []
    with source.expanduser().open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "metadata_json" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a metadata_json column.")
        missing = [column for column in BASE_COLUMNS if column not in reader.fieldnames]
        if missing:
            raise ValueError(f"Input CSV is missing columns: {', '.join(missing)}")
        for line_number, row in enumerate(reader, start=2):
            try:
                metadata = json.loads(row.get("metadata_json") or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid metadata_json on CSV line {line_number}: {exc}") from exc
            if not isinstance(metadata, dict):
                raise ValueError(f"metadata_json on CSV line {line_number} is not an object.")
            output_row = {column: row.get(column, "") for column in BASE_COLUMNS}
            for selector in selectors:
                output_row[selector.header] = extract_tag_value(metadata, selector)
            if not keep_metadata:
                output_row.pop("metadata_json", None)
            rows.append(output_row)

    fieldnames = [column for column in BASE_COLUMNS if keep_metadata or column != "metadata_json"]
    fieldnames.extend(selector.header for selector in selectors)
    write_csv(destination, fieldnames, rows)
    return len(rows)


def add_oci_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="OCI CLI configuration profile")
    parser.add_argument("--config-file", help="OCI CLI configuration file")
    parser.add_argument("--auth", help="OCI CLI auth mode, such as instance_principal")
    parser.add_argument(
        "--bootstrap-region",
        help="Region used only to obtain the tenancy's subscribed-region list",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser(
        "collect", help="Collect all searchable tenancy resources into CSV"
    )
    collect.add_argument(
        "--tenancy-id", help="Tenancy OCID; omitted by default so it is prompted"
    )
    collect.add_argument("-o", "--output", help="Output CSV path")
    collect.add_argument(
        "--tag",
        action="append",
        help=(
            "Tag to extract into the collected CSV (maximum 2); repeat or comma-separate. "
            "Formats: freeform:KEY, defined:NAMESPACE.KEY, system:NAMESPACE.KEY"
        ),
    )
    add_oci_options(collect)

    extract = subparsers.add_parser(
        "extract-tags", help="Recreate an inventory CSV with selected tag columns"
    )
    extract.add_argument("-i", "--input", help="Inventory CSV created by collect")
    extract.add_argument("-o", "--output", help="Output CSV path")
    extract.add_argument(
        "--tag",
        action="append",
        help=(
            "Tag selector; repeat or comma-separate values. Formats: "
            "freeform:KEY, defined:NAMESPACE.KEY, system:NAMESPACE.KEY"
        ),
    )
    extract.add_argument(
        "--drop-metadata",
        action="store_true",
        help="Omit metadata_json from the recreated CSV",
    )
    return parser


def interactive_command() -> List[str]:
    print("OCI tenancy inventory")
    print("  1) Collect resources from OCI")
    print("  2) Recreate a CSV with selected tag columns")
    while True:
        choice = prompt_value("Choose an action", default="1")
        if choice == "1":
            return ["collect"]
        if choice == "2":
            return ["extract-tags"]
        print("Choose 1 or 2.")


def collect_command(args: argparse.Namespace) -> int:
    if shutil.which("oci") is None:
        raise RuntimeError("The OCI CLI executable 'oci' was not found in PATH.")
    tenancy_id = args.tenancy_id or prompt_tenancy_ocid()
    if not TENANCY_OCID_RE.match(tenancy_id):
        raise ValueError("--tenancy-id must be a tenancy OCID beginning with 'ocid1.tenancy.'.")
    output = Path(args.output or prompt_value("Output CSV", "oci_tenancy_inventory.csv"))
    selectors = (
        parse_tag_selectors(args.tag, maximum=2)
        if args.tag
        else prompt_optional_tag_selectors(maximum=2)
    )

    print("Loading subscribed OCI regions...", file=sys.stderr)
    subscriptions = list_region_subscriptions(tenancy_id, args)
    regions = [subscription_region(item) for item in subscriptions if subscription_region(item)]
    if not regions:
        raise RuntimeError("No subscribed regions were returned for the tenancy.")
    print(f"Searching {len(regions)} subscribed region(s): {', '.join(regions)}", file=sys.stderr)
    rows, duplicates = collect_rows(tenancy_id, subscriptions, args)
    rows = add_tag_columns(rows, selectors)
    fieldnames = [*BASE_COLUMNS, *(selector.header for selector in selectors)]
    write_csv(output, fieldnames, rows)
    print(
        f"Wrote {len(rows)} resources to {output.expanduser().resolve()} "
        f"with {len(selectors)} extracted tag column(s) "
        f"({duplicates} duplicate regional search results removed)."
    )
    return 0


def extract_command(args: argparse.Namespace) -> int:
    source = Path(args.input or prompt_value("Source inventory CSV", required=True))
    if not source.expanduser().is_file():
        raise ValueError(f"Input CSV does not exist: {source.expanduser()}")
    destination = Path(
        args.output or prompt_value("Output CSV", "oci_tenancy_inventory_with_tags.csv")
    )
    tag_values = args.tag
    if not tag_values:
        print("Tag formats: freeform:KEY, defined:NAMESPACE.KEY, system:NAMESPACE.KEY")
        tag_values = [prompt_value("Tags (comma-separated)", required=True)]
    selectors = parse_tag_selectors(tag_values)
    row_count = recreate_with_tags(
        source, destination, selectors, keep_metadata=not args.drop_metadata
    )
    print(
        f"Wrote {row_count} resources with {len(selectors)} selected tag column(s) "
        f"to {destination.expanduser().resolve()}."
    )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    command_line = list(sys.argv[1:] if argv is None else argv)
    if not command_line:
        command_line = interactive_command()
    args = build_parser().parse_args(command_line)
    try:
        if args.command == "collect":
            return collect_command(args)
        return extract_command(args)
    except (OciCommandError, OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
