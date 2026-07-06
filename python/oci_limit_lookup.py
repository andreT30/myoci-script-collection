#!/usr/bin/env python3
"""
Interactive OCI service-limit lookup.

This helper shells out to the OCI CLI and combines:
  - oci limits service list
  - oci limits definition list
  - oci limits value list
  - oci limits resource-availability get

It reports the configured limit value, current usage, and available capacity
where the OCI Limits API supports resource availability for that limit.
"""

import argparse
import csv
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


OUTPUT_FORMATS = ("table", "csv", "json")
SCOPE_TYPES = ("AD", "GLOBAL", "REGION")


class OciCommandError(RuntimeError):
    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str, stderr: str) -> None:
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Command failed ({returncode}): {shlex.join(cmd)}\n"
            f"STDOUT:\n{stdout}\n"
            f"STDERR:\n{stderr}"
        )


def run_cmd(cmd: List[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise OciCommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc.stdout


def get_any(data: Dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def extract_items(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data", [])
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items = data.get("items", [])
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return [data]
    return []


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def prompt_value(label: str, default: Optional[str] = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("Value is required.")


def prompt_choice(label: str, choices: Sequence[str], default: str) -> str:
    allowed = {choice.lower(): choice for choice in choices}
    while True:
        value = prompt_value(label, default=default).lower()
        if value in allowed:
            return allowed[value]
        print(f"Choose one of: {', '.join(choices)}")


def service_label(service: Dict[str, Any]) -> str:
    name = item_name(service)
    description = item_description(service)
    if description and description.lower() != name.lower():
        return f"{name} - {description}"
    return name


def print_service_choices(services: Sequence[Dict[str, Any]], total_count: int, limit: int = 40) -> None:
    shown = services[:limit]
    for idx, service in enumerate(shown, start=1):
        print(f"{idx:3d}) {service_label(service)}")
    if len(services) > limit:
        print(f"... showing {limit} of {len(services)} matches. Type more search text to narrow.")
    if len(services) != total_count:
        print(f"Filtered to {len(services)} of {total_count} services.")


def prompt_service_selection(compartment_id: str, args: argparse.Namespace) -> str:
    print("\nLoading OCI limit services...")
    services = sorted(
        list_services(compartment_id, args),
        key=lambda service: (item_description(service).lower(), item_name(service).lower()),
    )
    services = [service for service in services if item_name(service)]
    if not services:
        return prompt_value("Service name (blank searches all definitions)")

    filtered = services
    print("\nChoose a service, or press Enter to search across all service definitions.")
    while True:
        print_service_choices(filtered, len(services))
        value = input("Service number/name/search text (blank=all, *=reset): ").strip()
        if not value:
            return ""
        if value == "*":
            filtered = services
            continue

        if value.isdigit():
            selected = int(value)
            if 1 <= selected <= min(len(filtered), 40):
                return item_name(filtered[selected - 1])
            print("Choose one of the displayed numbers.")
            continue

        exact = next((service for service in services if item_name(service).lower() == value.lower()), None)
        if exact:
            return item_name(exact)

        terms = value.lower().split()
        matches = [
            service
            for service in services
            if all(term in service_label(service).lower() for term in terms)
        ]
        if not matches:
            print("No matching services. Try another search or press Enter for all.")
            continue
        filtered = matches


def add_global_options(cmd: List[str], args: argparse.Namespace) -> List[str]:
    if args.region:
        cmd.extend(["--region", args.region])
    if args.profile:
        cmd.extend(["--profile", args.profile])
    if args.config_file:
        cmd.extend(["--config-file", args.config_file])
    if args.auth:
        cmd.extend(["--auth", args.auth])
    return cmd


def run_oci(oci_args: List[str], args: argparse.Namespace) -> Dict[str, Any]:
    cmd = ["oci"]
    cmd.extend(oci_args)
    cmd.extend(["--output", "json"])
    add_global_options(cmd, args)
    return json.loads(run_cmd(cmd))


def list_services(compartment_id: str, args: argparse.Namespace) -> List[Dict[str, Any]]:
    cmd = ["limits", "service", "list", "--compartment-id", compartment_id, "--all"]
    if args.subscription_id:
        cmd.extend(["--subscription-id", args.subscription_id])
    return extract_items(run_oci(cmd, args))


def list_limit_definitions(
    compartment_id: str,
    args: argparse.Namespace,
    service_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    cmd = ["limits", "definition", "list", "--compartment-id", compartment_id, "--all"]
    if service_name:
        cmd.extend(["--service-name", service_name])
    if args.subscription_id:
        cmd.extend(["--subscription-id", args.subscription_id])
    return extract_items(run_oci(cmd, args))


def list_limit_values(
    compartment_id: str,
    service_name: str,
    args: argparse.Namespace,
) -> List[Dict[str, Any]]:
    cmd = [
        "limits",
        "value",
        "list",
        "--compartment-id",
        compartment_id,
        "--service-name",
        service_name,
        "--all",
    ]
    if args.availability_domain:
        cmd.extend(["--availability-domain", args.availability_domain])
    if args.external_location:
        cmd.extend(["--external-location", args.external_location])
    if args.scope_type:
        cmd.extend(["--scope-type", args.scope_type])
    if args.subscription_id:
        cmd.extend(["--subscription-id", args.subscription_id])
    return extract_items(run_oci(cmd, args))


def get_resource_availability(
    compartment_id: str,
    service_name: str,
    limit_name: str,
    availability_domain: Optional[str],
    args: argparse.Namespace,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    cmd = [
        "oci",
        "limits",
        "resource-availability",
        "get",
        "--compartment-id",
        compartment_id,
        "--service-name",
        service_name,
        "--limit-name",
        limit_name,
        "--output",
        "json",
    ]
    if availability_domain:
        cmd.extend(["--availability-domain", availability_domain])
    if args.external_location:
        cmd.extend(["--external-location", args.external_location])
    if args.subscription_id:
        cmd.extend(["--subscription-id", args.subscription_id])
    add_global_options(cmd, args)

    try:
        payload = json.loads(run_cmd(cmd))
    except OciCommandError as exc:
        stderr = exc.stderr.lower()
        if exc.returncode == 404 or "notauthorizedornotfound" in stderr or "not found" in stderr:
            return None, "not available"
        if exc.returncode == 400 or "invalidparameter" in stderr:
            return None, "invalid scope"
        return None, f"error: {short_error(exc.stderr)}"

    data = payload.get("data")
    if isinstance(data, dict):
        return data, None
    return payload, None


def short_error(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if not lines:
        return "unknown"
    return lines[-1][:140]


def item_name(item: Dict[str, Any]) -> str:
    return normalize_text(get_any(item, ("name", "limit-name", "limitName")))


def item_description(item: Dict[str, Any]) -> str:
    return normalize_text(get_any(item, ("description", "display-name", "displayName")))


def item_service_name(item: Dict[str, Any]) -> str:
    return normalize_text(get_any(item, ("service-name", "serviceName", "service")))


def item_scope_type(item: Dict[str, Any]) -> str:
    return normalize_text(get_any(item, ("scope-type", "scopeType")))


def parse_limit_queries(values: Optional[Iterable[str]]) -> List[str]:
    queries: List[str] = []
    for value in values or []:
        for part in value.split(","):
            query = part.strip()
            if query and query not in queries:
                queries.append(query)
    return queries


def matches_limit(item: Dict[str, Any], query: str) -> bool:
    query_lc = query.lower()
    return query_lc in item_name(item).lower() or query_lc in item_description(item).lower()


def matching_limit_query(item: Dict[str, Any], queries: Sequence[str]) -> Optional[str]:
    for query in queries:
        if matches_limit(item, query):
            return query
    return None


def index_definitions(definitions: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    indexed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for definition in definitions:
        service = item_service_name(definition)
        name = item_name(definition)
        if service and name:
            indexed[(service, name)] = definition
    return indexed


def find_matching_definitions(
    compartment_id: str,
    args: argparse.Namespace,
    service_name: Optional[str],
    queries: Sequence[str],
) -> List[Dict[str, Any]]:
    definitions = list_limit_definitions(compartment_id, args, service_name=service_name)
    matches = [definition for definition in definitions if matching_limit_query(definition, queries)]
    if service_name:
        for match in matches:
            match.setdefault("service-name", service_name)
    return matches


def unique_service_names(definitions: List[Dict[str, Any]], fallback: Optional[str]) -> List[str]:
    names = sorted({item_service_name(definition) for definition in definitions if item_service_name(definition)})
    if names:
        return names
    return [fallback] if fallback else []


def build_rows(
    compartment_id: str,
    args: argparse.Namespace,
    service_name: Optional[str],
    limit_queries: Sequence[str],
) -> List[Dict[str, Any]]:
    services = list_services(compartment_id, args)
    service_descriptions = {
        item_name(service): item_description(service)
        for service in services
        if item_name(service)
    }

    definitions = find_matching_definitions(compartment_id, args, service_name, limit_queries)
    definition_index = index_definitions(definitions)
    service_names = unique_service_names(definitions, service_name)
    if service_name and service_name not in service_names:
        service_names.append(service_name)

    rows: List[Dict[str, Any]] = []
    seen = set()

    for svc in service_names:
        values = list_limit_values(compartment_id, svc, args)
        matching_values = [
            value
            for value in values
            if matching_limit_query(value, limit_queries)
        ]

        for value in matching_values:
            name = item_name(value)
            matched_query = matching_limit_query(value, limit_queries) or ""
            availability_domain = normalize_text(
                get_any(value, ("availability-domain", "availabilityDomain"))
            )
            scope_type = item_scope_type(value)
            definition = definition_index.get((svc, name), {})
            if not definition and definitions:
                definition = next(
                    (
                        candidate
                        for candidate in definitions
                        if item_name(candidate) == name and (item_service_name(candidate) in ("", svc))
                    ),
                    {},
                )
            if not scope_type:
                scope_type = item_scope_type(definition)
            if not availability_domain:
                availability_domain = args.availability_domain or ""

            row_key = (svc, name, availability_domain, scope_type)
            if row_key in seen:
                continue
            seen.add(row_key)

            availability, availability_error = get_resource_availability(
                compartment_id,
                svc,
                name,
                availability_domain or None,
                args,
            )

            row = {
                "region": args.region or "",
                "compartment_id": compartment_id,
                "service_name": svc,
                "service_description": service_descriptions.get(svc, ""),
                "matched_query": matched_query,
                "limit_name": name,
                "limit_description": item_description(definition) or item_description(value),
                "scope_type": scope_type,
                "availability_domain": availability_domain,
                "limit_value": get_any(value, ("value", "limit-value", "limitValue"), ""),
                "used": "",
                "available": "",
                "fractional_usage": "",
                "fractional_availability": "",
                "effective_quota_value": "",
                "availability_status": availability_error or "ok",
            }

            if availability:
                row.update(
                    {
                        "used": get_any(availability, ("used",), ""),
                        "available": get_any(availability, ("available",), ""),
                        "fractional_usage": get_any(
                            availability,
                            ("fractional-usage", "fractionalUsage", "fractional_usage"),
                            "",
                        ),
                        "fractional_availability": get_any(
                            availability,
                            (
                                "fractional-availability",
                                "fractionalAvailability",
                                "fractional_availability",
                            ),
                            "",
                        ),
                        "effective_quota_value": get_any(
                            availability,
                            (
                                "effective-quota-value",
                                "effectiveQuotaValue",
                                "effective_quota_value",
                            ),
                            "",
                        ),
                    }
                )

            rows.append(row)

    if rows or service_name:
        return rows

    return scan_services_for_values(compartment_id, args, services, limit_queries)


def scan_services_for_values(
    compartment_id: str,
    args: argparse.Namespace,
    services: List[Dict[str, Any]],
    limit_queries: Sequence[str],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for service in services:
        svc = item_name(service)
        if not svc:
            continue
        try:
            values = list_limit_values(compartment_id, svc, args)
        except OciCommandError:
            continue
        for value in values:
            matched_query = matching_limit_query(value, limit_queries)
            if not matched_query:
                continue
            availability_domain = normalize_text(
                get_any(value, ("availability-domain", "availabilityDomain"))
            ) or args.availability_domain
            availability, availability_error = get_resource_availability(
                compartment_id,
                svc,
                item_name(value),
                availability_domain or None,
                args,
            )
            row = {
                "region": args.region or "",
                "compartment_id": compartment_id,
                "service_name": svc,
                "service_description": item_description(service),
                "matched_query": matched_query,
                "limit_name": item_name(value),
                "limit_description": item_description(value),
                "scope_type": item_scope_type(value),
                "availability_domain": availability_domain or "",
                "limit_value": get_any(value, ("value", "limit-value", "limitValue"), ""),
                "used": get_any(availability or {}, ("used",), ""),
                "available": get_any(availability or {}, ("available",), ""),
                "fractional_usage": get_any(
                    availability or {}, ("fractional-usage", "fractionalUsage", "fractional_usage"), ""
                ),
                "fractional_availability": get_any(
                    availability or {},
                    ("fractional-availability", "fractionalAvailability", "fractional_availability"),
                    "",
                ),
                "effective_quota_value": get_any(
                    availability or {},
                    ("effective-quota-value", "effectiveQuotaValue", "effective_quota_value"),
                    "",
                ),
                "availability_status": availability_error or "ok",
            }
            rows.append(row)
    return rows


def print_table(rows: List[Dict[str, Any]], columns: Sequence[str]) -> None:
    if not rows:
        print("No matching limits found.")
        return

    display_columns = [
        "matched_query",
        "service_name",
        "limit_name",
        "scope_type",
        "availability_domain",
        "limit_value",
        "used",
        "available",
        "effective_quota_value",
        "availability_status",
        "limit_description",
    ]
    selected = [column for column in display_columns if column in columns]
    widths = {
        column: max(
            len(column),
            *(len(str(row.get(column, ""))) for row in rows),
        )
        for column in selected
    }
    header = " | ".join(column.ljust(widths[column]) for column in selected)
    rule = "-+-".join("-" * widths[column] for column in selected)
    print(header)
    print(rule)
    for row in rows:
        print(" | ".join(str(row.get(column, "")).ljust(widths[column]) for column in selected))


def print_csv(rows: List[Dict[str, Any]], columns: Sequence[str], stream: Any) -> None:
    writer = csv.DictWriter(stream, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)


def output_file_path(path: str) -> Path:
    output_path = Path(path).expanduser()
    if output_path.parent and str(output_path.parent) != ".":
        output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def emit_output(rows: List[Dict[str, Any]], args: argparse.Namespace) -> None:
    columns = [
        "region",
        "compartment_id",
        "service_name",
        "service_description",
        "matched_query",
        "limit_name",
        "limit_description",
        "scope_type",
        "availability_domain",
        "limit_value",
        "used",
        "available",
        "fractional_usage",
        "fractional_availability",
        "effective_quota_value",
        "availability_status",
    ]

    if args.output_file:
        path = output_file_path(args.output_file)
        if args.output_format == "json":
            with path.open("w", encoding="utf-8") as stream:
                json.dump(rows, stream, indent=2)
                stream.write("\n")
        elif args.output_format == "csv":
            with path.open("w", encoding="utf-8", newline="") as stream:
                print_csv(rows, columns, stream)
        else:
            with path.open("w", encoding="utf-8") as stream:
                old_stdout = sys.stdout
                try:
                    sys.stdout = stream
                    print_table(rows, columns)
                finally:
                    sys.stdout = old_stdout
        print(f"Wrote {len(rows)} row(s) to {path}", file=sys.stderr)
        return

    if args.output_format == "json":
        print(json.dumps(rows, indent=2))
    elif args.output_format == "csv":
        print_csv(rows, columns, sys.stdout)
    else:
        print_table(rows, columns)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Look up OCI service limits, usage, and available capacity."
    )
    parser.add_argument("-c", "--compartment-id", help="Tenancy/root compartment OCID or compartment OCID.")
    parser.add_argument("--service-name", help="OCI Limits service name, for example: compute.")
    parser.add_argument(
        "--limit-name",
        action="append",
        help=(
            "Limit name or search text. Repeat the option or pass comma-separated values, "
            "for example: --limit-name standard-e6-core-count --limit-name standard-e6-memory-count."
        ),
    )
    parser.add_argument("--region", help="OCI region to query, for example: eu-frankfurt-1.")
    parser.add_argument("--availability-domain", help="Availability domain for AD-scoped limits.")
    parser.add_argument("--external-location", help="External cloud provider location, where applicable.")
    parser.add_argument("--scope-type", choices=SCOPE_TYPES, help="Filter limit values by scope type.")
    parser.add_argument("--subscription-id", help="Subscription OCID assigned to the tenant.")
    parser.add_argument("-f", "--output-format", choices=OUTPUT_FORMATS, help="Output format.")
    parser.add_argument("--output-file", help="Write output to this file instead of stdout.")
    parser.add_argument("--profile", help="OCI CLI config profile.")
    parser.add_argument("--config-file", help="OCI CLI config file path.")
    parser.add_argument("--auth", help="OCI CLI auth mode, for example: instance_principal or security_token.")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting for missing required inputs.",
    )
    return parser.parse_args(argv)


def fill_interactive_args(args: argparse.Namespace) -> None:
    can_prompt = not args.non_interactive and sys.stdin.isatty()
    if not can_prompt:
        missing = [
            name
            for name, value in (
                ("--compartment-id", args.compartment_id),
                ("--limit-name", parse_limit_queries(args.limit_name)),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required arguments: {', '.join(missing)}")
        if not args.output_format:
            args.output_format = "table"
        return

    if not args.compartment_id:
        args.compartment_id = prompt_value("Tenancy/root compartment OCID", required=True)
    if not args.region:
        args.region = prompt_value("Region (blank uses OCI CLI default)")
    if not args.service_name:
        args.service_name = prompt_service_selection(args.compartment_id, args)
    if not args.limit_name:
        value = prompt_value("Limit names/search text (comma-separated accepted)", required=True)
        args.limit_name = [value]
    if not args.scope_type:
        args.scope_type = prompt_value("Scope type filter AD/GLOBAL/REGION (blank for all)").upper() or None
        if args.scope_type and args.scope_type not in SCOPE_TYPES:
            raise ValueError(f"Invalid scope type: {args.scope_type}")
    if not args.availability_domain:
        args.availability_domain = prompt_value("Availability domain for AD limits (blank if not needed)")
    if not args.output_format:
        args.output_format = prompt_choice("Output format table/csv/json", OUTPUT_FORMATS, "table")
    if args.output_format in ("csv", "json") and not args.output_file:
        args.output_file = prompt_value(
            f"Output {args.output_format.upper()} file path (blank prints to terminal)"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parse_args(argv)
        fill_interactive_args(args)
        limit_queries = parse_limit_queries(args.limit_name)
        if not limit_queries:
            raise ValueError("At least one --limit-name value is required.")
        rows = build_rows(args.compartment_id, args, args.service_name, limit_queries)
        emit_output(rows, args)
        if any(row["availability_status"] != "ok" for row in rows) and args.output_format == "table":
            print(
                "\nNote: OCI does not expose resource availability for every limit; "
                "'not available' means the Limits API returned no usage data for that limit."
            )
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
