"""Versioned, strictly typed local cleanup artifacts (never SDK instructions)."""
from dataclasses import asdict, dataclass, fields
from datetime import datetime
import hashlib
import json
import math

SCHEMA_VERSION = 1
ACTIONS = frozenset({"retain", "delete", "schedule", "prepare", "cascade", "unresolved"})


class CleanupError(RuntimeError):
    """An invalid artifact, unsafe scope, or cleanup operation."""


@dataclass(frozen=True)
class Node:
    key: str
    resource_type: str
    region: str
    compartment_id: str
    display_name: str
    lifecycle_state: str
    handler: str
    action: str
    metadata: dict
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Edge:
    before: str
    after: str
    evidence: str


@dataclass(frozen=True)
class Probe:
    service: str
    region: str
    compartment_id: str
    status: str
    detail: str


@dataclass
class Plan:
    schema_version: int
    tenancy_id: str
    parent_id: str
    home_region: str
    created_at: str
    compartments: dict[str, str]
    nodes: dict[str, Node]
    edges: list[Edge]
    probes: list[Probe]
    depths: dict[str, int]
    bulk_types: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Observation:
    status: str
    compartment_id: str
    lifecycle_state: str
    scheduled_at: str | None
    etag: str | None
    detail: str


@dataclass(frozen=True)
class Submission:
    status: str
    request_id: str | None
    scheduled_at: str | None
    detail: str
    operation_evidence: dict | None = None


@dataclass
class State:
    schema_version: int
    tenancy_id: str
    parent_id: str
    records: dict[str, dict]


def _object(data, allowed, label, optional=()):
    if type(data) is not dict or set(data) - set(allowed) or set(allowed) - set(optional) - set(data):
        raise CleanupError(f"Invalid {label} fields")


def _text(value, label, empty=False):
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise CleanupError(f"Invalid {label}: expected string")
    return value


def _strings(value, label):
    if type(value) is not list:
        raise CleanupError(f"Invalid {label}: expected list")
    return tuple(_text(item, label) for item in value)


def _json_value(value):
    """Reject non-JSON values without serializing arbitrary Python objects."""
    pending = [value]
    while pending:
        item = pending.pop()
        if item is None or type(item) in (str, bool, int):
            continue
        if type(item) is float and math.isfinite(item):
            continue
        if type(item) is list:
            pending.extend(item)
        elif type(item) is dict and all(type(key) is str for key in item):
            pending.extend(item.values())
        else:
            raise CleanupError("Artifact contains a non-JSON value")


def _timestamp(value, label):
    _text(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CleanupError(f"Invalid {label}: expected UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise CleanupError(f"Invalid {label}: expected UTC timestamp")


def _header(data):
    if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
        raise CleanupError("Unsupported schema version")
    for key in ("tenancy_id", "parent_id"):
        _text(data[key], key)
    if data["tenancy_id"] == data["parent_id"]:
        raise CleanupError("A tenancy cannot be the retained compartment")


def _node(data):
    _object(data, [field.name for field in fields(Node)], "node", ("blockers",))
    for key in ("key", "resource_type", "region", "compartment_id", "display_name", "lifecycle_state", "handler", "action"):
        _text(data[key], key, empty=key in {"display_name", "lifecycle_state", "handler", "region"})
    if data["action"] not in ACTIONS or type(data["metadata"]) is not dict:
        raise CleanupError("Invalid node action or metadata")
    _json_value(data["metadata"])
    values = dict(data)
    values["blockers"] = _strings(data.get("blockers", []), "blockers")
    return Node(**values)


def _edge(data):
    _object(data, ("before", "after", "evidence"), "edge")
    return Edge(**{key: _text(value, key) for key, value in data.items()})


def _probe(data):
    _object(data, [field.name for field in fields(Probe)], "probe")
    _text(data["status"], "probe status")
    if data["status"] not in {"complete", "failed", "not_supported"}:
        raise CleanupError("Invalid probe status")
    return Probe(**{key: _text(value, key, empty=key in {"detail", "region"}) for key, value in data.items()})


def plan_from_dict(data: dict) -> Plan:
    _object(data, [field.name for field in fields(Plan)], "plan")
    _header(data)
    _text(data["home_region"], "home_region")
    _timestamp(data["created_at"], "created_at")
    for key in ("compartments", "nodes", "depths", "bulk_types"):
        if type(data[key]) is not dict:
            raise CleanupError(f"Invalid {key}: expected object")
    for key in ("edges", "probes"):
        if type(data[key]) is not list:
            raise CleanupError(f"Invalid {key}: expected list")
    compartments = {_text(k, "compartment"): _text(v, "parent link") for k, v in data["compartments"].items()}
    nodes = {_text(k, "node identity"): _node(v) for k, v in data["nodes"].items()}
    for key, value in data["depths"].items():
        if key not in nodes or type(value) is not int or value < 1:
            raise CleanupError("Invalid deletion depth")
    plan = Plan(data["schema_version"], data["tenancy_id"], data["parent_id"], data["home_region"],
                data["created_at"], compartments, nodes, [_edge(e) for e in data["edges"]],
                [_probe(p) for p in data["probes"]], dict(data["depths"]),
                {_text(k, "bulk type"): _strings(v, "bulk metadata") for k, v in data["bulk_types"].items()})
    from .graph import validate_scope
    validate_scope(plan, plan.parent_id)
    return plan


def plan_to_dict(plan: Plan) -> dict:
    data = asdict(plan)
    for value in data["nodes"].values():
        value["blockers"] = list(value["blockers"])
    data["bulk_types"] = {key: list(value) for key, value in data["bulk_types"].items()}
    plan_from_dict(data)
    return data


def state_from_dict(data: dict) -> State:
    _object(data, [field.name for field in fields(State)], "state")
    _header(data)
    if type(data["records"]) is not dict:
        raise CleanupError("Invalid state records")
    for key, record in data["records"].items():
        _text(key, "record identity")
        if type(record) is not dict:
            raise CleanupError("Invalid state record")
        _json_value(record)
    # Copy rather than alias the caller's mutable action history.
    return State(data["schema_version"], data["tenancy_id"], data["parent_id"],
                 json.loads(json.dumps(data["records"], allow_nan=False)))


def state_to_dict(state: State) -> dict:
    data = asdict(state)
    state_from_dict(data)
    return data


def child_key(service: str, region: str, parent_id: str, object_name: str, version_id: str = "") -> str:
    """Unambiguous stable identity for non-OCID child objects."""
    values = (service, region, parent_id, object_name, version_id)
    for label, value in zip(("service", "region", "parent_id", "object_name", "version_id"), values):
        _text(value, label, empty=label == "version_id")
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
