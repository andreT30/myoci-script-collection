# OCI Compartment Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Neither named execution helper is installed in this workspace; preserve the selected execution method and use the available TDD, secure-coding, and verification skills to perform the same task gates if the user authorizes that fallback.

**Goal:** Build a repeatable OCI Python SDK tool that discovers and maps a compartment tree, deletes resources in descending dependency depth, retains the input compartment, and reports pending deletions and coverage gaps.

**Architecture:** Keep graph planning and persistent state independent of OCI calls. Use an explicit handler registry for service discovery, live verification, dependency evidence, and allowed mutations; an executor reads the JSON plan and journals actions before submitting them. OCI bulk actions are selected from a runtime catalog only after a handler establishes scope and dependency eligibility.

**Tech Stack:** Python 3.10+, OCI Python SDK, standard-library argparse/dataclasses/json/unittest, and atomic local file replacement. Use `oci>=2.187.0,<3` in the tool-specific requirements file and validate that minimum release as well as the installed release during implementation.

**Spec:** [Approved design](../specs/2026-10-08-compartment-cleanup-design.md), commit `89cd1d3`.

## Global Constraints

- The chosen compartment is the retained parent: the tool must never delete it.
- The tool must never delete resources outside that tree, including resources that refer to something inside it.
- A run must report `incomplete` whenever any discovered resource, scheduled deletion, child compartment, failed discovery probe, unknown deletion method, unresolved dependency, or failed action remains.
- It must not silently skip resources.
- An edge `A -> B` means **delete A before B**.
- There is no fixed maximum depth.
- Preserve the entire local work directory until cleanup is finished.
- A later `--report` can refresh the map without erasing the action history.
- Bulk eligibility alone does not establish that an action respects the deletion boundary.
- No automated test performs a live deletion.
- Commit only completed, validated files related to this task, per the user's repository instructions.

## Review Focus

1. A resource moves out of the tree, a plan is edited, or a caller supplies another parent: reject the action before submission (Tasks 1, 2, 9).
2. Permission changes produce an ambiguous 404 or missing Search result: keep verification unresolved, rather than mark deletion complete (Tasks 3, 4, 9).
3. A request is accepted just before interruption, or a state write fails: reconcile live state and recorded request IDs before another mutation (Tasks 2, 8, 9).
4. A producer recreates a deleted entity, or a vault deletion cascades outside the tree: order the producer first or block the action (Tasks 6, 7, 9).
5. Resources, descendants, or pages are added after the report: retain the saved deletion set, report drift, and require a refreshed report for additions (Tasks 3, 4, 9, 10).

## File Map and Execution Rules

Create `python/oci_compartment_cleanup.py` as the executable entry point. Create a focused `python/compartment_cleanup/` package with `__init__.py`, `model.py`, `graph.py`, `store.py`, `reporting.py`, `gateway.py`, `discovery.py`, `executor.py`, `cli.py`, and `handlers/` containing `base.py`, `core.py`, `network.py`, `load_balancers.py`, `storage.py`, `scheduled.py`, and `logging_analytics.py`. Create `python/requirements-compartment-cleanup.txt` and `docs/oci-compartment-cleanup.md`; update README tool registration and prerequisites. Add tracked tests under `tests/compartment_cleanup/` without exposing existing ignored tests.

Run focused tests using `PYTHONPATH=python python3 -m unittest discover -s tests/compartment_cleanup -p 'test_<task>.py' -v`. Run the whole available suite with `PYTHONPATH=python python3 -m unittest discover -s tests/compartment_cleanup -v` before each commit. Read the current root tests to determine whether they have a runnable suite; run it at the final gate if present, and report any pre-existing failure by name. The working tree was clean before the design and plan; check it again before execution. Use an isolated worktree at execution time through the using-git-worktrees skill, leaving these reviewed documents accessible to the executor.

Every test step below begins with a failing test for missing behavior, then a minimal implementation, then a passing focused and accumulated suite. Do not create production implementations from the code fragments below before observing the corresponding failure. Tests use a behavior-based OCI simulator with a resource store, scheduled clock, pagination, permission errors, and request lifecycle; use SDK model contract checks separately for exact SDK payload shapes. No test depends on real credentials or calls the network.

## Shared Interfaces

Task 1 defines these dataclasses and all JSON serialization/validation. Keys are OCIDs for OCI resources; non-OCID child objects use a deterministic SHA-256 key over service, region, parent ID, object name, and version/upload ID. Names never identify an OCI resource by themselves.

```python
@dataclass(frozen=True)
class Node:
    key: str
    resource_type: str
    region: str
    compartment_id: str
    display_name: str
    lifecycle_state: str
    handler: str
    action: str  # retain, delete, schedule, prepare, cascade, unresolved
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
    status: str  # complete, failed, not_supported
    detail: str

@dataclass
class Plan:
    schema_version: int
    tenancy_id: str
    parent_id: str
    home_region: str
    created_at: str
    compartments: dict[str, str]  # compartment -> immediate parent
    nodes: dict[str, Node]
    edges: list[Edge]
    probes: list[Probe]
    depths: dict[str, int]
    bulk_types: dict[str, tuple[str, ...]]

@dataclass(frozen=True)
class Observation:
    status: str  # present, pending, deleted, unresolved, moved
    compartment_id: str
    lifecycle_state: str
    scheduled_at: str | None
    etag: str | None
    detail: str

@dataclass(frozen=True)
class Submission:
    status: str  # submitted, pending, deleted, unresolved
    request_id: str | None
    scheduled_at: str | None
    detail: str

@dataclass
class State:
    schema_version: int
    tenancy_id: str
    parent_id: str
    records: dict[str, dict]  # status, attempts, timestamps, requests, errors

class CleanupError(RuntimeError):
    pass
```

Task 3 defines `Gateway` with `client(service: str, region: str, endpoint: str | None = None) -> object`, `items(service: str, region: str, operation: str, params: dict, endpoint: str | None = None) -> list[dict]`, `read(service: str, region: str, operation: str, params: dict, endpoint: str | None = None) -> tuple[dict, dict]`, and `write(service: str, region: str, operation: str, params: dict, endpoint: str | None = None) -> tuple[dict, dict]`. Only code-defined operation names can reach these methods. A gateway normalizes SDK models to JSON-safe values, supplies bounded read retries, and leaves mutation retry choice to the handler. An endpoint can only be derived from a fresh OCI response and validated against the current realm and vault identity; never read an endpoint or SDK method from the JSON plan.

Task 4 defines the base `Handler.discover(gateway: Gateway, compartment_id: str, region: str) -> tuple[list[Node], list[Edge], list[Probe]]`, `Handler.inspect(gateway: Gateway, node: Node, scope: set[str]) -> Observation`, and `Handler.submit(gateway: Gateway, node: Node, observation: Observation, attempt_id: str) -> Submission`. `Registry` owns `handlers: dict[str, Handler]`, `classify(node: Node) -> Node`, and `handler_for(node: Node) -> Handler | None`. Tasks 5–7 supply concrete handlers. Every handler must verify its own operation and known cascade effects; arbitrary `getattr` driven by a plan is prohibited.

## Task 1: Versioned Plan and Graph

**Files:** Create `model.py`, `graph.py`, package `__init__.py`, and `tests/compartment_cleanup/test_graph.py`; modify `.gitignore` to track only the new test directory.

**Interfaces:** Produce the shared model, `plan_from_dict(data: dict) -> Plan`, `plan_to_dict(plan: Plan) -> dict`, `compute_depths(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, int], dict[str, tuple[str, ...]]]`, and `validate_scope(plan: Plan, supplied_parent: str) -> set[str]`. The blocker dictionary identifies cycles and dangling edges; blocked nodes do not get runnable depths.

- [ ] Write graph tests for a chain of seven resources, disconnected nodes, a diamond, a cycle, a dangling edge, and a protected parent. Pin direction explicitly:

```python
def test_seven_levels_are_deleted_deepest_first(self):
    nodes = {str(i): Node(str(i), "Example", "r", "parent", "", "ACTIVE", "example", "delete", {}) for i in range(1, 8)}
    edges = [Edge(str(i), str(i - 1), "test dependency") for i in range(2, 8)]
    depths, blockers = compute_depths(nodes, edges)
    self.assertEqual(depths, {str(i): i for i in range(1, 8)})
    self.assertEqual(blockers, {})
```

- [ ] Run `test_graph.py` and observe failure from missing model/graph behavior. Add schema tests rejecting a wrong version, duplicate identity, parent marked delete, invalid compartment hierarchy, or edge referencing an external deletion target.
- [ ] Implement dataclasses and strict JSON conversion. The graph traverses successors iteratively so a deep chain does not fail at Python's recursion limit. Set a leaf to depth 1 and its predecessor to one plus the maximum successor depth. A cycle blocks all nodes in the cycle and every prerequisite reachable downstream from it. Validate the parent using the live hierarchy during execution as well as the file's hierarchy.
- [ ] Replace `/tests/` in `.gitignore` with `/tests/*` followed by `!/tests/compartment_cleanup/`; retain the existing unrelated ignored tests. Add ignore entries for the default `.oci-cleanup/` directory; user-selected directories outside it are documented as local artifacts.
- [ ] Run the graph and full accumulated suites, plus `git diff --check`; commit the model, graph, new tests, and relevant ignore changes with `feat: add OCI cleanup dependency plan`.

## Task 2: Atomic State, Work Directory Lock, and Reports

**Files:** Create `store.py`, `reporting.py`, and `tests/compartment_cleanup/test_store.py`.

**Interfaces:** Consume Plan/State. Produce `Workspace(path: Path).locked() -> context manager`, `.load(parent_id: str) -> tuple[Plan, State]`, `.save_plan(plan: Plan) -> None`, `.save_state(state: State) -> None`, `.save_report(text: str) -> None`, `reconcile_state(plan: Plan, old: State | None) -> State`, and `render_report(plan: Plan, state: State) -> str`.

- [ ] Write tests that refresh a plan while preserving a pending certificate's timestamp and attempts, reject a different tenancy/parent, reject an unexpected schema, and keep the old valid JSON if replacement fails. Use a real temporary directory and actual files:

```python
def test_refresh_preserves_scheduled_deletion(self):
    old = State(1, "tenancy", "parent", {"cert": {"status": "pending", "scheduled_at": "2026-10-10T12:00:00Z", "attempts": []}})
    refreshed = reconcile_state(self.plan, old)
    self.assertEqual(refreshed.records["cert"], old.records["cert"])
```

- [ ] Observe the failing focused tests. Add lock-contention tests using two processes, and tests for a truncated file or symlink at a managed artifact path. Preserve old records for nodes absent from a refreshed map until authoritative verification resolves them.
- [ ] Implement atomic replacement and restrictive permissions, refusing symlink artifact paths. Hold one advisory directory lock for both report refresh and deletion; process exit releases the lock, avoiding manual stale-lock deletion. Use a platform-supported lock on macOS/Linux and clearly reject unsupported platforms. Core replacement sequence:

```python
with tempfile.NamedTemporaryFile(mode="w", dir=target.parent, delete=False, encoding="utf-8") as stream:
    os.chmod(stream.name, 0o600)
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(stream.name, target)
```

- [ ] Render descending depth sections with identities, method, and edge evidence; unresolved nodes and coverage gaps get explicit sections. Include the parent retained, pending timestamps in UTC, next known revisit time, and the sentence `Preserve this work directory until cleanup is finished.` A timestamp is an earliest known condition, never a promise that cleanup will finish at that time.
- [ ] Run focused/full suites and commit with `feat: persist resumable OCI cleanup state`.

## Task 3: SDK Authentication, Pagination, and Hierarchy

**Files:** Create `gateway.py`, tool-specific requirements, `tests/compartment_cleanup/test_gateway.py`, and `tests/compartment_cleanup/simulator.py`.

**Interfaces:** Produce Gateway, `build_gateway(auth: str, config_file: str, profile: str, bootstrap_region: str | None) -> Gateway`, `discover_scope(gateway: Gateway, parent_id: str) -> tuple[str, str, list[str], dict[str, str]]` returning tenancy, home region, subscribed regions, and parent links. Simulator provides `add(Node)`, `advance(datetime)`, `discover_scope(parent_id)`, a mutable resource store, operation events, page fixtures, permission failures, and pending work requests. It implements Gateway behavior without network calls.

- [ ] Write failing tests for API-key configuration/profile forwarding and instance-principal signer construction without reading key contents into reports. Patch SDK construction only, as authentication cannot be tested without an external identity. Test paginated list and collection `.items` responses, repeated page token detection, and a denied second page that produces a failed probe rather than a partial-success list.
- [ ] Add a hierarchy test containing an unrelated compartment and a hidden/malformed parent link. Ensure subtree scope follows actual links rather than matching names or OCID prefixes. Refuse a tenancy OCID as the retained parent; accept only an existing non-root compartment that is reachable from the authenticated tenancy.
- [ ] Implement explicit client factories. The core signer selection is:

```python
if auth == "api_key":
    config = oci.config.from_file(config_file, profile)
    oci.config.validate_config(config)
    signer = None
elif auth == "instance_principal":
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    config = {"region": bootstrap_region or signer.region, "tenancy": signer.tenancy_id}
else:
    raise CleanupError("Unsupported authentication mode")
```

Use `IdentityClient` for `get_compartment`, `list_compartments`, and `list_region_subscriptions`; locate the home region from the subscription flag. Use `SearchClient.search_resources(StructuredSearchDetails(query=...))`. Use SDK pagination helpers or an explicit page loop that normalizes both list and collection results and preserves every failure. Do not rely on unsupported `compartment_id_in_subtree` combinations; verify their behavior from the installed SDK and filter by parent links.
- [ ] Treat `NotAuthorizedOrNotFound` as unresolved unless an independently successful service-specific probe and explicit terminal-state evidence establish removal. A read timeout/403/404 never translates directly into `deleted`. Tests must exercise this policy rather than assume every 404 means gone.
- [ ] Install the dependency only at execution time in a local virtual environment. Run the focused/full suites, SDK model-contract tests, and commit with `feat: connect OCI cleanup to the Python SDK`.

## Task 4: Search Inventory, Evidence, and Refresh

**Files:** Create `discovery.py`, `handlers/base.py`; create `tests/compartment_cleanup/test_discovery.py`.

**Interfaces:** Consume Gateway and models. Produce `discover(gateway: Gateway, parent_id: str, registry: Registry, previous: Plan | None = None) -> Plan`, `compare_plan(saved: Plan, live: Plan) -> dict[str, list[str]]` with added/moved/changed identities, `merge_nodes(search_nodes: list[Node], handler_nodes: list[Node]) -> dict[str, Node]`, and `collapse_cascades(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, Node], list[Edge]]`. Registry's concrete handlers arrive in Tasks 5–7; until then tests inject a registry of service simulators.

- [ ] Test multiple compartments and regions, duplicate Search/global resources, resources omitted by Search but found by a service probe, failed probes, and an unknown bulk-supported type whose dependencies are unresolved. An unknown type must not become safe just because it appears in the bulk catalog:

```python
def test_bulk_support_does_not_resolve_unknown_dependencies(self):
    plan = discover(self.gateway_with_unknown_bulk_type, "parent", self.registry)
    unknown = plan.nodes["unknown"]
    self.assertEqual(unknown.action, "unresolved")
    self.assertTrue(unknown.blockers)
```

- [ ] Observe failures, then query `list_bulk_action_resource_types(bulk_action_type="BULK_DELETE_RESOURCES")` with pagination and preserve each type's metadata keys. Use exact catalog type names in bulk requests; aliases are an explicit code-defined mapping. Never infer required metadata values from a resource's display name.
- [ ] Build compartment nodes and attach resource-before-compartment and child-before-parent edges, excluding a delete action for the retained parent. Distinguish actual resources from preparation/cascade nodes. A failed probe blocks relevant compartment deletion. Extract references only from typed resource fields and explicit association APIs; do not treat every incidental OCID in tags or descriptions as a dependency.
- [ ] Test and implement cascade graph normalization: a verified cascade member uses `metadata["cascade_owner"]` to remap its incoming/outgoing dependency edges to its owner, excluding self-edges. The displayed plan retains all member identities and evidence. The executable graph includes the owner; members become completed only when live verification confirms their removal. This prevents VCN defaults or vault-owned keys from blocking the very owner operation that removes them. Unknown owners, cycles, or unverified memberships stay unresolved.
- [ ] Add an absence test: a refreshed Search result omits a pending node, but a direct service read still reports it pending. Retain that node and its blocker. Newly discovered nodes enter a report refresh; a deletion run against an old plan reports them as drift and does not silently expand its deletion set.
- [ ] Run focused/full suites and commit with `feat: discover OCI resources and coverage gaps`.

## Task 5: Core, Network, and Storage Handlers

**Files:** Create `handlers/core.py`, `handlers/network.py`, `handlers/load_balancers.py`, `handlers/storage.py`, and `tests/compartment_cleanup/test_core.py`, `test_network.py`, `test_load_balancers.py`, `test_storage.py`; extend base registry.

**Interfaces:** Implement Handler methods. Each registered type declares discovery, live read, terminal states, reference fields, known cascades, and bulk metadata builder. `Registry.classify` selects `delete`, `prepare`, `cascade`, or `unresolved`; bulk is chosen later without replacing the handler used for verification.

This task has four independently reviewable deliveries: 5A IAM/Compute/Block Storage in `core.py`, 5B VCN networking in `network.py`, 5C load balancers in `load_balancers.py`, and 5D Object Storage in `storage.py`. Complete each delivery's failing tests, implementation, accumulated suite, review, and commit before starting the next. Use the corresponding focused test file above.

- [ ] Write and observe failing tests for instance-before-subnet, subnet-before-route-table, volume attachment detachment before volume deletion, a VCN's built-in default resources, in-scope resource -> child compartment, and an external VNIC/attachment that blocks deletion. Test that terminating an instance preserves its boot volume, so a separately scoped volume action controls its deletion.
- [ ] Implement explicit method families using named parameters and SDK model constructors. Check each row against the installed SDK before enabling it; if an operation's documented dependency behavior cannot be established, keep its handler unresolved and report the reason rather than register an unsafe action.

| Resource | SDK clients and operations | Dependency/preparation rules |
| --- | --- | --- |
| IAM policy | IdentityClient `list_policies`, `get_policy`, `delete_policy` | Delete only the policy's own in-scope object. Keep authorization-affecting policies until other resource actions finish; report loss of permission as incomplete. |
| Instance, attachments | ComputeClient `list_instances`, `get_instance`, `terminate_instance`; `list_vnic_attachments`, `list_volume_attachments`, `list_boot_volume_attachments` | Instance termination precedes its inherited VNIC removal. Use `preserve_boot_volume=True`; verify volume/VNIC memberships and preserve out-of-scope volumes. Attachment operations have distinct planned nodes. |
| VCN/network objects | VirtualNetworkClient `list_vcns`, `get_vcn`, `delete_vcn`; matching list/get/delete operations for subnets, gateways, NSGs, custom route tables, security lists, DHCP options | Inspect actual references and memberships. VCN defaults use verified `cascade` membership and are removed with the VCN. Planned preparation nodes clear in-scope route-table routes using `UpdateRouteTableDetails(route_rules=[])` where necessary. External members/references block the branch. |
| Boot/block volume and backups | BlockstorageClient list/get/delete methods, with availability-domain enumeration where required | Detach in-scope attachments first. Use a fresh GET and ETag where supported. External attachments block; a backup is an independently scoped resource. |
| Load balancers | LoadBalancerClient and NetworkLoadBalancerClient list/get/delete operations | Inspect subnets, NSGs, certificates, and private IP references; check documented internal-child cascade scope before marking safe. Track asynchronous deletion. |
| Object Storage | ObjectStorageClient `get_namespace`, `list_buckets`, `get_bucket`, `list_objects`, `list_object_versions`, `list_multipart_uploads`, `delete_object`, `abort_multipart_upload`, `delete_bucket` | Version/object/upload nodes precede the bucket. Page through all versions and markers. Retention/replication rules are mapped; locked retention or unresolved replication dependencies block cleanup. |

The VCN registry uses these exact method names and identifier parameters. Listing is compartment-scoped; additional filters and association calls belong to the typed handler, not the saved JSON.

```python
NETWORK_OPERATIONS = {
    "Vcn": ("list_vcns", "get_vcn", "delete_vcn", "vcn_id"),
    "Subnet": ("list_subnets", "get_subnet", "delete_subnet", "subnet_id"),
    "InternetGateway": ("list_internet_gateways", "get_internet_gateway", "delete_internet_gateway", "ig_id"),
    "NatGateway": ("list_nat_gateways", "get_nat_gateway", "delete_nat_gateway", "nat_gateway_id"),
    "ServiceGateway": ("list_service_gateways", "get_service_gateway", "delete_service_gateway", "service_gateway_id"),
    "LocalPeeringGateway": ("list_local_peering_gateways", "get_local_peering_gateway", "delete_local_peering_gateway", "local_peering_gateway_id"),
    "RouteTable": ("list_route_tables", "get_route_table", "delete_route_table", "rt_id"),
    "SecurityList": ("list_security_lists", "get_security_list", "delete_security_list", "security_list_id"),
    "DhcpOptions": ("list_dhcp_options", "get_dhcp_options", "delete_dhcp_options", "dhcp_id"),
    "NetworkSecurityGroup": ("list_network_security_groups", "get_network_security_group", "delete_network_security_group", "network_security_group_id"),
}
```

SDK parameter contracts must be checked before enabling these literals. Add unsupported network types from Search, such as an unresolved DRG family, as blockers until their actual relationship handler is implemented; this is a recorded gap, never an omitted node. Extend resource families using tested explicit code, not name-based SDK inference.

- [ ] The network handler inspects known external attachments using read-only visible-tenancy probes or direct association reads; external objects never enter the executable node set. Failed external checks create unresolved evidence. Handle relationship direction explicitly; for example an instance uses a subnet, so delete the instance before the subnet. Do not infer that deleting a key consumer also deletes its encryption key.
- [ ] Object tests use a versioned bucket with two versions of one name, a delete marker, a multipart upload, a locked retention rule, and a second page. Deletion uses explicit version/upload identities from the plan and validates the owning bucket live; it must not delete a newly uploaded object absent from the plan. SDK object deletion has no assumed universal server-side batch API: use bounded concurrency for independent objects and actual bulk APIs for eligible resources.
- [ ] Preparation/cascade tests require the VCN handler to verify the full live cascade membership. A default resource does not block its VCN merely because it cannot be deleted alone, but an unknown default/child or out-of-scope cascade member does. Ensure dependent branches still wait until the owning resource's removal is confirmed.
- [ ] For 5A run focused/full suites and commit with `feat: resolve compute and volume cleanup dependencies`; for 5B use `feat: resolve VCN cleanup dependencies`; for 5C use `feat: verify load balancer cleanup`; for 5D use `feat: map Object Storage cleanup`. Each commit contains only the corresponding validated handler and tests.

## Task 6: Certificates, Authorities, Vaults, Keys, and Secrets

**Files:** Create `handlers/scheduled.py`, `tests/compartment_cleanup/test_scheduled.py`; extend registry.

**Interfaces:** Implement Handler methods, `scheduled_time(kind: str, now: datetime) -> datetime` using documented minimums plus a small safe margin, and `validate_cascade(nodes: list[Node], scope: set[str]) -> tuple[str, ...]`. Preserve an existing live schedule exactly. Times are timezone-aware UTC ISO 8601 strings in artifacts.

- [ ] Write failing tests for scheduling a certificate once, refreshing an existing schedule, issuer/association ordering, pending resources blocking prerequisites, a vault replica or key outside the tree blocking source-vault scheduling, and a secret replica outside the tree blocking source-secret scheduling. Advance the simulator clock past a date without removing the resource: it must remain pending until live OCI state confirms deletion.

```python
def test_schedule_date_alone_does_not_complete_deletion(self):
    node = self.simulator.pending_certificate("cert", "2026-10-10T12:00:00Z")
    self.simulator.advance(datetime(2026, 10, 11, tzinfo=timezone.utc))
    observation = self.handler.inspect(self.simulator, node, {"parent"})
    self.assertEqual(observation.status, "pending")
```

- [ ] Observe failures and implement the concrete SDK mapping:

| Resource | Discovery/read | Action |
| --- | --- | --- |
| Certificate | CertificatesManagementClient `list_certificates`, `get_certificate`, `list_associations(certificates_resource_id=...)` | `schedule_certificate_deletion(certificate_id, ScheduleCertificateDeletionDetails(time_of_deletion=...))` |
| Certificate authority | `list_certificate_authorities`, `get_certificate_authority`, certificate/CA issuer relationships and associations | `schedule_certificate_authority_deletion(certificate_authority_id, ScheduleCertificateAuthorityDeletionDetails(time_of_deletion=...))` |
| CA bundle | `list_ca_bundles`, `get_ca_bundle`, association checks | `delete_ca_bundle(ca_bundle_id)` after consumers disappear |
| Vault | KmsVaultClient `list_vaults`, `get_vault`, `list_vault_replicas` | `schedule_vault_deletion(vault_id, ScheduleVaultDeletionDetails(time_of_deletion=...))` after verifying every affected key and replica |
| Key | KmsManagementClient at the fresh vault management endpoint; `list_keys`, `get_key` | `schedule_key_deletion(key_id, ScheduleKeyDeletionDetails(time_of_deletion=...))` |
| Secret | VaultsClient `list_secrets`, `get_secret` | `schedule_secret_deletion(secret_id, ScheduleSecretDeletionDetails(time_of_deletion=...))` |

- [ ] Use a minimum of one day for certificates/secrets and seven days for CAs/vaults/keys, plus a five-minute margin against clock skew and elapsed requests. Do not allow the operator to set a time below the service minimum. Add a fixture containing secret content and ensure it never appears in plan/state/report: only identifying/dependency metadata is recorded. Secret deletion also deletes replicas; inspect their live replication configuration and resolve every target's scope before permitting the source deletion. Unknown or external targets block it.
- [ ] Certificate associations are references, not standalone deletable association API objects. Place the consumer before the certificate, then confirm associations have disappeared. Never invent `delete_association`. An external consumer or failed association read blocks scheduling. In-scope vault keys can be individually scheduled; the vault's own cascade requires proof that all affected identities are in scope. With a fully verified cascade, owned keys use the vault as their cascade owner and graph normalization redirects consumer edges to it, avoiding an unnecessary extra seven-day wait. An unresolved endpoint/replica identity prevents that cascade.
- [ ] Read back the resource after scheduling to record the service's confirmed timestamp. If the call's response is lost, the next inspection detects pending state and reconciles it instead of rescheduling. Include real SDK model serialization checks for every schedule payload.
- [ ] Run focused/full suites and commit with `feat: resume OCI scheduled deletions`.

## Task 7: Logging Analytics Producers and Entities

**Files:** Create `handlers/logging_analytics.py`, `tests/compartment_cleanup/test_logging_analytics.py`; extend registry.

**Interfaces:** Implement Handler methods; consume namespace discovery and scope; produce producer-before-entity edges and explicit external/unresolved producer blockers.

- [ ] Write failing tests where a Service Connector produces an entity and recreates it until the connector disappears, an external connector blocks the entity, and a second page of entities is discovered. The simulator implements recreation, so the assertion exercises the planner/executor rather than a mocked call count.

```python
def test_connector_precedes_entity(self):
    nodes, edges, probes = self.handler.discover(self.simulator, "parent", "region")
    graph_nodes = {node.key: node for node in nodes}
    depths, blockers = compute_depths(graph_nodes, edges)
    self.assertGreater(depths["connector"], depths["entity"])
    self.assertFalse(blockers)
```

- [ ] Observe failures and implement paginated `LogAnalyticsClient.list_namespaces`, `list_log_analytics_entities`, `get_log_analytics_entity`, and `delete_log_analytics_entity(namespace_name, log_analytics_entity_id)`. Obtain every relevant namespace; do not assume `.items[0]` is sufficient. Read the entity's creation source, cloud resource, management agent, and association details to establish producer evidence.
- [ ] Use ServiceConnectorClient `list_service_connectors`, `get_service_connector`, and `delete_service_connector`. Confirm `DELETED` before progressing. Map Object Storage collection rules and EM Bridges as producers through their LogAnalytics list/get/delete APIs; otherwise mark that entity's producer unresolved. A source-type string without an identified producer is insufficient evidence to execute deletion.
- [ ] When entity-source associations exist, permit `is_force_delete=True` only after their owning entity and affected collections have verified in-scope membership; otherwise report a blocker. Avoid changing tenancy-wide entity preferences as part of compartment cleanup.
- [ ] Add a stale-plan test where the entity reappears after an apparent deletion. Rediscovery reports it active and the branch remains incomplete. The same identity must reconcile safely even if a prior attempt recorded deletion; state history is retained.
- [ ] Run focused/full suites and commit with `feat: clean Logging Analytics entities after producers`.

## Task 8: Bulk Submission and Work Request Reconciliation

**Files:** Extend `gateway.py`; create bulk functions in `executor.py`, `tests/compartment_cleanup/test_bulk.py`.

**Interfaces:** Produce `bulk_groups(plan: Plan, ready: list[Node], registry: Registry) -> list[list[Node]]`, `submit_bulk(gateway: Gateway, plan: Plan, nodes: list[Node], attempt_id: str) -> Submission`, and `inspect_bulk(gateway: Gateway, plan: Plan, request_id: str) -> dict`. Each group contains one compartment and one depth, with verified identifiers and all catalog metadata. Limit batch size to the service-documented limit verified at implementation; if the SDK exposes no documented limit, use conservative chunks of 20 and report the configured size.

- [ ] Write failing tests for grouping different compartments/depths, excluding missing metadata and scheduled nodes, routing every request to the home region, a partial-failure work request, a lost response, and a request still in progress when the bounded wait expires. Exclude an instance from bulk if the handler needs `preserve_boot_volume=True` to protect an out-of-scope boot volume: bulk cannot carry arbitrary per-service flags, so a direct operation is required there.
- [ ] Observe failures, then construct real models:

```python
details = oci.identity.models.BulkDeleteResourcesDetails(
    resources=[oci.identity.models.BulkActionResource(
        identifier=node.key,
        entity_type=node.metadata["bulk_resource_type"],
        metadata=node.metadata["bulk_metadata"],
    ) for node in nodes]
)
response = identity.bulk_delete_resources(
    compartment_id=nodes[0].compartment_id,
    bulk_delete_resources_details=details,
    opc_retry_token=attempt_id,
)
```

Validate the model property names through actual SDK serialization before use; do not derive payload field names from this snippet if the installed model differs. Persist the attempt token and intended group before submission. Retry only with a service-supported idempotency token and its original arguments; do not retry an ambiguous mutation through a second different action.
- [ ] Read `opc-work-request-id` and `opc-workrequest-id` case-insensitively, handling the documented header spellings. Poll `IdentityClient.get_work_request`; its `WorkRequest` model embeds `resources`, `errors`, and `logs`. Do not call nonexistent generic `list_work_request_errors` or confuse this with the separate IAM work-request API. Recheck each resource via its handler after terminal work-request status; a terminal failed/succeeded request alone never proves all its resources gone. Preserve request history when a later request retries a failed item.
- [ ] On interruption or missing response, reconcile live resource states first. If the operation outcome cannot be established, mark `unresolved` and report it; do not assume failure and send a duplicate schedule/delete. Bounded polling defaults to 300 seconds per run with a configurable positive limit; no multi-day sleeping occurs.
- [ ] Run focused/full suites and commit with `feat: track OCI bulk cleanup work requests`.

## Task 9: Deletion Executor and Final Verification

**Files:** Complete `executor.py`; create `tests/compartment_cleanup/test_executor.py`.

**Interfaces:** Consume Plan, State, Workspace, Registry, Gateway. Produce `execute(plan: Plan, state: State, workspace: Workspace, gateway: Gateway, registry: Registry, supplied_parent: str, wait_seconds: int = 300) -> State` and `cleanup_result(plan: Plan, state: State) -> tuple[str, int]` returning a readable result and exit status. Live drift does not expand the saved executable set.

- [ ] Write and observe failing tests for a complete seven-level cleanup, pending certificate with an independent runnable branch, unresolved/cyclic prerequisites, moved resource, edited parent action, changed hierarchy, new child/resource after report, partial bulk failure, and crash between submission and state persistence. Use the simulator's actual resources to assert outcome:

```python
def test_pending_certificate_preserves_child_compartment(self):
    state = execute(self.plan, self.state, self.workspace, self.simulator, self.registry, "parent")
    self.assertIn("parent", self.simulator.resources)
    self.assertIn("child", self.simulator.resources)
    self.assertEqual(state.records["certificate"]["status"], "pending")
    self.assertEqual(cleanup_result(self.plan, state)[1], 2)
```

- [ ] Revalidate tenancy, retained parent, live hierarchy, node scope, relationship evidence, and cascade scope before mutations. Reclassify each live resource through the code-defined registry instead of trusting edited `handler`, `action`, or metadata fields. Recompute cascade groups, depths, and blockers from validated edges rather than trusting stored depth values. If the chosen parent has moved outside the recorded tenancy or cannot be read, stop. Preserve the saved parent membership boundary even if an external compartment is later moved beneath it; require report refresh before targeting additions.
- [ ] Process depth values descending. A node is runnable only if every incoming predecessor is confirmed deleted or its planned preparation is complete. A pending/failed/unresolved predecessor blocks the node and its prerequisites. Process independent safe branches while blocked branches remain incomplete. Cascade members are confirmed through their owner; do not require them gone before submitting the very owner action that deletes them.
- [ ] Save an `attempting` record with immutable arguments and token before every submission; save the result immediately after it. On any state-write failure stop further mutations. Reconcile attempting/submitted/pending records first on a repeated run. Preserve past failures in history while allowing a newly verified action to proceed.
- [ ] Before each child compartment deletion, rerun every applicable probe for that compartment and ensure all resources/descendants are absent, all probes succeeded, and no out-of-plan additions exist. Submit `delete_compartment` only for descendants. Confirm its terminal state or subsequent authoritative IAM result; a rejection leaves it incomplete and records the error. Delete child policies after resource actions, as late as possible to reduce loss of the executor's own permissions.
- [ ] Perform final supported rediscovery and render/save the status. A successful result must be phrased `Cleanup complete for the recorded discovery coverage; retained parent: <OCID>.` Keep a visible universal-inventory limitation. Any known unsupported node, pending deletion, child compartment, failed probe, or unresolved evidence yields exit 2. Fatal schema/scope/authentication/local-write errors yield exit 1. The script never asserts universal proof of an empty parent.
- [ ] Run focused/full suites and commit with `feat: execute repeatable OCI cleanup plans`.

## Task 10: CLI, User Guide, and End-to-End Verification

**Files:** Create `cli.py`, `python/oci_compartment_cleanup.py`, `docs/oci-compartment-cleanup.md`, `tests/compartment_cleanup/test_cli.py`; update README.

**Interfaces:** Produce `main(argv: list[str] | None = None) -> int`. Report and delete are mutually exclusive modes. Required arguments are `--compartment-id` and `--work-dir`; authentication accepts `--auth api_key|instance_principal`, `--config-file`, `--profile`, and `--bootstrap-region`. Deletion additionally requires `--confirm-parent` matching `--compartment-id`. Provide `--wait-seconds` for bounded asynchronous waits. No default invocation can mutate OCI resources.

- [ ] Write and observe failing CLI tests for mutually exclusive modes, missing scope confirmation, a missing or mismatched plan, malformed JSON, report-only behavior, and a repeated deletion run after a simulated scheduled removal. Verify stdout includes pending resource identity and timestamp. The entry point is intentionally small:

```python
#!/usr/bin/env python3
from compartment_cleanup.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] Implement argument validation before constructing mutation-capable clients. `--report` exits 0 when report generation succeeds, even though the plan contains resources; incomplete discovery returns 2. Delete mode uses the result codes from Task 9. Display exact artifact paths and preserve-state guidance after each run. An interrupted process exits without erasing the latest valid state.
- [ ] Write the guide with these runnable command patterns and explain every file and result code:

```bash
python3 -m pip install -r python/requirements-compartment-cleanup.txt
python3 python/oci_compartment_cleanup.py --report \
  --compartment-id ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth api_key --profile DEFAULT
python3 python/oci_compartment_cleanup.py --delete \
  --compartment-id ocid1.compartment.oc1..example \
  --confirm-parent ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth api_key --profile DEFAULT
python3 python/oci_compartment_cleanup.py --report \
  --compartment-id ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth instance_principal
```

Document API-key configuration, instance-principal dynamic-group policies, all subscribed regions, home-region bulk actions, scope limits, cascading deletions, earliest scheduling times, report refresh, and repeated use of the identical deletion command. State prominently: **These commands create local files. Preserve the entire work directory until cleanup is finished.** Include an example `Cannot finish cleanup: <resource OCID> is pending deletion until <UTC timestamp>; rerun after that time and verify its removal.` Explain that report refresh recovers current state but cannot recover lost action history.
- [ ] Add a handler/coverage table showing exactly which direct discoveries/dependencies/deletions are implemented, which types use dynamic bulk support, and which gaps produce blockers. Never describe the script as universally complete. Add Logging Analytics producer ordering with the official source and the user-provided article. Explain that SDK object concurrency is different from an assumed server-side bulk API.
- [ ] Run the whole accumulated suite, any runnable pre-existing suite, compile all new Python files, run entry-point `--help` without OCI credentials, serialize schedule/bulk payloads with the supported SDK floor and installed SDK, and run `git diff --check`. Inspect README links and validate JSON fixtures through the real schema. Perform no optional live mutation.
- [ ] Request one independent code review of scope/cascade enforcement, dependency direction, ambiguous reads, and crash recovery using the available review skill. Fix actionable findings and rerun only affected tests plus the full required suite. Commit completed implementation/docs/tests with `feat: document and expose OCI compartment cleanup` and report commit IDs, meaningful test evidence, and remaining coverage gaps.

## Plan Self-Review Checklist

- [x] Purpose, retained parent, outside-tree protection, dependency depths, report mode, authentication, bulk requests, scheduled deletion, repeatability, local file retention, and Logging Analytics are assigned to concrete tasks.
- [x] Coverage gaps and universal inventory limits remain visible; no runtime catalog or guessed SDK operation is treated as proof of safe deletion.
- [x] Review Focus conditions have tests assigned to their owning tasks.
- [x] Interfaces and field names used by later tasks are defined above; code fragments are implementation targets gated by failing tests, not pre-written production code.
- [x] Existing ignored tests remain unrelated and excluded; the new cleanup test suite is tracked.
- [x] Plan and spec review precede execution; installed execution-helper availability is recorded explicitly.

## API References for Execution

- [Identity SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/identity/client/oci.identity.IdentityClient.html): compartment, bulk catalog, bulk deletion, and IAM work requests.
- [Certificates management SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/certificates_management/client/oci.certificates_management.CertificatesManagementClient.html): associations and scheduling.
- [KMS Vault SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/key_management/client/oci.key_management.KmsVaultClient.html) and [KMS management SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/key_management/client/oci.key_management.KmsManagementClient.html): vault, replicas, keys, and management endpoints.
- [Secret management SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/vault/client/oci.vault.VaultsClient.html): secret metadata and scheduled deletion.
- [Logging Analytics SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/log_analytics/client/oci.log_analytics.LogAnalyticsClient.html) and [Service Connector SDK](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/sch/client/oci.sch.ServiceConnectorClient.html): namespace/entity discovery and producers.

Verify every enabled handler against its service's current official API reference and the installed SDK before implementation. SDK signatures can use generic keyword arguments, so checking a method's existence alone is insufficient: exercise the real model and named-parameter contracts without a network call.
