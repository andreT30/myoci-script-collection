# OCI compartment-tree cleanup: design

## Purpose and completion rule

Create a repeatable Python tool that removes resources from a chosen OCI
compartment and all of its descendants, then deletes the descendant
compartments. The chosen compartment is the retained parent: the tool must
never delete it. The tool must never delete resources outside that tree,
including resources that refer to something inside it.

The desired outcome is an empty retained parent with no descendant
compartments. A run must report `incomplete` whenever any discovered resource,
scheduled deletion, child compartment, failed discovery probe, unknown deletion
method, unresolved dependency, or failed action remains. OCI has no universal
resource inventory or deletion API, so the tool must state its discovery
coverage and must not claim that it has proved the absence of resource types
its probes cannot see. It must not silently skip resources.

## Operator workflow and authentication

The command is a new script under `python/` using the OCI Python SDK. It
supports API-key authentication through an OCI configuration file and profile,
and instance-principal authentication through the SDK signer. It does not
store credentials in its output.

1. `--report` discovers the retained parent, its descendant compartments,
   and their resources across subscribed regions. It writes a machine-readable
   dependency plan and a readable report without changing OCI resources.
2. An explicit delete mode reads the saved plan, requires the parent OCID as
   a scope guard, and checks current OCI state before each action.
3. The operator repeats delete mode over days or weeks while scheduled
   deletions mature. A later `--report` can refresh the map without erasing
   the action history. Each run explains what it completed, what is pending,
   the next known deletion time, and what needs manual attention.

The README and command help must say clearly: **preserve the entire local work
directory until cleanup is finished**. A fresh report can reconstruct the
current map, but the saved state retains work-request IDs, outcomes, and the
history needed to explain a long cleanup.

## Discovery and coverage

Discovery enumerates the compartment hierarchy through IAM, obtains all
subscribed regions, and queries Resource Search per compartment and region.
Service-specific probes supplement Search for resource types it does not
index and for details needed to resolve dependencies or deletion methods.
Bulk-action support is queried from OCI at runtime; the tool must not assume
that all Search types are bulk-deletable. Service handlers cover operations
that need preparation, direct deletion, or scheduling.

Each probe records `complete`, `failed`, or `not_supported`, with its service,
region, compartment, and error. A failed probe is a coverage gap, even if
Search returned no resources. The plan records each discovered resource's
stable identity, type, name, region, compartment, lifecycle state, deletion
method, identifying metadata required by bulk actions, and evidence for its
dependency edges. A resource with insufficient detail is marked unresolved
rather than assigned a guessed action.

The first service-specific cases include Certificates, Vault resources, and
Logging Analytics entities. Their producers must be removed first: an entity
created from a Service Connector can reappear while that connector continues
sending logs. The graph therefore places the connector before the entity.
An external producer is a blocker. Further service handlers can be added without changing
the plan format. The completion rule applies regardless of how many handlers
are present: unsupported types are explicit blockers, not exceptions counted
as success.

## Dependency map and deletion order

The plan is a versioned JSON graph. An edge `A -> B` means **delete A before
B**. A node's deletion depth is its longest path to a node with no successors,
plus one. Thus a node at depth 5 is processed before depth 4, continuing to
depth 1; there is no fixed maximum depth. The human report lists nodes at
each depth and why each edge exists. Cycles and uncertain edges are surfaced
as blockers rather than broken arbitrarily.

Dependencies can cross compartments only when both ends are inside the chosen
tree. An external resource or reference is recorded as a blocker; it is never
added to the deletion set. Child compartments are deleted bottom-up only when
their resources and descendants have actually disappeared. The retained
parent is represented as a scope boundary, not a deletion target.

## Execution and repeatability

Execution validates that the plan belongs to the supplied retained parent.
It rechecks resource identity, compartment membership, and state before each
mutation. For eligible resources at the same depth and in the same
compartment, it uses OCI's bulk-delete API in the tenancy home region,
providing the metadata required for each type. It tracks the IAM work request
and its item errors before treating any resource as deleted. Resources not
eligible for bulk action use explicit service handlers. Any child action that
is still running or pending blocks deletion of its prerequisite.

Before choosing an action, its handler checks any documented cascade effects.
For example, deleting a source vault can also delete its replicated vault and
keys. If any affected resource is outside the chosen tree, or the handler
cannot establish its scope, that action is blocked. Bulk eligibility alone
does not establish that an action respects the deletion boundary.

Handlers for delayed deletion record the service-confirmed scheduled timestamp
and observed lifecycle state. They do not reschedule an already pending
resource. Certificates can require at least one day; Vault keys and vaults
can require at least seven days. The tool never waits for a multi-day period
inside one process. Later runs refresh the state, skip actions already done or
pending, and advance the graph only when OCI confirms removal. A failed or
partial bulk operation remains actionable in the report; it is not inferred
to have succeeded because the work request ended.

Before deleting a child compartment, the tool runs its available discovery
probes again and checks the compartment's resources and descendants. If OCI
rejects compartment deletion, it records the service error and returns to
discovery on the next run. It does not attempt to delete the retained parent.

## Local artifacts

A user-selected work directory contains:

- `plan.json`: latest resource map, dependency edges, depths, and coverage
  record, with a schema version and retained-parent OCID.
- `state.json`: durable action journal, work-request IDs, scheduled deletion
  timestamps, current status, and errors, keyed by stable resource identity.
- `report.txt`: regenerated human-readable deletion order and progress.

Writes to JSON files are atomic. Refreshing the report reconciles nodes by
identity and preserves `state.json`. An existing work directory tied to a
different parent is rejected. Concurrent mutation runs against one directory
are prevented. The report explains that losing these files does not restore
deleted resources and that a fresh report may recover the current OCI state
but not the full action history.

## Errors, safety, and verification

The tool exits nonzero for incomplete cleanup and distinguishes pending
deletion from actionable failures in its report. Authentication, authorization,
pagination, rate-limit, and work-request failures are recorded with enough
context to retry. Execution never invents a deletion command for an unknown
resource type and never treats an empty Search result as universal proof of an
empty compartment.

Automated tests use simulated OCI responses. They cover graph depths and
cycles, in-tree scope protection, unsupported resources and failed probes,
bulk work-request partial failures, scheduled deletion and resume, plan
refresh without losing state, and interrupted atomic writes. No automated
test performs a live deletion. Documentation includes an example discovery
run, an explicit deletion run, repeated runs after scheduled deletion, local
file retention, and the meaning of incomplete coverage.

## Source notes

- [OCI Search overview](https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/queryoverview.htm)
  describes supported resource types and permission-dependent results.
- [OCI Identity SDK reference](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/identity/client/oci.identity.IdentityClient.html)
  describes bulk-action type discovery, bulk deletion, home-region execution,
  and work-request tracking.
- [Certificate deletion](https://docs.oracle.com/en-us/iaas/Content/certificates/deleting-certificate.htm)
  and [Vault deletion](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/managingvaults_topic-To_delete_a_vault.htm)
  document minimum scheduled-deletion periods.
- [Logging Analytics entities](https://docs.oracle.com/en-us/iaas/log-analytics/doc/manage-entities.html)
  documents that deleted entities can reappear while log producers remain.
  The [user-provided example](https://karthicin.medium.com/how-to-delete-many-logging-analytics-entities-in-oci-d26bd6bafe53)
  shows SDK listing and deletion of those entities.
