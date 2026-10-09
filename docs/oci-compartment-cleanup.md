# OCI compartment-tree cleanup

This tool maps and removes supported resources in a selected compartment and its
descendants, then deletes empty descendant compartments. It retains the selected
parent. Deletion is irreversible. Review the saved report before running delete
mode, including preserved-volume and reserved-IP effects.

**These commands create local files. Preserve the entire work directory until cleanup is finished.**
You MUST preserve all created local files and the entire work directory until
cleanup is finished.

OCI has no universal resource inventory. Completion means complete for the
recorded discovery coverage, not proof that every possible OCI resource type is
absent. Unsupported resources, uncertain dependencies, failed probes and pending
deletions remain visible blockers.

## Install and authenticate

Run these commands from the repository root on macOS or Linux, using Python 3.10
or newer. This tool uses the OCI Python SDK directly and does not require the OCI
CLI. Its supported SDK minimum is 2.187.0.

```bash
python3 -m pip install -r python/requirements-compartment-cleanup.txt
python3 python/oci_compartment_cleanup.py --help
```

For API-key authentication, configure an OCI SDK configuration file, normally
`~/.oci/config`, with `user`, `fingerprint`, `tenancy`, `region`, and `key_file`.
Keep the private key outside the work directory. `--profile` selects a named
configuration profile; `--config-file` changes the file. `--bootstrap-region`
overrides the initial region. See [OCI SDK configuration](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm).

For instance-principal authentication, run on an OCI compute instance in a dynamic
group with the needed IAM policies. Run from an instance outside the cleanup
tree, and keep the work directory on storage outside the resources being
removed. An eligible in-tree runner or journal volume is still a deletion target:
removing it can stop the run or lose the history. The signer supplies tenancy and region;
`--bootstrap-region` can change the initial region. Configuration-file/profile
arguments apply to API-key authentication. See [instance principals](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm).

The identity needs permission to read the tenancy hierarchy and region
subscriptions, Search, bulk-action catalog, and each implemented service's
inventory and dependency APIs. Read-only reverse-dependency scans include visible
compartments outside the cleanup tree: those reads find external consumers and
producers that may block an in-tree action. Delete mode additionally needs each
applicable service's delete, detach, update or scheduled-deletion permissions,
plus IAM work-request reads and deletion of descendant compartments. Permissions
limited to the parent can leave those reverse scans incomplete. Dynamic-group
policies must grant these permissions to the instance's group; API-key policies
must grant them to the user's group. Removing an in-tree IAM policy may remove the
executor's own access, so policies are processed late.

For example, the official IAM resource types include `compartments` and
`tenancies` for hierarchy/subscription reads, and `policies` for policy removal.
The core families include `instance-family`, `compute-management-family`,
`virtual-network-family` and `volume-family`. Grant the relevant read access at
tenancy scope for reverse scans, and the relevant manage/update/delete access at
the target compartment scope. Descendant removal needs `manage compartments`;
IAM work-request inspection must also be authorized for the submitted compartment.
Home-region bulk calls need the same target-resource deletion permissions; catalog
availability does not grant them. See [IAM operation permissions](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/iampolicyreference.htm)
and [core service policy types](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/corepolicyreference.htm).

Service policies differ; use the [IAM policy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/policyreference.htm)
to grant the operations needed for the reviewed plan. This guide does not supply
a universal least-privilege policy. Successful lists cover resources visible to
the caller; they do not certify unchanged permissions or hidden-resource absence.

## Discover and review

Replace the example OCID with the retained parent compartment OCID. The tenancy
root cannot be the cleanup parent.

```bash
python3 python/oci_compartment_cleanup.py --report \
  --compartment-id ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth api_key --profile DEFAULT
```

Or use instance principals:

```bash
python3 python/oci_compartment_cleanup.py --report \
  --compartment-id ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth instance_principal
```

Report mode reads OCI and writes local artifacts. It discovers all subscribed
regions and the tenancy home region, queries Search, supplements it with typed
service inventories, and inspects pending schedules. It submits no OCI mutations.
A successful report exits 0 even when resources or blockers remain; a failed or
unsupported discovery probe returns 2. Read `report.txt` for dependency order,
coverage gaps, unknown methods, external relationships and progress.

An edge `A -> B` means remove A before B. Dependency depth is the longest
chain of resources waiting on this resource's removal, plus one. Greater depths
run first; this is dependency depth, distinct from compartment nesting. There is
no fixed maximum depth. Cycles and unresolved predecessors block the affected
branch. Independent safe branches can progress. An accepted asynchronous action
or elapsed scheduled timestamp does not unblock its dependent resource.

## Execute and resume

The confirmation must exactly match the retained parent used by the saved plan:

```bash
python3 python/oci_compartment_cleanup.py --delete \
  --compartment-id ocid1.compartment.oc1..example \
  --confirm-parent ocid1.compartment.oc1..example \
  --work-dir .oci-cleanup/example --auth api_key --profile DEFAULT
```

Use the same authentication flags as the report command. For instance principals,
replace `--auth api_key --profile DEFAULT` with `--auth instance_principal`.
There is no default mode; both missing mode and conflicting modes are rejected
before authentication. Delete mode requires an existing valid plan and journal.

The command validates the authenticated tenancy, saved scope and fresh identity,
relationships and cascade membership before each mutation. It executes only saved
identities. Newly discovered resources or changed hierarchy require a new report.
It never deletes the retained parent or external resources. Child compartments
are deleted bottom-up after available probes confirm their resources and
children have disappeared.

Repeat the **identical delete command** after pending operations or schedules
mature. The default `--wait-seconds 300` bounds asynchronous polling in one run;
any override must be positive and finite. The process does not wait for days.
Schedules use the minimum service period plus a five-minute submission margin:

| Resource | Earliest requested deletion |
| --- | --- |
| Certificate | 1 day plus margin |
| Certificate authority | 7 days plus margin |
| Vault or key | 7 days plus margin |
| Secret | 1 day plus margin |

The service-confirmed timestamp, not the requested time, appears in the report.
An already pending resource is inspected without rescheduling. For example:

```text
Cannot finish cleanup: <resource OCID> is pending deletion until <UTC timestamp>; rerun after that time and verify its removal.
```

A schedule can remain pending after that date. If the current read has no date,
the report says the UTC schedule is unknown and preserves the previous date only
in history. An asynchronous operation without a schedule is displayed as in
progress. The next known revisit time is an earliest known condition, not a
promise of completion. See [certificate deletion](https://docs.oracle.com/en-us/iaas/Content/certificates/deleting-certificate.htm),
[CA deletion](https://docs.oracle.com/en-us/iaas/Content/certificates/deleting-certificate-authority.htm),
[vault deletion](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/managingvaults_topic-To_delete_a_vault.htm),
and [secret deletion](https://docs.oracle.com/en-us/iaas/Content/secret-management/Tasks/delete-secret.htm).

## Preserve the work directory

Each run prints the absolute artifact paths and preservation instruction.

| File | Purpose |
| --- | --- |
| `plan.json` | Versioned current resource identities, scope, graph, methods, depths and discovery coverage |
| `state.json` | Durable action journal, immutable submission arguments/tokens, shared bulk attempts, work-request evidence, schedules, failures, terminal observations and proof invalidations |
| `report.txt` | Readable dependency order, progress, pending timestamps and coverage gaps |
| `.lock` | Shared exclusive-lock file; retain it with the other files |

JSON replacement is atomic; the directory is locked from journal load through
execution or report refresh. Local write failure stops further mutations.
Preserve the **entire directory**, including `.lock`, all history and any backup
you make. Never edit or delete records to force completion. Missing, malformed,
mismatched or linked artifacts are fatal rather than replaced with an empty
journal. An interrupted initial run that leaves an incomplete pair also requires
operator attention; do not continue deletion with a reconstructed empty state.

Rerunning `--report` in the same directory reconciles old identities before
refreshing the current map, keeps old attempts and shared bulk records, and can
include newly discovered resources or the current hierarchy. It invalidates old
completion evidence when fresh reads contradict it. Ambiguous submissions are
reconciled before another action; refreshing the map does not authorize blind
replay. Removed identities retain journal records. Unresolved invalidated history
can keep a later delete result incomplete even when its identity is absent from
the refreshed map.

A fresh report can recover the current map after losing local files, but **cannot
recover lost action history**, original arguments, retry tokens or work-request
IDs. Loss of the directory does not restore deleted resources.

## Implemented coverage and blockers

All actions require fresh typed identity and scope evidence. The table describes
implemented contracts, not a promise that every resource in these services is
eligible.

| Area | Discovery, dependencies and actions | Explicit limits / blockers |
| --- | --- | --- |
| IAM and Search | Tenancy hierarchy, subscribed regions, per-compartment/region Search, runtime bulk catalog; descendant compartment deletion; in-tree policies deleted late | Search-only identities lack authoritative dependency proof; unknown resource types remain unresolved; retained parent, root and external policies persist |
| Compute | Instances, VNIC/boot/block attachments; VNIC/private/public IP association scans; instance-pool and OKE producer reads; instance termination and eligible attachment detach | Managed instances, unreadable or external cascade members, unsupported IP lifetimes or unknown associations block; arbitrary external automation is not inventoried |
| Block Storage | Volumes, boot volumes and their backups; all visible attachments; encryption-key references; conditional direct deletion | Volume groups/group backups, replicas and unsupported retention/protection remain unresolved; external consumers block deletion |
| Networking | VCN, subnet, Internet/NAT/service/local-peering gateways, route tables, security lists, DHCP options, NSGs; reverse VNIC/LB/DNS/route references; explicit route preparation and verified default/DNS cascades | Resolver endpoints, customer zones, unsupported resolver configurations, VLAN/DRG attachments or unresolved cross-compartment effects block; default VCN components are not independent delete targets |
| LB and NLB | Typed configuration, subnet/NSG/TLS references; direct deletion and exact service work-request reconciliation; owner configuration cascade | External backend servers/subnets are retained references; unknown configuration or unproved cascade effects block |
| Object Storage | Canonical namespace and bucket identity; all objects/versions/markers, uploads, PARs, lifecycle/retention/replication records; exact-version deletion, eligible preparations and bucket deletion | Active locked/indefinite retention, unknown retention eligibility, inbound/outbound replication and read-only buckets block; replication is not silently detached |
| Certificates | Certificates, CAs, CA bundles, issuer/consumer relationships; scheduled certificate/CA deletion and immediate bundle deletion | External/unreadable issued children or consumers and CRL configuration effects block |
| Vault, keys and secrets | Fresh validated KMS endpoints, visible full-tenancy key membership/counts and typed consumers; proven vault-key cascades, individual schedules, secret regional replication evidence | Unknown endpoints/counts, EXTERNAL vault cascade/count proof, unresolved replica/cascade identity or external consumers block; purge absence alone is not proof |
| Logging Analytics | Namespaces, entities, object collection rules, EM bridges and service connectors; exact object-rule entity edges; direct deletion after verified checks | Manual `NONE` entities with resolved associations/producers can be eligible; automatic SCH/EM per-entity mapping remains unsupported; no native entity bulk deletion |

Standalone instance termination explicitly preserves boot volumes and
launch-created data volumes. An external volume is preserved and detached;
in-tree volumes are independently deleted later when eligible. Matched reserved
public IPs are retained and automatically unassigned. These effects are disclosed
in the report. External or unreadable VNICs and ephemeral-IP cascade members
block termination. Owner ETags protect owner revision, not an atomic snapshot of
all associated resources; concurrent moves, creation and changed visibility can
still leave a branch incomplete.

A missing GET (`NotAuthorizedOrNotFound`), empty Search/list, accepted delete,
finished work request without exact item evidence, or elapsed deadline alone
never proves removal. Saved positive terminal lifecycle or exact correlated
operation evidence plus fresh supported inventory is required. Captured positive
terminal proofs have narrow purge corroboration for certificates, CA bundles,
empty unreplicated standard vaults and unreplicated secrets, among other typed
handlers. KMS keys whose verified endpoint becomes unavailable, nonempty vault
cascades, uncertain replicas and purged resources without positive proof can
remain unresolved. Individually verified EXTERNAL key references can be scheduled
for deletion from OCI; external key material is retained, as documented for
[external key references](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/ekms_deleting_key_references.htm).
EXTERNAL vault cascades
remain blocked when complete membership/count evidence is unavailable.

### Bulk operations

IAM bulk actions run in the tenancy **home region**, for one compartment at a
time. Only known eligible direct Block Storage/networking types whose exact
same-case candidate alias appears in a fresh runtime catalog with an **empty
required metadata set** qualify. Saved catalog hints cannot select a method.
Instances, schedules, policies, child compartments, LB/NLB, unknown types,
blocked nodes and cascade/preparation actions use their explicit contracts or
remain blocked. IAM groups are conservatively capped at 20 by this tool; no
published numeric IAM maximum has been verified. IAM bulk lacks an ETag
precondition, and work-request completion requires exact resource-level evidence,
not just overall success. Failed items retain separate outcomes and history.

Object Storage has a real [server batch API](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/batch-delete-objects.htm)
for up to 1,000 explicit names in one bucket. This tool uses it only with fresh
`Disabled` versioning, no retained history/markers, unchanged bucket identity and
an exact HEAD ETag per object. Per-item deleted results are recorded and verified;
versions/markers use individual exact-version operations. SDK concurrency or CLI
`bulk-delete` loops issue individual requests and are different from this server
batch. The batch lacks a bucket versioning precondition: detected drift requires
refresh/reconciliation.

### Logging Analytics producer ordering

Entities can reappear when new logs arrive through Service Connector Hub, Object
Storage collection or EM bridge uploads. Remove verified producers before their
entities, then rediscover. Oracle documents this behavior in [Manage Entities](https://docs.oracle.com/en-us/iaas/log-analytics/doc/manage-entities.html).

The implemented exact producer link is `rule.entity_id == entity.id` for an
object collection rule. Free-text creation details, a shared log group, source
name or destination compartment do not prove an SCH/EM producer-to-entity link.
Automatic entities with those unresolved mappings remain blocked; `NONE` manual
entities are eligible only after supported producer and association checks.
External producers block affected entity deletion. Forced association deletion
is not enabled. EM bridge deletion explicitly preserves entities
(`is_delete_entities=False`); referenced external buckets, streams and log groups
are retained. Deleting collection rules does not remove already ingested logs.

The [article about deleting many Logging Analytics entities](https://karthicin.medium.com/how-to-delete-many-logging-analytics-entities-in-oci-d26bd6bafe53)
is background context supplied for this project; its direct access returned 403
during the audit and its claims are not used as API contracts. This tool uses
singular entity deletes and does not claim a native Logging Analytics bulk API.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Report generated with successful recorded probes, or deletion completed for recorded discovery coverage |
| `2` | Report has failed/unsupported probes, or deletion remains incomplete because resources, pending actions, gaps or unresolved evidence remain |
| `1` | Fatal authentication, scope, schema, local-write or interrupted-run failure |

Invalid command-line arguments return `2` before constructing clients. Help
returns `0` without loading credentials. A successful deletion prints:

```text
Cleanup complete for the recorded discovery coverage; retained parent: <OCID>.
```
