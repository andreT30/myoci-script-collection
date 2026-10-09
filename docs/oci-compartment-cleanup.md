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

## Get the files onto your workstation

Use macOS or Linux with Python 3.10 or newer. The cleanup tool consists of an
entry script and a Python package; keep them together in the layout shown below.

### Windows workstations

Native Windows Python is not supported: the tool's workspace locking and durable
file writes require macOS or Linux filesystem APIs. On Windows, use a Linux
distribution in **WSL 2** with Python 3.10 or newer. See
[Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).

If WSL is not installed, run this in an administrator PowerShell window and
complete the restart and Linux user setup described in that guide:

```powershell
wsl --install
```

Then open the Linux distribution's terminal. Run the remaining commands in that
terminal, including repository download, environment creation, installation,
authentication, and cleanup. Start in your Linux home directory with `cd ~` so
the clone is stored there. Keep the repository, environment, and cleanup work
directory in the [WSL Linux filesystem](https://learn.microsoft.com/en-us/windows/wsl/filesystems),
such as `/home/<user>/`, rather than under `/mnt/c/`. The `~/.venvs/` and
`~/.oci/config` paths below refer to your Linux home directory inside WSL.

### Download the tool

> **OCI Cloud Shell (9 October 2026):** The Cloud Shell session used when writing
> this note ran Python 3.9. With that version, the SDK installation succeeds but
> this tool fails at startup, including `--help`, with
> `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`.
> Check your session's version; if it is below 3.10, run the tool on a local
> workstation with Python 3.10 or newer.

The simplest option is to clone the repository and enter its root directory:

```bash
git clone https://github.com/andreT30/myoci-script-collection.git
cd myoci-script-collection
```

If you do not use Git, download the repository using **Code → Download ZIP** on
GitHub, extract it, and open a terminal in the extracted repository directory.

To copy only the cleanup tool instead, create a local directory and copy these
items into it, preserving the `python/` directory layout:

```text
myoci-script-collection/
└── python/
    ├── oci_compartment_cleanup.py
    ├── requirements-compartment-cleanup.txt
    └── compartment_cleanup/       (copy this entire directory)
        ├── __init__.py
        ├── cli.py
        ├── ...                    (keep all other Python modules)
        └── handlers/              (keep all service handlers)
```

The other collection tools are optional for compartment cleanup. Copying only
`oci_compartment_cleanup.py` is insufficient: it imports the accompanying
`compartment_cleanup/` package, including `__init__.py` and every service handler.
Keep a copy of this guide for reference.

Run all commands below from the directory containing `python/`, whether you
cloned the repository, extracted the ZIP, or copied the minimum files. The
example `.oci-cleanup/example` work directory will be created beneath that
directory; preserve it across report and deletion runs until cleanup finishes.

## Install and authenticate

This tool uses the OCI Python SDK directly and does not require the OCI
CLI. Its supported SDK minimum is 2.187.0.

### Create a virtual environment

Use a virtual environment to install the SDK separately from your system Python.
This also handles the `error: externally-managed-environment` message that can
appear with Homebrew Python on macOS or a package-managed Python on Linux.
See the [Python packaging guidance](https://packaging.python.org/en/latest/specifications/externally-managed-environments/).

From the directory containing `python/`, check that `python3 --version` reports
3.10 or newer, then create and activate the environment. The commands below
place it in `~/.venvs/oci-compartment-cleanup`, outside the downloaded repository:

```bash
python3 --version
python3 -m venv ~/.venvs/oci-compartment-cleanup
source ~/.venvs/oci-compartment-cleanup/bin/activate
python3 --version
python3 -m pip install -r python/requirements-compartment-cleanup.txt
python3 python/oci_compartment_cleanup.py --help
```

If your supported interpreter has a versioned name, such as `python3.11`, use
`python3.11 --version` and
`python3.11 -m venv ~/.venvs/oci-compartment-cleanup` for the first two commands.
After activation, `python3` uses the environment's interpreter. Creating a
virtual environment with Python 3.9 does not upgrade it to Python 3.10.

Keep the environment active when running the report and delete commands below.
In each new terminal session, return to the same directory and reactivate it:

```bash
source ~/.venvs/oci-compartment-cleanup/bin/activate
```

Install the requirements once when creating the environment; later cleanup runs
can reuse it. To leave the environment when you are done with the terminal session:

```bash
deactivate
```

The locations have different purposes:

- The downloaded repository contains the scripts. Run the tool commands from
  its root directory, which contains `python/`.
- `~/.venvs/oci-compartment-cleanup` contains the environment and installed
  packages. Activating it does not change your working directory.
- `.oci-cleanup/example`, used in the examples below, is created under the
  repository root and contains the cleanup plan and journal. Preserve the entire
  work directory until cleanup finishes, including between terminal sessions.

### Authentication and permissions

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
subscriptions and Search. Delete mode additionally needs targeted resource and
relationship reads, the bulk-action catalog where applicable, each service's
delete, detach, update or scheduled-deletion permissions, and descendant
compartment deletion. A rejected deletion may require reads of an external
consumer to explain the dependency. External resources are retained. Exhaustive
reports require broader inventory and reverse-dependency read permissions.
Removing an in-tree IAM policy may remove the executor's own access, so policies
are processed late.

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

Report mode reads OCI and writes local artifacts. It first discovers the
compartment tree and subscribed regions, then queries Search for the whole tree
in each region, reading every result page. Trees with more than 50 compartments
use batches of up to 50 compartments per query.

The default report saves the metadata returned by Search, including original
resource types, names, identifiers, lifecycle states, tags and additional details
when present. It maps supported types to fixed deletion methods without scanning
every service or predicting every dependency. Previously recorded resources and
pending scheduled deletions remain in the journal when Search omits them. Known
scheduled resources receive targeted reads to refresh their service-confirmed dates.

Search can omit unindexed resources and recent changes. This report does not
establish that the compartment is empty. Unknown deletion methods and failed
Search queries are reported explicitly. For a broader, slower inventory of all
implemented services, add `--exhaustive-discovery` to the report command. This is
never enabled automatically.

Before scanning, the command summarizes the operation and asks for **`YES` in
uppercase**. Confirmation requires an interactive terminal; piped input and
noninteractive execution do not bypass it. Report mode submits no OCI mutations.

The terminal shows scan phases and a compact summary: resource counts by type and
region, coverage gaps, unsupported methods, and pending deletions with names and
UTC dates. The absolute paths of the saved files appear at the end. Add
`--verbose` for individual SDK calls and the detailed report in the terminal.
`report.txt` always contains the full details.

A successful report exits 0 even when resources or blockers remain; failed
inventory probes return 2. Plan and report files are saved after discovery. An
empty work directory during the first scan does not mean the process is idle.
Press Ctrl+C to interrupt, then rerun with the same work directory.

An observed edge `A -> B` means remove A before B. The default report starts with
compartment containment. Further dependency edges are recorded when a service
rejects deletion and a targeted investigation corroborates the relationship.
Dependency depth is distinct from compartment nesting; the initial map does not
claim a complete dependency order. Pending deletion does not count as removal.

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

Deletion requires **two separate uppercase `YES` confirmations**. The first
summarizes the requested operation before authentication. The second shows the
authenticated scope and saved inventory before any deletion. `--confirm-parent`
binds the command to the saved parent; it does not replace either prompt.

Before each action, the tool checks the target's live identity, scope, revision
and known effects using a fixed service contract. It retains the parent and
external resources. Descendant compartments are attempted after their known
contents and child compartments have been confirmed removed.

When OCI rejects deletion because of dependencies, the tool displays the actual
service error and immediately investigates that target. You can **handle**, **skip**
or **stop**. Corroborated in-tree dependencies can be processed before retrying the
original target. Any new deletion targets require another exact `YES` after their
identities are displayed. Unsupported, external or unverified dependencies remain
manual actions. A timeout or uncertain response requires reconciliation before
another submission.

Eligible volume resources use OCI bulk deletion with per-member outcomes. Eligible
bucket objects use batch deletion after the rejected bucket's contents are mapped
and approved. A failed member does not authorize replay of successful members.

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

Rerunning `--report` in the same directory refreshes the current map, preserves
old identities, attempts and shared bulk records, and can
include newly discovered resources or the current hierarchy. It invalidates old
completion evidence when fresh reads contradict it. Ambiguous submissions are
reconciled before another action; refreshing the map does not authorize blind
replay. Removed identities retain journal records. Unresolved invalidated history
can keep a later delete result incomplete even when its identity is absent from
the refreshed map.

A fresh report can recover the current map after losing local files, but **cannot
recover lost action history**, original arguments, retry tokens or work-request
IDs. Loss of the directory does not restore deleted resources.

## Supported actions and remaining blockers

Search can return types without a supported deletion contract. These remain
visible in the report and require manual service action. Live checks can also
block a supported type because of retention, replication, unknown ownership,
managed producers, external consumers or uncertain completion evidence.

Implemented contracts cover selected Compute, Block Storage, network, load
balancer, Object Storage, certificate, vault/key/secret and Logging Analytics
resources, plus IAM policies and descendant compartments. The tool uses fixed
SDK contracts; Search metadata cannot select arbitrary methods or endpoints.

Instance termination preserves boot and launch-created data volumes; eligible
in-tree volumes are separate targets. Reserved IP and owner-managed default
network effects must be corroborated and are disclosed before submission.
Bucket retention and replication protections remain enforced. Certificate and
vault purge absence alone does not prove completion.

Concurrent creation, moves and visibility changes can leave cleanup incomplete.
Run another report when the inventory changes, and preserve the work directory
through every report and delete run.
