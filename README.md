# OCI script collection

Utilities for OCI resource inventory, service-limit lookup, VM reporting, IAM
policy analysis, bulk tag updates, and Linux 9 SSH recovery.

## Prerequisites

All tools expect an authenticated and configured [OCI CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm)
and an identity with permission to read or modify the resources involved.

- `python3` is required by every Python tool and by the policy hierarchy tool.
- `jq` is required by the Bash tools.
- The OCI CLI configuration defaults to `~/.oci/config` and the `DEFAULT`
  profile unless the tool or environment specifies otherwise.
- CSV, TSV, generated bulk-tag JSON, Python caches, local environments, and
  tests are intentionally excluded from Git by `.gitignore`.

Make the scripts executable after cloning if the filesystem did not preserve
their modes:

```bash
chmod +x bash/*.sh python/*.py
```

## Tool summary

| Tool | Purpose | Changes OCI resources? |
| --- | --- | --- |
| `python/oci_tenancy_inventory.py` | Inventory searchable resources across all subscribed regions and optionally extract tags | No |
| `python/oci_limit_lookup.py` | Look up service limits, usage, and available capacity | No |
| `bash/list_all_vms_in_tenancy.sh` | List VM details across all subscribed regions | No |
| `bash/count_policy_hierarchy_statements.sh` | Count IAM policy statements along every compartment path | No |
| `python/bulk_edit_tags_single_compartment.py` | Apply a defined tag to supported resources in one compartment | **Yes** |
| `oci_linux9_opc_ssh_recovery.md` | Recovery guide for the `opc` user's SSH access | Procedural guide |

## Tenancy resource inventory

`python/oci_tenancy_inventory.py` uses OCI Resource Search in every subscribed
region. The CSV contains:

- `resource_ocid`
- `compartment_id`
- `resource_type`
- `region`
- `lifecycle_state`
- `metadata_json`
- Up to two tag columns selected during collection

OCI Resource Search only returns indexed resources visible to the authenticated
identity. Regionless OCI resources are reported as `GLOBAL`.

### Interactive menu

Running without arguments offers collection or tag extraction:

```bash
python3 python/oci_tenancy_inventory.py
```

### Collect resources interactively

This prompts for the tenancy OCID, output path, and up to two tag selectors:

```bash
python3 python/oci_tenancy_inventory.py collect
```

Valid tag selector formats are:

```text
freeform:Owner
defined:Operations.CostCenter
system:orcl-cloud.free-tier-retain
```

### Collect with command-line values

```bash
python3 python/oci_tenancy_inventory.py collect \
  --tenancy-id ocid1.tenancy.oc1..example \
  --tag freeform:Owner \
  --tag defined:Operations.CostCenter \
  --output oci_tenancy_inventory.csv
```

Two selectors can also be comma-separated:

```bash
python3 python/oci_tenancy_inventory.py collect \
  --tenancy-id ocid1.tenancy.oc1..example \
  --tag 'freeform:Owner,defined:Operations.CostCenter' \
  --output oci_tenancy_inventory.csv
```

### Use another OCI profile or config file

```bash
python3 python/oci_tenancy_inventory.py collect \
  --profile PRODUCTION \
  --config-file ~/.oci/config \
  --bootstrap-region eu-frankfurt-1
```

### Use instance-principal authentication

```bash
python3 python/oci_tenancy_inventory.py collect \
  --auth instance_principal
```

### Recreate an existing inventory with selected tag columns

The original `metadata_json` column is retained by default:

```bash
python3 python/oci_tenancy_inventory.py extract-tags \
  --input oci_tenancy_inventory.csv \
  --tag freeform:Owner \
  --tag defined:Operations.CostCenter \
  --output inventory_with_tags.csv
```

There is no two-tag limit when reprocessing an existing CSV. Use
`--drop-metadata` to omit the JSON metadata column from the new file:

```bash
python3 python/oci_tenancy_inventory.py extract-tags \
  --input oci_tenancy_inventory.csv \
  --tag freeform:Owner \
  --tag freeform:Environment \
  --tag defined:Operations.CostCenter \
  --drop-metadata \
  --output inventory_tags_only.csv
```

### Inventory options

`collect` supports:

| Option | Meaning |
| --- | --- |
| `--tenancy-id OCID` | Tenancy OCID; prompted when omitted |
| `-o, --output PATH` | Destination CSV; prompted when omitted |
| `--tag SELECTOR` | Tag to extract; repeat or comma-separate, maximum two |
| `--profile NAME` | OCI CLI profile |
| `--config-file PATH` | OCI CLI configuration file |
| `--auth MODE` | OCI CLI auth mode, such as `instance_principal` or `security_token` |
| `--bootstrap-region REGION` | Region used to retrieve the subscribed-region list |

`extract-tags` supports:

| Option | Meaning |
| --- | --- |
| `-i, --input PATH` | Inventory CSV produced by `collect`; prompted when omitted |
| `-o, --output PATH` | Destination CSV; prompted when omitted |
| `--tag SELECTOR` | Tag to extract; repeat or comma-separate |
| `--drop-metadata` | Exclude `metadata_json` from the resulting CSV |

## OCI service-limit lookup

`python/oci_limit_lookup.py` reports limit definitions, configured values,
usage, available capacity, scope, availability domain, and effective quota when
the OCI Limits API exposes that information.

### Interactive lookup

```bash
python3 python/oci_limit_lookup.py
```

The interactive flow prompts for the compartment, region, service, limit search
text, scope, availability domain, and output format. Services can be selected by
number or filtered by typing part of their name or description.

### Look up one limit

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --service-name compute \
  --limit-name standard-a1-core-regional-count \
  --output-format table
```

### Search by partial limit name

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --limit-name standard-a1 \
  --output-format csv \
  --output-file limits.csv
```

### Look up multiple limits

Repeat `--limit-name`:

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --limit-name standard-e6-core-count \
  --limit-name standard-e6-memory-count \
  --output-format table
```

Or use comma-separated search values:

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --limit-name 'standard-e6-core-count,standard-e6-memory-count' \
  --output-format json \
  --output-file limits.json
```

### Query an availability-domain-scoped limit

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --service-name compute \
  --limit-name vm-standard-e5-flex-count \
  --scope-type AD \
  --availability-domain 'example:EU-FRANKFURT-1-AD-1' \
  --output-format table
```

### Non-interactive use

`--compartment-id` and at least one `--limit-name` are required when prompting
is disabled:

```bash
python3 python/oci_limit_lookup.py \
  --non-interactive \
  --compartment-id ocid1.tenancy.oc1..example \
  --limit-name standard-a1 \
  --region eu-frankfurt-1 \
  --output-format json
```

### Limit lookup options

| Option | Meaning |
| --- | --- |
| `-c, --compartment-id OCID` | Tenancy/root compartment or child compartment OCID |
| `--service-name NAME` | OCI Limits service name, such as `compute` |
| `--limit-name VALUE` | Limit name or partial search text; repeat or comma-separate |
| `--region REGION` | OCI region; otherwise use the OCI CLI default |
| `--availability-domain AD` | Availability domain for AD-scoped limits |
| `--external-location LOCATION` | External cloud location where applicable |
| `--scope-type AD\|GLOBAL\|REGION` | Limit scope filter |
| `--subscription-id OCID` | Subscription OCID assigned to the tenant |
| `-f, --output-format table\|csv\|json` | Output format |
| `--output-file PATH` | Write output to a file rather than standard output |
| `--profile NAME` | OCI CLI profile |
| `--config-file PATH` | OCI CLI configuration file |
| `--auth MODE` | OCI CLI auth mode, such as `instance_principal` or `security_token` |
| `--non-interactive` | Fail instead of prompting for missing required inputs |

## List all VMs in a tenancy

`bash/list_all_vms_in_tenancy.sh` searches each subscribed region and reports
the region, display name, instance OCID, shape, first attached VNIC private IP,
and image OCID.

Syntax:

```text
bash/list_all_vms_in_tenancy.sh TENANCY_OCID [json|csv]
```

JSON is the default:

```bash
bash/list_all_vms_in_tenancy.sh \
  ocid1.tenancy.oc1..example \
  > all_instances.json
```

CSV output:

```bash
bash/list_all_vms_in_tenancy.sh \
  ocid1.tenancy.oc1..example \
  csv \
  > all_instances.csv
```

Progress and region diagnostics go to standard error, so redirecting standard
output produces a clean report. This script uses the OCI CLI's currently active
configuration and does not provide profile or auth command-line options.

## Count IAM policy statements through the compartment hierarchy

`bash/count_policy_hierarchy_statements.sh` counts active policy statements
attached directly to each accessible active compartment, adds the counts along
each root-to-compartment path, and classifies each path as `OK`, `WARNING`, or
`BREACH`.

The defaults are:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `OCI_TENANCY` | Auto-detected | Tenancy OCID |
| `WARNING_THRESHOLD` | `450` | Path count at which status becomes `WARNING` |
| `BREACH_THRESHOLD` | `500` | Path count at which status becomes `BREACH` |
| `KEEP_TMPDIR` | `true` | Keep intermediate JSON and TSV files for inspection |

### Use the configured tenancy

```bash
bash/count_policy_hierarchy_statements.sh
```

### Specify the tenancy explicitly

```bash
OCI_TENANCY=ocid1.tenancy.oc1..example \
  bash/count_policy_hierarchy_statements.sh
```

### Change thresholds and remove temporary files automatically

```bash
OCI_TENANCY=ocid1.tenancy.oc1..example \
WARNING_THRESHOLD=400 \
BREACH_THRESHOLD=500 \
KEEP_TMPDIR=false \
  bash/count_policy_hierarchy_statements.sh
```

### Save the TSV report

```bash
OCI_TENANCY=ocid1.tenancy.oc1..example \
KEEP_TMPDIR=false \
  bash/count_policy_hierarchy_statements.sh \
  > policy_hierarchy_statement_counts.tsv
```

Progress and temporary-file paths are written to standard error. The TSV report
is written to standard output and sorted by descending path statement count.

## Bulk-edit defined tags in one compartment

> **Warning:** `python/bulk_edit_tags_single_compartment.py` changes tags on OCI
> resources. Review the compartment, namespace, key, value, and generated JSON
> payloads before using it in a production tenancy.

The tool is interactive and has no command-line options:

```bash
python3 python/bulk_edit_tags_single_compartment.py
```

It prompts for:

1. Compartment OCID
2. Defined-tag namespace
3. Defined-tag key
4. Defined-tag value

It then:

1. Retrieves the resource types supported by OCI bulk tag editing.
2. Searches the selected compartment with pagination.
3. Excludes unsupported resource types.
4. Writes `resources.json` and `bulkedit.json` in the current directory.
5. Submits an asynchronous OCI bulk tag edit request.

The command prints a resource-type summary and, when OCI returns one, the work
request OCID. The operation applies an `ADD_OR_SET` defined-tag update to all
matching supported resources in the compartment.

## Linux 9 `opc` SSH recovery

See [`oci_linux9_opc_ssh_recovery.md`](oci_linux9_opc_ssh_recovery.md) for the
step-by-step recovery procedure when the `opc` user's SSH key or access needs to
be restored on an OCI Linux 9 instance.

## Help commands

```bash
python3 python/oci_tenancy_inventory.py --help
python3 python/oci_tenancy_inventory.py collect --help
python3 python/oci_tenancy_inventory.py extract-tags --help
python3 python/oci_limit_lookup.py --help
```
