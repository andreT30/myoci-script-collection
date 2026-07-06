# myoci-script-collection

## OCI limit lookup

Interactive Python helper:

```bash
python3 python/oci_limit_lookup.py
```

In interactive mode, the script loads available OCI Limits services and shows a
numbered list. Pick a service by number, type part of a service name/description
to filter the list, or press Enter to search across all service definitions.

Example direct calls:

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --service-name compute \
  --limit-name standard-a1-core-regional-count \
  --output-format table
```

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --limit-name standard-a1 \
  --output-format csv \
  --output-file limits.csv
```

Multiple limits can be searched in one run:

```bash
python3 python/oci_limit_lookup.py \
  --compartment-id ocid1.tenancy.oc1..example \
  --region eu-frankfurt-1 \
  --limit-name standard-e6-core-count \
  --limit-name standard-e6-memory-count \
  --output-format table
```

You can also pass comma-separated values to `--limit-name` or at the interactive
prompt.

Outputs can be `table`, `csv`, or `json`. For `csv` and `json`, use
`--output-file` or provide a path when prompted; blank prints to the terminal.
For AD-scoped limits, pass `--availability-domain` or provide it when prompted.
The script uses the OCI CLI configuration/profile you already have, and supports
`--profile`, `--config-file`, and OCI CLI `--auth` modes such as
`instance_principal` or `security_token`.
