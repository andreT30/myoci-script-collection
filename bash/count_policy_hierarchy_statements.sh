#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Count OCI IAM policy statements across compartment hierarchy paths.
#
# This calculates the aggregate policy statement count from:
#   ROOT tenancy compartment
#   + parent compartments
#   + child compartments
#   + each target compartment
#
# It helps detect paths approaching or exceeding the OCI 500-statement limit.
# -----------------------------------------------------------------------------

KEEP_TMPDIR="${KEEP_TMPDIR:-true}"
WARNING_THRESHOLD="${WARNING_THRESHOLD:-450}"
BREACH_THRESHOLD="${BREACH_THRESHOLD:-500}"

TENANCY_OCID="${OCI_TENANCY:-}"

if [ -z "$TENANCY_OCID" ]; then
  TENANCY_OCID="$(oci iam region-subscription list \
    --query 'data[0]."tenancy-id"' \
    --raw-output 2>/dev/null || true)"
fi

if [ -z "$TENANCY_OCID" ] || [ "$TENANCY_OCID" = "null" ]; then
  echo "ERROR: Could not determine tenancy OCID." >&2
  echo "Set it first, for example:" >&2
  echo "  export OCI_TENANCY=ocid1.tenancy.oc1..xxxxx" >&2
  exit 1
fi

command -v oci >/dev/null 2>&1 || {
  echo "ERROR: oci CLI not found on PATH." >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || {
  echo "ERROR: jq not found on PATH." >&2
  echo "Install it with:" >&2
  echo "  brew install jq" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 not found on PATH." >&2
  exit 1
}

TMPDIR="$(mktemp -d)"
COMPARTMENTS_JSON="$TMPDIR/compartments.json"
POLICY_COUNTS_TSV="$TMPDIR/policy_counts.tsv"
RESULTS_TSV="$TMPDIR/policy_hierarchy_statement_counts.tsv"

echo "TMPDIR=$TMPDIR" >&2

if [ "$KEEP_TMPDIR" != "true" ]; then
  trap 'rm -rf "$TMPDIR"' EXIT
else
  echo "Keeping TMPDIR for inspection. Delete it manually when done." >&2
fi

echo "Tenancy OCID: $TENANCY_OCID" >&2
echo "Fetching active compartments..." >&2

oci iam compartment list \
  --compartment-id "$TENANCY_OCID" \
  --compartment-id-in-subtree true \
  --access-level ACCESSIBLE \
  --all \
  --lifecycle-state ACTIVE \
  --output json > "$COMPARTMENTS_JSON"

compartment_count="$(jq '.data | length' "$COMPARTMENTS_JSON")"
echo "Active child compartments found: $compartment_count" >&2

echo "Counting active policy statements directly attached to each compartment..." >&2

: > "$POLICY_COUNTS_TSV"

root_count="$(
  oci iam policy list \
    --compartment-id "$TENANCY_OCID" \
    --all \
    --lifecycle-state ACTIVE \
    --query 'sum(data[*].length(statements))' \
    --raw-output
)"

if [ -z "$root_count" ] || [ "$root_count" = "null" ]; then
  root_count="0"
fi

printf "%s\t%s\t%s\t%s\n" "$TENANCY_OCID" "" "ROOT" "$root_count" >> "$POLICY_COUNTS_TSV"

i=0

jq -r '.data[] | [.id, ."compartment-id", .name] | @tsv' "$COMPARTMENTS_JSON" |
while IFS=$'\t' read -r cid parent_id name; do
  i=$((i + 1))
  echo "[$i/$compartment_count] Counting policies for: $name" >&2

  count="$(
    oci iam policy list \
      --compartment-id "$cid" \
      --all \
      --lifecycle-state ACTIVE \
      --query 'sum(data[*].length(statements))' \
      --raw-output
  )"

  if [ -z "$count" ] || [ "$count" = "null" ]; then
    count="0"
  fi

  printf "%s\t%s\t%s\t%s\n" "$cid" "$parent_id" "$name" "$count" >> "$POLICY_COUNTS_TSV"
done

echo "Computing hierarchy path aggregates..." >&2

python3 - "$TENANCY_OCID" "$POLICY_COUNTS_TSV" "$WARNING_THRESHOLD" "$BREACH_THRESHOLD" > "$RESULTS_TSV" <<'PY'
import sys
from collections import defaultdict

tenancy_ocid = sys.argv[1]
counts_tsv = sys.argv[2]
warning_threshold = int(sys.argv[3])
breach_threshold = int(sys.argv[4])

nodes = {}
children = defaultdict(list)

with open(counts_tsv, "r", encoding="utf-8") as f:
    for raw_line in f:
        line = raw_line.rstrip("\n")
        if not line:
            continue

        parts = line.split("\t")

        if len(parts) != 4:
            print(f"WARNING: Skipping malformed line: {line}", file=sys.stderr)
            continue

        cid, parent_id, name, local_count = parts

        try:
            local_count_int = int(local_count)
        except ValueError:
            local_count_int = 0

        nodes[cid] = {
            "id": cid,
            "parent_id": parent_id,
            "name": name,
            "local_count": local_count_int,
        }

        if parent_id:
            children[parent_id].append(cid)

if tenancy_ocid not in nodes:
    print(f"ERROR: Tenancy/root node not found: {tenancy_ocid}", file=sys.stderr)
    sys.exit(1)

print(
    "STATUS\tPATH_STATEMENT_COUNT\tLOCAL_STATEMENT_COUNT\tCOMPARTMENT_PATH\tCOMPARTMENT_OCID"
)

results = []

def status_for(total):
    if total >= breach_threshold:
        return "BREACH"
    if total >= warning_threshold:
        return "WARNING"
    return "OK"

def walk(cid, path, running_total):
    node = nodes[cid]
    new_path = path + [node["name"]]
    new_total = running_total + node["local_count"]

    results.append(
        (
            status_for(new_total),
            new_total,
            node["local_count"],
            " / ".join(new_path),
            cid,
        )
    )

    for child_id in children.get(cid, []):
        walk(child_id, new_path, new_total)

walk(tenancy_ocid, [], 0)

for status, path_count, local_count, path, cid in sorted(
    results,
    key=lambda row: row[1],
    reverse=True,
):
    print(f"{status}\t{path_count}\t{local_count}\t{path}\t{cid}")
PY

cat "$RESULTS_TSV"

echo "" >&2
echo "Done." >&2
echo "Intermediate files:" >&2
echo "  Compartments JSON: $COMPARTMENTS_JSON" >&2
echo "  Local policy counts TSV: $POLICY_COUNTS_TSV" >&2
echo "  Final results TSV: $RESULTS_TSV" >&2
