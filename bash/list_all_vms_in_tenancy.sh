#!/usr/bin/env bash
# list_all_instances.sh
# Usage:
#   ./list_all_instances.sh <TENANCY_OCID> [json|csv]
# 
# Example run: sh list_all_instances.sh tenancy_ocid > all_instances.json
#
# Requires: oci CLI, jq

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <TENANCY_OCID> [json|csv]" >&2
  exit 1
fi

TENANCY_OCID="$1"
FORMAT="${2:-json}"   # json (default) or csv

# 1. Get all subscribed regions using jq (NO '[' token possible)
echo "Discovering regions..." >&2
oci iam region-subscription list \
  --tenancy-id "$TENANCY_OCID" \
  --output json > /tmp/_regions.json

echo "Raw regions payload (for debug):" >&2
jq '.data[]."region-name"' /tmp/_regions.json >&2

tmp_ndjson=$(mktemp)
trap 'rm -f "$tmp_ndjson" /tmp/_regions.json' EXIT

# 2. Loop through regions safely
#    jq -r prints each region name on its own line, no brackets.
while IFS= read -r region; do
  # skip empty lines just in case
  [ -z "$region" ] && continue

  echo "Fetching instances in region: $region" >&2

  oci search resource structured-search \
    --region "$region" \
    --query-text 'query instance resources return allAdditionalFields' \
    --output json \
  | jq --arg region "$region" '
      .data.items[]
      | {
          region:       $region,
          display_name: ."display-name",
          ocid:         .identifier,
          shape:        ."additional-details".shape,
          private_ip:   (."additional-details".attachedVnics[0].privateIp // null),
          image_id:     ."additional-details".imageId
        }
    ' >> "$tmp_ndjson"

done < <(jq -r '.data[]."region-name"' /tmp/_regions.json)

# 3. Output consolidated JSON or CSV
case "$FORMAT" in
  json)
    jq -s '.' "$tmp_ndjson"
    ;;
  csv)
    jq -s -r '
      (first | keys_unsorted) as $cols
      | $cols,
        (.[]
          | [.[ $cols[] ]])
      | @csv
    ' "$tmp_ndjson"
    ;;
  *)
    echo "Unknown format '$FORMAT' (use json or csv)" >&2
    exit 1
    ;;
esac
 