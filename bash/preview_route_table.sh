#!/usr/bin/env bash
set -euo pipefail
umask 077

# Configuration: edit these defaults or export the variables before running.
SOURCE_RT="${SOURCE_RT-REPLACE_ME_SOURCE_RT}"
DEST_COMPARTMENT="${DEST_COMPARTMENT-REPLACE_ME_DEST_COMPARTMENT}"
DEST_VCN="${DEST_VCN-REPLACE_ME_DEST_VCN}"
DEST_NAME="${DEST_NAME-REPLACE_ME_DEST_NAME}"
OLD_NAT="${OLD_NAT-REPLACE_ME_OLD_NAT}"
NEW_NAT="${NEW_NAT-REPLACE_ME_NEW_NAT}"
OLD_SGW="${OLD_SGW-REPLACE_ME_OLD_SGW}"
NEW_SGW="${NEW_SGW-REPLACE_ME_NEW_SGW}"

for value in \
  "$SOURCE_RT" "$DEST_COMPARTMENT" "$DEST_VCN" "$DEST_NAME" \
  "$OLD_NAT" "$NEW_NAT" "$OLD_SGW" "$NEW_SGW"
do
  if [[ -z "$value" || "$value" == *REPLACE_ME* ]]; then
    echo "Error: set all configuration values and replace every REPLACE_ME value before running." >&2
    exit 1
  fi
done

command -v oci >/dev/null || {
  echo "Error: OCI CLI is required." >&2
  exit 1
}
command -v jq >/dev/null || {
  echo "Error: jq is required." >&2
  exit 1
}

TASK_DIR="$(mktemp -d)"
trap 'rm -rf "$TASK_DIR"' EXIT

echo "Reading source route table..."
oci network route-table get \
  --rt-id "$SOURCE_RT" \
  --output json > "$TASK_DIR/source.json"

echo "Preparing rules..."
jq -e \
  --arg oldNat "$OLD_NAT" \
  --arg newNat "$NEW_NAT" \
  --arg oldSgw "$OLD_SGW" \
  --arg newSgw "$NEW_SGW" '
  [
    .data["route-rules"][]
    | select(.["route-type"] != "LOCAL")
  ]
  | if (any(.[]; .["network-entity-id"] == $oldNat) | not)
    then error("OLD_NAT was not found in the source rules")
    else .
    end
  | if (any(.[]; .["network-entity-id"] == $oldSgw) | not)
    then error("OLD_SGW was not found in the source rules")
    else .
    end
  | map(
      {
        destination: (.destination // .["cidr-block"]),
        destinationType: (.["destination-type"] // "CIDR_BLOCK"),
        networkEntityId: (
          if .["network-entity-id"] == $oldNat then $newNat
          elif .["network-entity-id"] == $oldSgw then $newSgw
          else .["network-entity-id"]
          end
        ),
        description: .description
      }
      | with_entries(select(.value != null))
    )
' "$TASK_DIR/source.json" > "$TASK_DIR/rules.json"

echo "Rules to copy:"
jq . "$TASK_DIR/rules.json"

# Save the original extraction for inspection.
cp "$TASK_DIR/source.json" ./source-route-table.json

# Build the complete creation request without sending it to OCI.
jq \
  --arg compartment "$DEST_COMPARTMENT" \
  --arg vcn "$DEST_VCN" \
  --arg name "$DEST_NAME" '
  {
    compartmentId: $compartment,
    vcnId: $vcn,
    displayName: $name,
    routeRules: .
  }
' "$TASK_DIR/rules.json" > ./destination-route-table.json

echo "DRY RUN: no OCI resources were created or changed."
echo "Original route table:"
jq . ./source-route-table.json

echo "Proposed creation request:"
jq . ./destination-route-table.json

# Create on target after reviewing destination-route-table.json:
# oci network route-table create \
#   --from-json file://destination-route-table.json \
#   --wait-for-state AVAILABLE
