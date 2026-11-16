#!/usr/bin/env bash
set -euo pipefail
umask 077

# Configuration: edit these defaults or export the variables before running.
SOURCE_SL="${SOURCE_SL-REPLACE_ME_SOURCE_SL}"
DEST_COMPARTMENT="${DEST_COMPARTMENT-REPLACE_ME_DEST_COMPARTMENT}"
DEST_VCN="${DEST_VCN-REPLACE_ME_DEST_VCN}"
DEST_NAME="${DEST_NAME-REPLACE_ME_DEST_NAME}"

for value in "$SOURCE_SL" "$DEST_COMPARTMENT" "$DEST_VCN" "$DEST_NAME"
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
  echo "Error: jq 1.6 or later is required." >&2
  exit 1
}

TASK_DIR="$(mktemp -d)"
trap 'rm -rf "$TASK_DIR"' EXIT

echo "Reading source security list..."
oci network security-list get \
  --security-list-id "$SOURCE_SL" \
  --output json > "$TASK_DIR/source.json"

echo "Preparing destination request..."
jq -e \
  --arg compartment "$DEST_COMPARTMENT" \
  --arg vcn "$DEST_VCN" \
  --arg name "$DEST_NAME" '
  # Convert hyphenated keys to camelCase, including nested TCP/UDP options.
  # Remove null object values, preserving false, zero, and empty arrays.
  def convert:
    walk(
      if type == "object" then
        with_entries(
          .key |= (
            split("-")
            | .[0] + (.[1:] | map((.[0:1] | ascii_upcase) + .[1:]) | join(""))
          )
        )
        | with_entries(select(.value != null))
      else .
      end
    );

  .data
  | if ((.["ingress-security-rules"] | type) != "array"
        or (.["egress-security-rules"] | type) != "array")
    then error("Source ingress and egress security rules must be arrays")
    else .
    end
  | {
      compartmentId: $compartment,
      vcnId: $vcn,
      displayName: $name,
      ingressSecurityRules: .["ingress-security-rules"],
      egressSecurityRules: .["egress-security-rules"]
    }
  | convert
' "$TASK_DIR/source.json" > "$TASK_DIR/request.json"

echo "Proposed creation request:"
jq . "$TASK_DIR/request.json"

echo "Creating destination security list..."
NEW_SL="$(
  oci network security-list create \
    --from-json "file://$TASK_DIR/request.json" \
    --wait-for-state AVAILABLE \
    --query 'data.id' \
    --raw-output
)"

echo "Created security list: $NEW_SL"
