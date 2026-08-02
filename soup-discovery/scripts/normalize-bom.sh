#!/usr/bin/env bash
# Normalise raw syft CycloneDX output into something that can be committed, diffed and
# used as evidence.
#
# Four transformations, each fixing a property the raw output lacks:
#
#   1. Harvest SHA-256 hashes off the parallel `type: file` components onto the real
#      library, matching on `<name>-<version>.jar`. Must happen BEFORE dropping them:
#      Maven libraries come back with empty `hashes` and only a SHA-1 in
#      externalReferences, so the file entries are the only source of a SHA-256 —
#      and Component Hash is a CISA minimum element.
#   2. Drop `type: file` components. Their `name` is the absolute path the scan happened
#      to see, which differs per machine and destroys determinism.
#   3. Strip `syft:cpe23` properties. These are guessed CPE variants; CVE-matching on
#      them produces phantom findings.
#   4. Sort components and properties, and drop the random serialNumber and timestamp.
#      syft's ordering is not contractual, so without this two runs of the same commit
#      differ and no staleness check is possible.
#
# Usage: normalize-bom.sh <raw.cdx.json> [out.cdx.json]

set -uo pipefail

IN="${1:?usage: normalize-bom.sh <raw.cdx.json> [out.cdx.json]}"
OUT="${2:-${IN%.json}.norm.json}"
KEEP_TIMESTAMP="${KEEP_TIMESTAMP:-0}"   # 1 for the release tier, which needs a timestamp

# Stable identity for the BOM subject. Without this, metadata.component.name is whatever
# path was handed to syft — relative from one caller, absolute from another — and the
# subject's bom-ref is a content hash of that name, so both differ between runs even
# though the scanned content is identical. Found by running the determinism check itself;
# it is invisible to a components-only inspection.
SUBJECT="${BOM_SUBJECT:-}"

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$IN" ]] || { echo "::error::not found: $IN" >&2; exit 1; }

if [[ -z "$SUBJECT" ]]; then
  echo "::error::BOM_SUBJECT is required — it is the stable name of the thing this BOM describes" >&2
  echo "::error::  without it the subject name is the scan path and the output is not reproducible" >&2
  echo "::error::  e.g. BOM_SUBJECT=pipeline-worker normalize-bom.sh raw.json" >&2
  exit 1
fi

jq --argjson keep_ts "$KEEP_TIMESTAMP" --arg subject "$SUBJECT" '
  # jar filename -> SHA-256, from the type:file components
  ( [ .components[]?
      | select(.type == "file")
      | { key:   (.name | split("/") | last),
          value: ([ .hashes[]? | select(.alg == "SHA-256") ] | first) }
      | select(.value != null) ]
    | from_entries ) as $hashes

  | .components = (
      [ .components[]? | select(.type != "file") ]
      | map(
          . as $c
          # 1. harvest a hash if the component has none
          | ( if (($c.hashes // []) | length) == 0
                then ($hashes[ ($c.name // "") + "-" + ($c.version // "") + ".jar" ] // null)
                else null end ) as $harvested
          | (if $harvested != null then .hashes = [$harvested] else . end)
          # 3. strip speculative CPEs, and drop the properties array if that empties it
          | (if (.properties // []) | length > 0
               then .properties = [ .properties[] | select(.name != "syft:cpe23") ]
               else . end)
          | (if (.properties // []) | length == 0 then del(.properties) else . end)
          # 4. deterministic property order
          | (if (.properties // []) | length > 0
               then .properties |= sort_by(.name, (.value // ""))
               else . end)
        )
      | sort_by((.name // ""), (.version // ""), (.purl // ""))
    )

  # 4. remove the fields that change on every run, and give the subject a stable identity
  | del(.serialNumber)
  | (if $keep_ts == 1 then . else del(.metadata.timestamp) end)
  | (if .metadata.component != null
       then .metadata.component.name = $subject
          | .metadata.component["bom-ref"] = ("quickbird:subject:" + $subject)
       else . end)
' "$IN" > "$OUT" || { echo "::error::normalisation failed" >&2; exit 1; }

RAW_TOTAL=$(jq '[.components[]?] | length' "$IN")
RAW_FILES=$(jq '[.components[]? | select(.type=="file")] | length' "$IN")
OUT_TOTAL=$(jq '[.components[]?] | length' "$OUT")
OUT_HASHED=$(jq '[.components[]? | select((.hashes // []) | length > 0)] | length' "$OUT")

{
  echo "normalised $IN -> $OUT"
  echo "  raw:        $RAW_TOTAL components ($RAW_FILES of them type:file scan artefacts)"
  echo "  normalised: $OUT_TOTAL components, $OUT_HASHED with a hash"
} >&2
