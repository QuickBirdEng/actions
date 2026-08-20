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
# The digest of what was actually scanned, read from syft's native output. Optional: a directory
# or lockfile scan has no image digest, and a missing one must not fail the run.
NATIVE="${SYFT_NATIVE:-}"
TARGET="${SCAN_TARGET:-}"
IMG_REF=""; IMG_ID=""; IMG_CREATED=""
if [[ -n "$NATIVE" && -f "$NATIVE" ]]; then
  IMG_REF=$(jq -r '(.source.metadata.repoDigests // [])[0] // ""' "$NATIVE" 2>/dev/null)
  [[ -z "$IMG_REF" || "$IMG_REF" == "null" ]] && \
    IMG_REF=$(jq -r '.source.metadata.manifestDigest // ""' "$NATIVE" 2>/dev/null)
  IMG_ID=$(jq -r '.source.metadata.imageID // ""' "$NATIVE" 2>/dev/null)
  [[ "$IMG_REF" == "null" ]] && IMG_REF=""
  [[ "$IMG_ID" == "null" ]] && IMG_ID=""

  # When the image was built. Needed because an image is a component in its own right and ages
  # like any other: Annex B B.1.1 makes the image the SOUP, so the currency policy applies to it rather
  # than to the packages inside it. Two sources, in order:
  #   the OCI standard label, which a well-behaved publisher sets, and
  #   `created` in the image config, which is always present.
  # Note what this does and does not say. linuxserver/wireguard:1.0.20210914 reports 2025-07-24:
  # the image is rebuilt regularly, and the 2021 in the tag is the version of the WireGuard
  # software inside it. Image age and packaged-software version are separate questions.
  IMG_CREATED=$(jq -r '.source.metadata.labels["org.opencontainers.image.created"] // ""' "$NATIVE" 2>/dev/null)
  if [[ -z "$IMG_CREATED" || "$IMG_CREATED" == "null" ]]; then
    IMG_CREATED=$(jq -r '.source.metadata.config // ""' "$NATIVE" 2>/dev/null \
                  | base64 -d 2>/dev/null | jq -r '.created // ""' 2>/dev/null)
  fi
  [[ "$IMG_CREATED" == "null" ]] && IMG_CREATED=""
fi

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$IN" ]] || { echo "::error::not found: $IN" >&2; exit 1; }

if [[ -z "$SUBJECT" ]]; then
  echo "::error::BOM_SUBJECT is required — it is the stable name of the thing this BOM describes" >&2
  echo "::error::  without it the subject name is the scan path and the output is not reproducible" >&2
  echo "::error::  e.g. BOM_SUBJECT=pipeline-worker normalize-bom.sh raw.json" >&2
  exit 1
fi

jq --argjson keep_ts "$KEEP_TIMESTAMP" --arg subject "$SUBJECT" \
   --arg ref "$IMG_REF" --arg imgid "$IMG_ID" --arg target "$TARGET" \
   --arg created "$IMG_CREATED" '
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
          # 5. record which bytes were actually examined. The CycloneDX output carries only
          # the image name and tag; the digest comes from the native output. Without it a
          # floating tag leaves the document unable to say what it looked at, which is why such
          # images were being excluded from scope as "not reproducible" — rewarding exactly the
          # configuration that caused the problem. With it, the document is exact whatever the
          # tag does afterwards, and tag mutation on a pinned image becomes visible: same tag,
          # different digest between two runs.
          | (if $ref != "" then .metadata.component.hashes =
                 ((.metadata.component.hashes // [])
                  + [{alg: "SHA-256", content: ($ref | sub("^.*@sha256:"; ""))}] | unique)
             else . end)
          | .metadata.component.properties =
              ((.metadata.component.properties // [])
               + [ {name: "quickbird:scan:target", value: $target} ]
               + (if $ref != "" then [{name: "quickbird:scan:image-digest", value: $ref}] else [] end)
               + (if $imgid != "" then [{name: "quickbird:scan:image-id", value: $imgid}] else [] end)
               + (if $created != "" then [{name: "quickbird:scan:image-created", value: $created}] else [] end)
               | unique_by(.name))
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
