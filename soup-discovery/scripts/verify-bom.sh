#!/usr/bin/env bash
# Gate on a generated CycloneDX BOM before it is allowed to become evidence.
#
# Checks three failure classes that are all silent today:
#
#   1. A component with no version. Fails IEC 62304 §8.1.2 (unique version per
#      configuration item) and cannot be CVE-matched. This is what BOM/platform-managed
#      Gradle dependencies produce under the current declared-only discovery.
#   2. Scan-path leakage. syft emits parallel `type: file` entries whose `name` is the
#      absolute path the scan happened to see (/Users/… locally, /scan/… in a container),
#      which destroys determinism and inflates the component count.
#   3. Speculative CPEs. syft generates large numbers of guessed cpe23 variants; matching
#      CVEs on those produces phantom findings. Only a canonical cpe may survive.
#
# Usage: verify-bom.sh <bom.cdx.json>

set -uo pipefail

BOM="${1:?usage: verify-bom.sh <bom.cdx.json>}"
command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$BOM" ]] || { echo "::error::BOM not found: $BOM" >&2; exit 1; }

jq -e '.bomFormat == "CycloneDX"' "$BOM" >/dev/null 2>&1 \
  || { echo "::error::$BOM is not a CycloneDX document" >&2; exit 1; }

SPEC=$(jq -r '.specVersion // "unknown"' "$BOM")
STATUS=0

# --- 1. unversioned components ---------------------------------------------
# `type: file` is excluded: those are scan artefacts, not components, and are removed
# by check 2 anyway. Everything that claims to be a library/application/container must
# carry a version.
UNVERSIONED=$(jq -c '
  [ .components[]?
    | select(.type != "file")
    | select((.version // "") == "")
    | {name, type, purl: (.purl // null)} ]' "$BOM")

N_UNVERSIONED=$(jq 'length' <<<"$UNVERSIONED")
if (( N_UNVERSIONED > 0 )); then
  echo "::error::$N_UNVERSIONED component(s) have no version — not valid as a configuration item" >&2
  jq -r '.[] | "::error::  no version: \(.name) (\(.type))"' <<<"$UNVERSIONED" >&2
  STATUS=1
fi

# --- 2. scan-path leakage ---------------------------------------------------
# metadata.component is checked too, not just components[]. The BOM subject's name is
# whatever path was handed to the scanner, and its bom-ref is a hash of that name, so a
# components-only check passes while the document still differs between two runs of the
# same content. Found by the determinism check, not by inspection.
LEAKED=$(jq -c '
  ( [ .components[]? | select(.name | test("^/|^[A-Za-z]:\\\\")) | .name ]
    + [ .metadata.component? | select(. != null)
        | select(.name | test("^/|^[A-Za-z]:\\\\|/")) | "metadata.component.name=" + .name ]
  ) | unique' "$BOM")
N_LEAKED=$(jq 'length' <<<"$LEAKED")
if (( N_LEAKED > 0 )); then
  echo "::error::$N_LEAKED component name(s) are filesystem paths — output is not reproducible across machines" >&2
  jq -r '.[0:5][] | "::error::  path as name: \(.)"' <<<"$LEAKED" >&2
  (( N_LEAKED > 5 )) && echo "::error::  … and $((N_LEAKED - 5)) more" >&2
  echo "::error::  fix: drop type:file components after harvesting their hashes onto the real component" >&2
  STATUS=1
fi

# --- 3. speculative CPEs ----------------------------------------------------
SPEC_CPE=$(jq '[ .components[]?.properties[]? | select(.name == "syft:cpe23") ] | length' "$BOM")
if (( SPEC_CPE > 0 )); then
  echo "::error::$SPEC_CPE speculative syft:cpe23 properties present — strip these before CVE matching, or phantom findings follow" >&2
  STATUS=1
fi

# --- report -----------------------------------------------------------------
jq -n \
  --arg spec "$SPEC" \
  --argjson unversioned "$UNVERSIONED" \
  --argjson leaked "$LEAKED" \
  --argjson spec_cpe "$SPEC_CPE" \
  --argjson total "$(jq '[.components[]? | select(.type != "file")] | length' "$BOM")" \
  --argjson with_purl "$(jq '[.components[]? | select(.type != "file") | select(.purl != null)] | length' "$BOM")" \
  --argjson with_license "$(jq '[.components[]? | select(.type != "file") | select((.licenses // []) | length > 0)] | length' "$BOM")" \
  --argjson with_hash "$(jq '[.components[]? | select(.type != "file") | select((.hashes // []) | length > 0)] | length' "$BOM")" \
  '{
     spec_version: $spec,
     components: $total,
     coverage: { purl: $with_purl, license: $with_license, hash: $with_hash },
     failures: {
       unversioned: ($unversioned | length),
       path_as_name: ($leaked | length),
       speculative_cpe: $spec_cpe
     }
   }' >&2

if (( STATUS == 0 )); then
  echo "BOM gate passed" >&2
else
  echo "::error::BOM gate failed — see above" >&2
fi
exit $STATUS
