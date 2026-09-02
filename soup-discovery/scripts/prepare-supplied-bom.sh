#!/usr/bin/env bash
# Take a CycloneDX document supplied for a candidate and use it as that candidate's raw BOM.
#
# Refuses anything that is not CycloneDX: a file that exists is not a BOM. Drops components
# carrying `project_path` — the build's own subprojects, which the manifest already names, the
# same double count mark-scope.py refuses between pub and cocoapods.
#
# Usage: prepare-supplied-bom.sh <supplied.cdx.json> <out.json>
#        prints how many subproject components were dropped

set -uo pipefail

IN="${1:?missing input}"
OUT="${2:?missing output}"

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }

if ! jq -e '.bomFormat == "CycloneDX"' "$IN" >/dev/null 2>&1; then
  echo "::error::$IN is not a CycloneDX document" >&2
  exit 1
fi

DROPPED=$(jq '[.components[]? | select((.purl // "") | contains("project_path"))] | length' "$IN")
jq '.components = [.components[]? | select((.purl // "") | contains("project_path") | not)]' \
  "$IN" > "$OUT" || { echo "::error::could not rewrite $IN" >&2; exit 1; }
echo "$DROPPED"
