#!/usr/bin/env bash
# Take a CycloneDX document supplied for a candidate and make it usable as that candidate's raw
# BOM.
#
# Some closures cannot be read off the artefact at all: syft finds no components in an AAB,
# because dex bytecode carries no package metadata. The build that produced the artefact can
# describe it, and that description is worth more than a scan of the bytes. This is the entry
# point for such a description.
#
# Two things happen here, and nothing else — normalisation and the BOM gate still run afterwards,
# so a supplied BOM is held to exactly the same bar as a scanned one:
#
#   1. Refuse anything that is not CycloneDX. A file that merely exists is not a BOM, and
#      accepting it would put an unchecked claim into the evidence.
#   2. Drop components carrying `project_path`. Those are the build's own subprojects, not
#      dependencies it resolved — for a Flutter app the plugins' Android wrappers, every one of
#      which pubspec.lock already names. Counting them here is the same double count mark-scope.py
#      refuses between pub and cocoapods.
#
# Usage: prepare-supplied-bom.sh <supplied.cdx.json> <out.json>
#        prints the number of dropped subproject components on stdout

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
