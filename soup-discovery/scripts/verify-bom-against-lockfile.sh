#!/usr/bin/env bash
# Prove a supplied CycloneDX document describes the same closure the Gradle lockfile pins.
#
# The reason this exists: resolving an Android closure needs more than Gradle. Flutter injects the
# plugin modules only once `flutter pub get` has written .flutter-plugins-dependencies, and without
# it the same command resolves a strict subset — measured, 49 of 153 — with no error and no warning.
# A BOM built that way carries licences, hashes and every appearance of completeness while
# describing a third of what ships. That is the failure this whole pipeline exists to prevent, so
# the lockfile stays the contract and the BOM has to match it.
#
# Compared on group:artifact:version. Components carrying `project_path` are the build's own
# subprojects and are not in the lockfile by construction, so they are left out of the comparison.
#
# Usage: verify-bom-against-lockfile.sh <bom.json> <gradle.lockfile>

set -uo pipefail

BOM="${1:?missing bom}"
LOCK="${2:?missing lockfile}"

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$BOM"  ]] || { echo "::error::no BOM at $BOM" >&2; exit 1; }
[[ -f "$LOCK" ]] || { echo "::error::no lockfile at $LOCK" >&2; exit 1; }

# `empty=` is Gradle's marker for configurations that resolved to nothing, not a coordinate.
LOCK_SET=$(grep -E '^[^#[:space:]]+=' "$LOCK" | grep -v '^empty=' | cut -d= -f1 | sort -u)
BOM_SET=$(jq -r '
  .components[]? | select((.purl // "") | contains("project_path") | not) | .purl // empty
  | capture("^pkg:maven/(?<g>[^/]+)/(?<a>[^@]+)@(?<v>[^?]+)")
  | "\(.g):\(.a):\(.v)"' "$BOM" | sort -u)

MISSING=$(comm -23 <(echo "$LOCK_SET") <(echo "$BOM_SET"))
EXTRA=$(comm -13 <(echo "$LOCK_SET") <(echo "$BOM_SET"))

if [[ -z "$MISSING" && -z "$EXTRA" ]]; then
  echo "BOM matches the lockfile: $(wc -l <<<"$LOCK_SET" | tr -d ' ') coordinates"
  exit 0
fi

echo "::error::the supplied BOM does not describe the locked closure" >&2
[[ -n "$MISSING" ]] && {
  echo "::error::  $(wc -l <<<"$MISSING" | tr -d ' ') locked coordinate(s) missing from the BOM" >&2
  head -5 <<<"$MISSING" | sed 's/^/::error::    /' >&2
}
[[ -n "$EXTRA" ]] && {
  echo "::error::  $(wc -l <<<"$EXTRA" | tr -d ' ') coordinate(s) in the BOM that are not locked" >&2
  head -5 <<<"$EXTRA" | sed 's/^/::error::    /' >&2
}
exit 1
