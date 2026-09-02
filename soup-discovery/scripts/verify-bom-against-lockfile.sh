#!/usr/bin/env bash
# Refuse a supplied BOM that does not describe the closure the Gradle lockfile pins.
#
# Without `flutter pub get` the same Gradle command resolves a strict subset and reports no error,
# so a BOM can look complete and describe a third of what ships. The lockfile is the contract.
#
# `project_path` components are the build's own subprojects and are not in the lockfile by
# construction, so they stay out of the comparison.
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
