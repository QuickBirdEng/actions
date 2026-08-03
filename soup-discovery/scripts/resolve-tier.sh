#!/usr/bin/env bash
# Which kind of document is this build producing?
#
#   release   a production release. The controlled record.
#   staging   a pre-release build (v1.0.15-qa4). Attached to its own prerelease so it can be
#             pulled later, and marked so it cannot be mistaken for the record.
#   branch    no tag at all. Nothing to attach it to and no version identity.
#
# Derived from the *tag shape*, not from `github.ref_type`: ref_type is 'tag' for
# v1.0.15-qa4 exactly as it is for v1.0.15, so deriving the tier from it marked every
# staging build as a release. The shape is the same signal §3.4 uses to decide which
# releases are production ones, so the two cannot drift — a project that redefines its
# production tag pattern redefines this at the same time.
#
# Lives in a script rather than inline in action.yml so it can be tested. The inline
# expression it replaces was wrong and nothing caught it.
#
# Usage: resolve-tier.sh <ref-type> <ref-name> [policy-file]

set -uo pipefail

REF_TYPE="${1:-}"
REF_NAME="${2:-}"
POLICY="${3:-}"

DEFAULT_PATTERN='^v?[0-9]+\.[0-9]+\.[0-9]+$'

if [[ "$REF_TYPE" != "tag" || -z "$REF_NAME" ]]; then
  echo "branch"
  exit 0
fi

PATTERN="$DEFAULT_PATTERN"
if [[ -n "$POLICY" && -f "$POLICY" ]] && command -v yq >/dev/null 2>&1; then
  FROM_POLICY=$(yq -r '.production_release.tag_pattern // ""' "$POLICY" 2>/dev/null)
  [[ -n "$FROM_POLICY" && "$FROM_POLICY" != "null" ]] && PATTERN="$FROM_POLICY"
fi

# A broken pattern never matches anything, which would silently demote every production
# release to staging — the release would then carry an unmarked bundle and the monitor would
# refuse it. Fail loudly instead. grep exits 2 on an invalid expression, 1 on no match.
printf '%s' "$REF_NAME" | grep -qE "$PATTERN" 2>/dev/null
rc=$?
if [[ $rc -gt 1 ]]; then
  echo "::error::production_release.tag_pattern is not a valid regular expression: $PATTERN" >&2
  exit 1
fi

if [[ $rc -eq 0 ]]; then
  echo "release"
else
  echo "staging"
fi
