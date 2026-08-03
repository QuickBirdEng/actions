#!/usr/bin/env bash
# Which kind of document is this build producing?
#
#   candidate a build from a release-shaped tag (v1.0.15). It MAY become what runs in production.
#             It is not evidence that it did: in these repos a tag push only ever triggers the
#             staging workflow, and production is a later manual dispatch of the same ref. Dermafy
#             released v1.0.6 on 2025-10-15 and still runs v1.0.5 — a document stamped `release`
#             at build time would have claimed release evidence for a version that never shipped.
#   staging   a build from a QA tag (v1.0.15-qa4). Will never be production.
#   branch    no tag at all. Nothing to attach it to and no version identity.
#
# Whether a candidate actually reached production is a separate, dated fact held in the deployment
# record, and resolve-deployed.sh is what reads it. The document says what it is — a build of tag
# X — and does not assert what happened to X afterwards. That keeps it immutable: nothing has to
# be re-stamped later, which would mean editing a published asset.
#
# Derived from the *tag shape*, not from `github.ref_type`: ref_type is 'tag' for
# v1.0.15-qa4 exactly as it is for v1.0.15, so deriving the tier from it marked every
# staging build as a release.
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
  echo "candidate"
else
  echo "staging"
fi
