#!/usr/bin/env bash
# The standing overview: what the live environment is carrying, what the QA line is carrying,
# and what moved between them.
#
# Separate from compose-alert.sh so the QA workflow can post just this after a build, while
# the weekly message embeds it under the alert blocks. One renderer, two callers — the
# alternative was the same table assembled twice and drifting.
#
# The live environment is chosen by precedence, not configured per product: the first of
# Production, Study that has a deployment record AND an SBOM for it. Hard-coding one would be
# wrong the day production starts, and every product would need editing.
#
# Staging is deliberately NOT in that list. It carries the QA tag, so falling back to it
# compares the QA line against itself and reports "unchanged" — true, meaningless, and it
# reads as though live were up to date. Whatever is wrong with the live answer, saying it is
# better than an identity comparison dressed up as one.
#
# When no environment resolves, the block says which one it tried, what it runs, and why it
# could not be compared. osteocoach today is the case worth designing for: Study runs v1.0.3
# from 2026-05-12, released before the SBOM pipeline existed. "live: unknown, and by the way
# it has been on a four-month-old release since May" is the most useful line in the message.
# A blank row is not.
#
# Usage: compose-overview.sh <repo> <qa-bom.cdx.json|--latest> <qa-label|-> <policy.json> [out]
#
# --latest resolves the QA line here rather than in the caller: the newest release carrying an
# sbom-*.cdx.json asset. A workflow step that had to find it would duplicate the asset-naming
# convention that resolve-deployed.sh already depends on, in a second place, and the naming is
# load-bearing enough in one.
# Env:   PYTHON       interpreter with the cvss module (default python3)
#        LIVE_ORDER   comma-separated precedence (default "Production,Study")
#        DEPLOYED_JSON  pre-computed resolve-deployed.sh output, to avoid a second API pass

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:?usage: compose-overview.sh <repo> <qa-bom> <qa-label> <policy> [out]}"
QA_BOM="${2:?QA BOM required}"
QA_LABEL="${3:?QA label required}"
POLICY="${4:?policy required}"
OUT="${5:-/dev/stdout}"
PY="${PYTHON:-python3}"
LIVE_ORDER="${LIVE_ORDER:-Production,Study}"

for t in gh jq; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

if [[ "$QA_BOM" == "--latest" ]]; then
  LATEST=$(gh api "repos/$REPO/releases?per_page=100" 2>/dev/null | jq -c '
    [ .[] | select(.draft | not)
      | { tag: .tag_name, published: .published_at,
          sbom: ([ .assets[] | select(.name | test("^sbom-.*\\.cdx\\.json$")) | .url ][0] // null) }
      | select(.sbom != null) ]
    | sort_by(.published) | last // empty' 2>/dev/null)
  if [[ -z "$LATEST" ]]; then
    echo "  no release carries an SBOM asset — nothing to summarise" > "$OUT"
    exit 0
  fi
  QA_TAG=$(jq -r '.tag' <<<"$LATEST")
  [[ "$QA_LABEL" == "-" || -z "$QA_LABEL" ]] && QA_LABEL="QA ($QA_TAG)"
  QA_BOM="$WORK/qa.cdx.json"
  gh api -H "Accept: application/octet-stream" "$(jq -r '.sbom' <<<"$LATEST")" > "$QA_BOM" 2>/dev/null || : > "$QA_BOM"
  [[ -s "$QA_BOM" ]] || { echo "  the SBOM for $QA_TAG could not be downloaded" > "$OUT"; exit 0; }
fi

if [[ -n "${DEPLOYED_JSON:-}" && -s "${DEPLOYED_JSON:-}" ]]; then
  cp "$DEPLOYED_JSON" "$WORK/deployed.json"
else
  bash "$HERE/resolve-deployed.sh" "$REPO" > "$WORK/deployed.json" 2>/dev/null || : > "$WORK/deployed.json"
fi

# First environment in the precedence list that resolved to a ref with an SBOM.
PICK=$(jq -r --arg order "$LIVE_ORDER" '
  ($order | split(",")) as $pref
  | [ $pref[] as $e
      | (.environments // [])[]
      | select(.environment == $e)
      | select(.sbom != null)
      | { env: .environment, ref: .ref, at: (.deployed_at // ""), sbom: .sbom } ]
  | first // empty' "$WORK/deployed.json" 2>/dev/null)

# Nothing resolved: name the first environment in the list that exists and say what blocks it.
# The reason is already written by resolve-deployed.sh, which distinguishes "no deployment
# recorded" from "not a tag" from "tag has no SBOM" — collapsing them here would throw away
# the one part that tells someone what to fix.
# The deployment date comes from .environments, not .unresolvable, which carries only the
# reason. How long the live environment has been sitting on that version is the part someone
# acts on: four months behind is a different conversation from four days.
BLOCKED=$(jq -r --arg order "$LIVE_ORDER" '
  ($order | split(",")) as $pref
  | (.environments // []) as $envs
  | [ $pref[] as $e
      | ((.unresolvable // [])[] | select(.environment == $e)
         | { env: .environment, ref: (.ref // "-"), why: .why,
             at: ([ $envs[] | select(.environment == $e) | .deployed_at // "" ] | first // "") }) ]
  | first // empty' "$WORK/deployed.json" 2>/dev/null)

{
  if [[ -n "$PICK" ]]; then
    LIVE_ENV=$(jq -r '.env' <<<"$PICK")
    LIVE_REF=$(jq -r '.ref' <<<"$PICK")
    LIVE_URL=$(jq -r '.sbom' <<<"$PICK")
    if gh api -H "Accept: application/octet-stream" "$LIVE_URL" > "$WORK/live.cdx.json" 2>/dev/null \
       && [[ -s "$WORK/live.cdx.json" ]]; then
      PYTHON="$PY" bash "$HERE/summarise-state.sh" --compare "$POLICY" \
        "$WORK/live.cdx.json" "live ($LIVE_ENV, $LIVE_REF)" "$QA_BOM" "$QA_LABEL"
    else
      echo "  live ($LIVE_ENV, $LIVE_REF): SBOM could not be downloaded — showing the QA line only"
      PYTHON="$PY" bash "$HERE/summarise-state.sh" --render "$QA_BOM" "$POLICY" "$QA_LABEL"
    fi
  else
    if [[ -n "$BLOCKED" ]]; then
      B_ENV=$(jq -r '.env' <<<"$BLOCKED"); B_REF=$(jq -r '.ref' <<<"$BLOCKED")
      B_AT=$(jq -r '.at' <<<"$BLOCKED"); B_WHY=$(jq -r '.why' <<<"$BLOCKED")
      AGE=""
      if [[ -n "$B_AT" && "$B_AT" != "null" ]]; then
        DAYS=$(( ( $(date -u +%s) - $(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$B_AT" +%s 2>/dev/null \
                     || date -u -d "$B_AT" +%s 2>/dev/null || date -u +%s) ) / 86400 ))
        [[ "$DAYS" -gt 0 ]] && AGE=", deployed ${B_AT:0:10} (${DAYS}d ago)"
      fi
      echo "  live ($B_ENV): $B_REF$AGE — not comparable, $B_WHY"
    else
      echo "  live: no environment in $LIVE_ORDER has a recorded deployment"
    fi
    # Still show the QA line. The comparison is the part that is missing, not the state.
    PYTHON="$PY" bash "$HERE/summarise-state.sh" --render "$QA_BOM" "$POLICY" "$QA_LABEL"
  fi
} > "$OUT"
