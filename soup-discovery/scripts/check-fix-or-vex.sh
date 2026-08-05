#!/usr/bin/env bash
# Fix-or-VEX gate for the SOUP approval workflow.
#
# For each SOUP record, every vulnerability that OSV reports **for the exact version being
# approved** must have either been fixed (by approving a different version, in which case
# OSV reports nothing) or carry a VEX statement. There is no third option, and "we did not
# get round to it" currently reads exactly like "there is nothing to report".
#
# This is new behaviour, not a tightening: soup-approval-verification-workflow today checks
# requirement results and the version condition. CVEs do not appear in it at all.
#
# The query is version-exact on purpose. Elsewhere the tooling matches on the approval
# *family* ("1.x.x") because an approval is not version-specific — but a vulnerability is.
# Asking "does 1.0.1 have open CVEs" is the question; asking it of the family would drag in
# findings for versions nobody ships.
#
# Usage: check-fix-or-vex.sh <soup-record.json> [more records...]
# Exit 0 = every reported CVE has a disposition. Exit 1 = at least one does not.

set -uo pipefail

OSV="${OSV_API:-https://api.osv.dev}"
STRICT_UNDER_INVESTIGATION="${STRICT_UNDER_INVESTIGATION:-false}"

for t in jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
[[ $# -gt 0 ]] || { echo "::error::no SOUP records given" >&2; exit 1; }

# .soups/<ecosystem>/... -> the purl type OSV expects
purl_type() {
  case "$1" in
    npm|node)        echo "npm" ;;
    pub|dart|flutter) echo "pub" ;;
    maven|jvm|gradle) echo "maven" ;;
    golang|go)       echo "golang" ;;
    pypi|python)     echo "pypi" ;;
    *)               echo "$1" ;;
  esac
}

STATUS=0
TOTAL_OPEN=0

for record in "$@"; do
  [[ -f "$record" ]] || { echo "::error::not found: $record" >&2; STATUS=1; continue; }
  if ! jq -e '.package' "$record" >/dev/null 2>&1; then
    echo "::warning::$record has no .package — skipping" >&2; continue
  fi

  pkg=$(jq -r '.package' "$record")
  ver=$(jq -r '.metadata.input_version // ""' "$record")
  eco=$(purl_type "$(basename "$(dirname "$record")")")

  if [[ -z "$ver" ]]; then
    echo "::error::$pkg: metadata.input_version is empty — cannot check a version that is not stated" >&2
    STATUS=1; continue
  fi

  resp=$(curl -sS --fail --max-time 60 -X POST "$OSV/v1/query" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$pkg" --arg e "$eco" --arg v "$ver" \
          '{package:{name:$p, ecosystem:(if $e=="npm" then "npm"
                                         elif $e=="pub" then "Pub"
                                         elif $e=="maven" then "Maven"
                                         elif $e=="golang" then "Go"
                                         elif $e=="pypi" then "PyPI"
                                         else $e end)}, version:$v}')" 2>/dev/null) || {
    # A failed query is not "no vulnerabilities". Fail rather than wave the SOUP through
    # on the strength of a network error.
    echo "::error::$pkg@$ver: OSV query failed — cannot establish whether open CVEs exist" >&2
    STATUS=1; continue
  }

  # Prefer the CVE alias: that is what a VEX statement is keyed on.
  # A read loop rather than mapfile — mapfile is bash 4+, and macOS ships bash 3.2, so a
  # developer running this locally would get "command not found" and an exit code that
  # looks like success.
  ids=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && ids+=("$line")
  done < <(jq -r '[.vulns // [] | .[]
                  | (([.aliases // [] | .[] | select(startswith("CVE-"))] | first) // .id)]
                  | unique | .[]' <<<"$resp")

  if [[ ${#ids[@]} -eq 0 ]]; then
    echo "✅ $pkg@$ver — no vulnerabilities reported for this version" >&2
    continue
  fi

  missing=(); investigating=(); dispositioned=0
  for id in "${ids[@]}"; do
    [[ -z "$id" ]] && continue
    state=$(jq -r --arg id "$id" '.vex[$id].state // ""' "$record")
    just=$(jq -r --arg id "$id" '.vex[$id].justification // ""' "$record")
    detail=$(jq -r --arg id "$id" '.vex[$id].detail // ""' "$record")

    case "$state" in
      "")
        missing+=("$id — no VEX statement") ;;
      not_affected)
        # A not_affected without a justification code and a product-specific detail is an
        # assertion, not an argument. This is the mute-button case the rule exists to stop.
        if [[ -z "$just" ]]; then
          missing+=("$id — not_affected without a justification code")
        elif [[ -z "$detail" ]]; then
          missing+=("$id — not_affected without a detail explaining why, for this product")
        else
          dispositioned=$((dispositioned+1))
        fi ;;
      under_investigation)
        investigating+=("$id")
        [[ "$STRICT_UNDER_INVESTIGATION" == "true" ]] && missing+=("$id — still under_investigation")
        ;;
      affected|fixed)
        dispositioned=$((dispositioned+1)) ;;
      *)
        missing+=("$id — unknown VEX state '$state'") ;;
    esac
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    echo "✅ $pkg@$ver — ${#ids[@]} vulnerability/ies, all dispositioned ($dispositioned decided, ${#investigating[@]} under investigation)" >&2
  else
    echo "::error::❌ $pkg@$ver — ${#missing[@]} of ${#ids[@]} vulnerability/ies have no valid disposition" >&2
    for m in "${missing[@]}"; do echo "::error::    $m" >&2; done
    TOTAL_OPEN=$((TOTAL_OPEN + ${#missing[@]}))
    STATUS=1
  fi

  if [[ ${#investigating[@]} -gt 0 && "$STRICT_UNDER_INVESTIGATION" != "true" ]]; then
    echo "::warning::$pkg@$ver — ${#investigating[@]} still under_investigation: ${investigating[*]}" >&2
    echo "::warning::  under_investigation is a holding state. It reverts to 'affected' at the mitigation deadline (classification WI §5)." >&2
  fi
done

if [[ $STATUS -ne 0 ]]; then
  cat >&2 <<EOF
::error::
::error::Fix-or-VEX gate failed: $TOTAL_OPEN vulnerability/ies without a disposition.
::error::
::error::Each one needs exactly one of:
::error::  - a fix   -> approve a version OSV does not report as vulnerable, or
::error::  - a VEX statement in the record's "vex" block:
::error::      "CVE-XXXX-NNNNN": { "state": "not_affected",
::error::                          "justification": "<one of the five CSAF codes>",
::error::                          "detail": "<why, specific to this product>" }
::error::      or { "state": "affected", "response": "update", "detail": "..." }
::error::
::error::See VEX-SCHEMA.md. A not_affected is a defensible reachability claim, not a mute button.
EOF
fi
exit $STATUS
