#!/usr/bin/env bash
# Bring the previous run's clocks forward into this run's evidence directory.
#
# classify-findings.py sets first_seen = now when it has nothing to compare against, so without
# the earlier state every finding is first seen today: the clock start moves with the calendar,
# a deadline is never reached, and the breach block of the alert can never fire. track-lifecycle.py
# loses its transitions the same way, and decide-alert.sh loses the message it compares against.
#
# Only the state files, never the whole evidence directory. The rest of it is the previous run's
# working output, and a stale copy sitting in this run's directory would be read as if it described
# today.
#
# Missing state is a warning and a clean exit, not a failure: a first run has none, and refusing to
# monitor because there is no history would be the wrong trade.
#
# Usage: carry-monitor-state.sh <owner/repo> <product> <evidence-dir>
#        CARRY_ARTIFACTS_JSON  read the artifact list from a file instead of the API -- for tests
#        CARRY_ZIP             use this zip instead of downloading one -- for tests

set -uo pipefail

REPO="${1:?missing repo}"
PRODUCT="${2:?missing product}"
OUT="${3:?missing evidence dir}"

mkdir -p "$OUT"

artifacts() {
  if [[ -n "${CARRY_ARTIFACTS_JSON:-}" ]]; then cat "$CARRY_ARTIFACTS_JSON"; return; fi
  gh api "repos/$REPO/actions/artifacts?name=kev-monitor-$PRODUCT&per_page=1" 2>/dev/null
}

LIST=$(artifacts)
# An expired artifact still appears in the listing and downloads as a 410.
ID=$(jq -r '[.artifacts[]? | select(.expired | not)][0].id // ""' <<<"${LIST:-{\}}" 2>/dev/null)
if [[ -z "$ID" || "$ID" == "null" ]]; then
  echo "::warning::no earlier run to carry clocks from — every finding starts its clock today" >&2
  exit 0
fi

TMP=$(mktemp -d) || exit 0
trap 'rm -rf "$TMP"' EXIT

if [[ -n "${CARRY_ZIP:-}" ]]; then
  cp "$CARRY_ZIP" "$TMP/prev.zip" 2>/dev/null
else
  gh api "repos/$REPO/actions/artifacts/$ID/zip" > "$TMP/prev.zip" 2>/dev/null
fi
if [[ ! -s "$TMP/prev.zip" ]]; then
  echo "::warning::the evidence of run artifact $ID could not be downloaded — clocks restart today" >&2
  exit 0
fi

unzip -qo "$TMP/prev.zip" -d "$TMP" 'state-*.json' 'lifecycle-state-*.json' 'alert-state.json' 2>/dev/null

N=0
for f in "$TMP"/state-*.json "$TMP"/lifecycle-state-*.json "$TMP"/alert-state.json; do
  [[ -e "$f" ]] || continue
  # A truncated or half-written state file would silently reset the clocks it is meant to carry.
  jq -e . "$f" >/dev/null 2>&1 || { echo "::warning::$(basename "$f") is not readable JSON, skipped" >&2; continue; }
  cp "$f" "$OUT/" && N=$((N + 1))
done

if [[ "$N" == "0" ]]; then
  echo "::warning::artifact $ID carried no state files — clocks restart today" >&2
else
  echo "carried $N state file(s) from artifact $ID" >&2
fi
