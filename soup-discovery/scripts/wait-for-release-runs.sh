#!/usr/bin/env bash
# Wait until no release workflow is still building the artefacts of this tag.
#
# workflow_run fires when one named workflow finishes, never when all have, so a fast release
# workflow starts the scan while a slow one is still pushing what it is meant to scan.
#
# Does not wait for a workflow that has not started — a production release is a later manual
# dispatch. Names a failed run and continues: what it failed to push becomes a gap with a reason.
#
# Usage: wait-for-release-runs.sh <repo> <tag> <workflow name>...
#        WAIT_TIMEOUT   seconds before continuing anyway (default 2700)
#        WAIT_INTERVAL  seconds between polls (default 20)
#        WAIT_RUNS_JSON read runs from a file instead of the API — for tests

set -uo pipefail

REPO="${1:?missing repo}"; shift
TAG="${1:?missing tag}"; shift
[[ $# -gt 0 ]] || { echo "::error::name at least one workflow to wait for" >&2; exit 1; }
NAMES=("$@")

TIMEOUT="${WAIT_TIMEOUT:-2700}"
INTERVAL="${WAIT_INTERVAL:-20}"

fetch_runs() {
  if [[ -n "${WAIT_RUNS_JSON:-}" ]]; then cat "$WAIT_RUNS_JSON"; return; fi
  gh api "repos/$REPO/actions/runs?branch=$TAG&per_page=50" \
    -q '.workflow_runs[] | "\(.name)\t\(.status)\t\(.conclusion // "")"' 2>/dev/null
}

wanted() { local n="$1"; local w; for w in "${NAMES[@]}"; do [[ "$w" == "$n" ]] && return 0; done; return 1; }

WAITED=0
while :; do
  RUNNING=""
  while IFS=$'\t' read -r name status conclusion; do
    [[ -z "$name" ]] && continue
    wanted "$name" || continue
    case "$status" in
      completed) ;;
      *) RUNNING+="$name; " ;;
    esac
  done < <(fetch_runs)

  [[ -z "$RUNNING" ]] && break

  if (( WAITED >= TIMEOUT )); then
    # Continuing rather than failing: a named gap beats no document.
    echo "::warning::still running after ${TIMEOUT}s, continuing without: ${RUNNING%; }" >&2
    break
  fi
  echo "waiting for ${RUNNING%; } (${WAITED}s)" >&2
  sleep "$INTERVAL"
  WAITED=$(( WAITED + INTERVAL ))
done

while IFS=$'\t' read -r name status conclusion; do
  [[ -z "$name" ]] && continue
  wanted "$name" || continue
  [[ "$status" == "completed" ]] || continue
  if [[ "$conclusion" == "success" ]]; then
    echo "  $name: success"
  else
    echo "::warning::  $name: $conclusion — whatever it produces will be missing from this inventory" >&2
  fi
done < <(fetch_runs)
exit 0
