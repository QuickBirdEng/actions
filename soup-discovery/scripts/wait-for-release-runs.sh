#!/usr/bin/env bash
# Wait until no release workflow is still building the artefacts of this tag.
#
# workflow_run fires when *one* named workflow finishes, never when all of them have. Where two
# release workflows produce different parts of the inventory — one pushing the container images,
# another producing the android BOM — the faster one triggers the scan while the slower is still
# running. Measured on one product: images in ~5 minutes, the mobile build in 18 to 28. The scan
# would start on the first and describe an artefact set that is still half built.
#
# This waits for the runs that exist and are still going. It does not wait for a workflow that has
# not started, because a production release is a later manual dispatch and may be days away.
#
# It decides nothing. Whatever is missing afterwards is a gap with a reason, recorded by the
# pipeline as always — the point here is to stop turning a slow build into a missing artefact.
#
# Usage: wait-for-release-runs.sh <repo> <tag> <workflow name>...
#        WAIT_TIMEOUT   seconds before giving up and continuing anyway (default 2700)
#        WAIT_INTERVAL  seconds between polls (default 20)
#        WAIT_RUNS_JSON a file of runs to read instead of asking the API — for tests

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
    # Continuing rather than failing: a document with a named gap is worth more than no document,
    # and the gap says which artefact was missing.
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
    # Named, not fatal. What it failed to push turns into a gap with a reason further down.
    echo "::warning::  $name: $conclusion — whatever it produces will be missing from this inventory" >&2
  fi
done < <(fetch_runs)
exit 0
