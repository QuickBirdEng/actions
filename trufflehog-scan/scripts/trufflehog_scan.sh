#!/usr/bin/env bash
set -euo pipefail

# Resolve the base commit to scan from
BASE="${INPUT_BASE:-}"
if [[ -z "$BASE" ]]; then
    REF="${GITHUB_BASE_REF:-$DEFAULT_BRANCH}"
    BASE="$(git rev-parse "origin/$REF")"
fi

ARGS="--only-verified --fail --no-update"
[[ -n "${INPUT_EXCLUDE_PATHS:-}" ]] && ARGS="$ARGS --exclude-paths=$INPUT_EXCLUDE_PATHS"
[[ -n "${INPUT_INCLUDE_PATHS:-}" ]] && ARGS="$ARGS --include-paths=$INPUT_INCLUDE_PATHS"

trufflehog git file://. --since-commit "$BASE" --branch HEAD $ARGS
