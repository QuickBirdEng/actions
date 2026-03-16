#!/usr/bin/env bash
set -euo pipefail

BASE="${INPUT_BASE:-}"
if [[ -z "$BASE" ]]; then
    REF="${GITHUB_BASE_REF:-$DEFAULT_BRANCH}"
    BASE="$(git rev-parse "origin/$REF")"
fi

ARGS="--no-verification --fail --no-update"
[[ -n "${INPUT_EXCLUDE_PATHS:-}" ]] && ARGS="$ARGS --exclude-paths=$INPUT_EXCLUDE_PATHS"
[[ -n "${INPUT_INCLUDE_PATHS:-}" ]] && ARGS="$ARGS --include-paths=$INPUT_INCLUDE_PATHS"

docker run --rm \
  ghcr.io/trufflesecurity/trufflehog:latest \
  git \
  "https://oauth2:$GITHUB_TOKEN@github.com/$GITHUB_REPOSITORY.git" \
  --since-commit="$BASE" \
  --branch="$GITHUB_HEAD_REF" \
  $ARGS
