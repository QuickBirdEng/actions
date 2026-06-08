#!/usr/bin/env bash
set -euo pipefail

BASE_FILE="${INPUT_BASE_EXCLUDE_PATHS:-}"
CONSUMER_FILE="${INPUT_CONSUMER_FILE:-.qb/security/trufflehog-ignores.yaml}"
MERGED="${RUNNER_TEMP:-/tmp}/trufflehog-excludes-merged.txt"

CONSUMER_PATHS=""
if [ -f "$CONSUMER_FILE" ]; then
  CONSUMER_PATHS=$(yq '.paths[]' "$CONSUMER_FILE" 2>/dev/null || true)
  ACK_COUNT=$(yq '.acknowledged_findings | length' "$CONSUMER_FILE" 2>/dev/null || echo "0")
  if [ "${ACK_COUNT:-0}" != "0" ]; then
    echo "::notice::acknowledged_findings in $CONSUMER_FILE are only applied in the nightly org-wide scan, not in PR scans"
  fi
fi

if [ -n "$BASE_FILE" ] && [ -n "$CONSUMER_PATHS" ]; then
  cat "$BASE_FILE" > "$MERGED"
  echo "$CONSUMER_PATHS" >> "$MERGED"
  COUNT=$(wc -l < "$MERGED" | xargs)
  echo "Merged $COUNT exclude pattern(s) from base file + consumer ignore file"
  echo "file=$MERGED" >> "$GITHUB_OUTPUT"
elif [ -n "$CONSUMER_PATHS" ]; then
  echo "$CONSUMER_PATHS" > "$MERGED"
  COUNT=$(wc -l < "$MERGED" | xargs)
  echo "Loaded $COUNT exclude pattern(s) from consumer ignore file"
  echo "file=$MERGED" >> "$GITHUB_OUTPUT"
elif [ -n "$BASE_FILE" ]; then
  echo "Using base exclude-paths file (no consumer ignore file found)"
  echo "file=$BASE_FILE" >> "$GITHUB_OUTPUT"
else
  echo "No TruffleHog exclude paths configured"
fi
