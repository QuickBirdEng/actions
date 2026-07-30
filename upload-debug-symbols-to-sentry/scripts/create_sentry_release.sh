#!/usr/bin/env bash
set -euo pipefail

url="${INPUT_URL:-https://sentry.io}"

sentry-cli --url "$url" releases --org "$INPUT_ORGANIZATION" new "$INPUT_RELEASE"

# ── commit association ────────────────────────────────────────────────────────

# --auto reads the local git tree, so the job has to check out the full history
# (fetch-depth: 0). A shallow clone yields a single commit and no association.
commits_status=0
sentry-cli --url "$url" releases --org "$INPUT_ORGANIZATION" set-commits "$INPUT_RELEASE" --auto || commits_status=$?

# Finalize regardless, so a failed association never leaves a half-created
# release behind in Sentry. The failure is reported afterwards.
sentry-cli --url "$url" releases --org "$INPUT_ORGANIZATION" finalize "$INPUT_RELEASE"

if [[ "$commits_status" -ne 0 ]]; then
    echo "::error::Could not associate commits with release '$INPUT_RELEASE'. The checkout needs the full git history (fetch-depth: 0) for sentry-cli to see them."
    exit 1
fi
