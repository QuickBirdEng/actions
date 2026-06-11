#!/usr/bin/env bash

# This script needs bash >= 4.3 (declare -A) plus Linux-only tooling
# (sha256sum, linux cosign/trufflehog binaries) and is only supported on
# Linux runners. macOS ships bash 3.2 — fail fast with an actionable message.
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
    echo "::error::trufflehog-scan only supports Linux runners with bash >= 4.3 (this runner: $(uname -s), bash ${BASH_VERSION}). Route this job to a Linux runner label instead of bare 'self-hosted'."
    exit 1
fi

set -euo pipefail

# ── Resolve base commit ──────────────────────────────────────────────────────
# When INPUT_BASE is provided, scan from that commit to HEAD.
# Otherwise scan the full git history.
BASE="${INPUT_BASE:-}"

HEAD_SHA="$(git rev-parse HEAD)"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ── Resolve TruffleHog version ───────────────────────────────────────────────
VERSION="${INPUT_VERSION:-}"
if [[ -z "$VERSION" ]]; then
    MIN_AGE_DAYS="${INPUT_MIN_AGE_DAYS:-3}"
    VERSION=$(curl -sSf "https://api.github.com/repos/trufflesecurity/trufflehog/releases?per_page=30" \
        | jq -r --argjson days "$MIN_AGE_DAYS" '
            map(select(
                .draft == false and
                .prerelease == false and
                (.published_at | fromdateiso8601) <= (now - ($days * 86400))
            )) | first | .tag_name | ltrimstr("v")')
    if [[ -z "$VERSION" || "$VERSION" == "null" ]]; then
        echo "::error::No TruffleHog release found that is at least ${MIN_AGE_DAYS} day(s) old."
        exit 1
    fi
fi

ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]]  && ARCH="amd64"
[[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

# ── Download cosign (pinned, SHA256-verified) ─────────────────────────────────
# Pinned to cosign v3.0.5 — update both values together when bumping.
COSIGN_VERSION="3.0.5"
declare -A COSIGN_SHA256=(
    [amd64]="db15cc99e6e4837daabab023742aaddc3841ce57f193d11b7c3e06c8003642b2"
    [arm64]="d098f3168ae4b3aa70b4ca78947329b953272b487727d1722cb3cb098a1a20ab"
)
COSIGN_BIN="$TMPDIR/cosign"

curl -sSfL \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${ARCH}" \
    -o "$COSIGN_BIN"

echo "${COSIGN_SHA256[$ARCH]}  $COSIGN_BIN" | sha256sum -c
chmod +x "$COSIGN_BIN"

# ── Download TruffleHog artifacts ────────────────────────────────────────────
RELEASE_BASE="https://github.com/trufflesecurity/trufflehog/releases/download/v${VERSION}"
TARBALL_NAME="trufflehog_${VERSION}_linux_${ARCH}.tar.gz"

curl -sSfL "${RELEASE_BASE}/${TARBALL_NAME}"                          -o "$TMPDIR/${TARBALL_NAME}"
curl -sSfL "${RELEASE_BASE}/trufflehog_${VERSION}_checksums.txt"      -o "$TMPDIR/checksums.txt"
curl -sSfL "${RELEASE_BASE}/trufflehog_${VERSION}_checksums.txt.pem"  -o "$TMPDIR/checksums.txt.pem"
curl -sSfL "${RELEASE_BASE}/trufflehog_${VERSION}_checksums.txt.sig"  -o "$TMPDIR/checksums.txt.sig"

# ── Verify cosign signature on checksums file ─────────────────────────────────
"$COSIGN_BIN" verify-blob \
    --certificate         "$TMPDIR/checksums.txt.pem" \
    --signature           "$TMPDIR/checksums.txt.sig" \
    --certificate-identity-regexp "https://github.com/trufflesecurity/trufflehog/" \
    --certificate-oidc-issuer     "https://token.actions.githubusercontent.com" \
    "$TMPDIR/checksums.txt"

# ── Verify tarball SHA256 against checksums ───────────────────────────────────
(cd "$TMPDIR" && grep "${TARBALL_NAME}" checksums.txt | sha256sum -c)

# ── Extract binary ────────────────────────────────────────────────────────────
tar -xz -C "$TMPDIR" -f "$TMPDIR/${TARBALL_NAME}"
TRUFFLEHOG="$TMPDIR/trufflehog"
chmod +x "$TRUFFLEHOG"

# ── Build scan args ───────────────────────────────────────────────────────────
ARGS="--only-verified --no-update --json"
[[ -n "${INPUT_EXCLUDE_PATHS:-}" ]] && ARGS="$ARGS --exclude-paths=$INPUT_EXCLUDE_PATHS"
[[ -n "${INPUT_INCLUDE_PATHS:-}" ]] && ARGS="$ARGS --include-paths=$INPUT_INCLUDE_PATHS"

# ── Run scan ──────────────────────────────────────────────────────────────────
OUTFILE="$TMPDIR/findings.json"
ERRFILE="$TMPDIR/scan.err"

# GIT_LFS_SKIP_SMUDGE: trufflehog re-clones the repo into a temp dir and
# inherits the workspace's LFS config. With a broken/missing LFS pointer
# (e.g. dangling LFS object) the clone's checkout step fails and the scan
# never runs. LFS blobs are binary — irrelevant for secret-scanning text
# history — so skip smudge unconditionally.
SINCE_ARGS=""
[[ -n "$BASE" ]] && SINCE_ARGS="--since-commit=$BASE"

set +e
GIT_LFS_SKIP_SMUDGE=1 \
"$TRUFFLEHOG" git \
    "file://$GITHUB_WORKSPACE" \
    $SINCE_ARGS \
    --branch="$HEAD_SHA" \
    $ARGS > "$OUTFILE" 2> "$ERRFILE"
SCAN_EXIT=$?
set -e

# If trufflehog itself errored, surface that loudly rather than reporting a
# false "no secrets detected". A failed scan is NOT a passing scan.
if [[ $SCAN_EXIT -ne 0 ]]; then
    echo "::error::TruffleHog scan failed with exit code $SCAN_EXIT — see stderr below. This is NOT a passing scan."
    echo "----- TruffleHog stderr -----"
    cat "$ERRFILE"
    echo "----- end -----"
    exit "$SCAN_EXIT"
fi

# ── Copy findings to caller-specified output file (before cleanup) ────────────
if [[ -n "${INPUT_OUTPUT_FILE:-}" ]]; then
    cp "$OUTFILE" "$INPUT_OUTPUT_FILE"
fi

# ── Emit annotations ──────────────────────────────────────────────────────────
if [[ "${INPUT_ANNOTATIONS:-true}" == "true" ]]; then
python3 - "$OUTFILE" << 'PYEOF'
import sys, json

def find_git_metadata(node):
    if isinstance(node, dict):
        if 'file' in node or 'File' in node:
            return node
        for v in node.values():
            result = find_git_metadata(v)
            if result:
                return result
    return {}

count = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        git = find_git_metadata(d.get('SourceMetadata', {}))
        file_path = git.get('file', git.get('File', ''))
        line_num  = git.get('line', git.get('Line', 1)) or 1
        detector  = d.get('DetectorName', 'Unknown')
        verified  = 'verified' if d.get('Verified', False) else 'unverified'
        msg = f"TruffleHog [{detector}]: {verified} secret detected"
        if file_path:
            print(f"::error file={file_path},line={line_num}::{msg}")
        else:
            print(f"::error::{msg}")
        count += 1

if count > 0:
    print(f"TruffleHog found {count} secret(s).")
    sys.exit(1)
else:
    print("No secrets detected.")
PYEOF
else
    # annotations disabled — still exit non-zero if findings exist
    if [[ -s "$OUTFILE" ]]; then
        COUNT=$(grep -c . "$OUTFILE" || true)
        echo "TruffleHog found $COUNT secret(s). Annotations suppressed (annotations=false)."
        exit 1
    else
        echo "No secrets detected."
    fi
fi