#!/usr/bin/env bash
set -euo pipefail

# ── Resolve base commit ──────────────────────────────────────────────────────
BASE="${INPUT_BASE:-}"
if [[ -z "$BASE" ]]; then
    REF="${GITHUB_BASE_REF:-$DEFAULT_BRANCH}"
    BASE="$(git rev-parse "origin/$REF")"
fi

HEAD_SHA="$(git rev-parse HEAD)"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ── Resolve TruffleHog version ───────────────────────────────────────────────
VERSION="${INPUT_VERSION:-}"
if [[ -z "$VERSION" ]]; then
    VERSION=$(curl -sSf "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")
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

"$TRUFFLEHOG" git \
    "file://$GITHUB_WORKSPACE" \
    --since-commit="$BASE" \
    --branch="$HEAD_SHA" \
    $ARGS > "$OUTFILE" || true

# ── Emit annotations ──────────────────────────────────────────────────────────
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
