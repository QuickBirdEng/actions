#!/usr/bin/env bash
set -euo pipefail

BASE="${INPUT_BASE:-}"
if [[ -z "$BASE" ]]; then
    REF="${GITHUB_BASE_REF:-$DEFAULT_BRANCH}"
    BASE="$(git rev-parse "origin/$REF")"
fi

ARGS="--only-verified --no-update --json"
[[ -n "${INPUT_EXCLUDE_PATHS:-}" ]] && ARGS="$ARGS --exclude-paths=$INPUT_EXCLUDE_PATHS"
[[ -n "${INPUT_INCLUDE_PATHS:-}" ]] && ARGS="$ARGS --include-paths=$INPUT_INCLUDE_PATHS"

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

docker run --rm \
  ghcr.io/trufflesecurity/trufflehog:latest \
  git \
  "https://oauth2:$GITHUB_TOKEN@github.com/$GITHUB_REPOSITORY.git" \
  --since-commit="$BASE" \
  --branch="$GITHUB_HEAD_REF" \
  $ARGS > "$TMPFILE"

python3 - "$TMPFILE" << 'PYEOF'
import sys, json

def find_git_metadata(node):
    """Recursively search for the dict that contains a 'file' key."""
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
        print(json.dumps(d.get('SourceMetadata')), file=sys.stderr)
        git = find_git_metadata(d.get('SourceMetadata', {}))
        file_path = git.get('file', git.get('File', ''))
        line_num = git.get('line', git.get('Line', 1)) or 1
        detector = d.get('DetectorName', 'Unknown')
        verified = 'verified' if d.get('Verified', False) else 'unverified'
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
