#!/usr/bin/env bash
set -euo pipefail

# ── input validation ──────────────────────────────────────────────────────────

build_number="${INPUT_BUILD_NUMBER:-$GITHUB_RUN_ID}"

if [[ ! "$build_number" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid build number '$build_number' (allowed: letters, digits, '.', '_', '-')"
    exit 1
fi

if ! curl --help all 2>/dev/null | grep -q -- '--aws-sigv4'; then
    echo "::error::curl on this runner cannot sign S3 requests (needs curl 7.75+), found: $(curl --version | head -1)"
    exit 1
fi

# ── credentials ───────────────────────────────────────────────────────────────

# Passing the keys as --user would expose them in the process list, which
# matters on shared self-hosted runners. A 0600 config file does not.
credentials="${RUNNER_TEMP}/qb-spaces-curl.conf"
(umask 077 && printf 'user = "%s:%s"\n' "$INPUT_ACCESS_KEY" "$INPUT_SECRET_KEY" > "$credentials")
trap 'rm -f "$credentials"' EXIT

# ── delete ────────────────────────────────────────────────────────────────────

endpoint="${SPACES_ENDPOINT:-https://${INPUT_SPACE_NAME}.${INPUT_SPACE_REGION}.digitaloceanspaces.com}"
prefix="${GITHUB_REPOSITORY##*/}/debug-symbols/${build_number}"
deleted=0

echo "Deleting debug symbols under '$prefix/'"

for platform in $INPUT_PLATFORMS; do
    archive="debug-symbols-${platform}.tar.gz"

    curl_status=0
    status="$(curl --silent --show-error --config "$credentials" \
        --request DELETE \
        --aws-sigv4 "aws:amz:${INPUT_SPACE_REGION}:s3" \
        --output /dev/null --write-out '%{http_code}' \
        "${endpoint}/${prefix}/${archive}")" || curl_status=$?

    if [[ "$curl_status" -ne 0 ]]; then
        echo "::warning::Could not reach ${endpoint} to delete '$archive' (curl exit $curl_status)"
        continue
    fi

    # S3 deletes are idempotent, so a missing key answers 204 just like a hit.
    case "$status" in
        200|204|404)
            deleted=$((deleted + 1))
            echo "Deleted $archive"
            ;;
        *)
            echo "::warning::Deleting '$archive' answered HTTP $status - it will stay in the Space"
            ;;
    esac
done

echo "Deleted $deleted of $(echo "$INPUT_PLATFORMS" | wc -w | tr -d ' ') key(s)"
