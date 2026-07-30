#!/usr/bin/env bash
set -euo pipefail

# ── input validation ──────────────────────────────────────────────────────────

# The build number becomes a path segment in the Space, so keep it to safe
# characters. It stays the same across a re-run of a single job.
build_number="${INPUT_BUILD_NUMBER:-$GITHUB_RUN_ID}"

if [[ ! "$build_number" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid build number '$build_number' (allowed: letters, digits, '.', '_', '-')"
    exit 1
fi

# ── curl capability ───────────────────────────────────────────────────────────

# curl signs the S3 requests itself since 7.75. Fail with a clear message
# instead of a confusing 403 when the runner ships something older.
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

download_dir="${RUNNER_TEMP}/qb-debug-symbols-download"
rm -rf "$download_dir"
mkdir -p "$download_dir"

endpoint="${SPACES_ENDPOINT:-https://${INPUT_SPACE_NAME}.${INPUT_SPACE_REGION}.digitaloceanspaces.com}"
prefix="${GITHUB_REPOSITORY##*/}/debug-symbols/${build_number}"
downloaded=0

# ── download ──────────────────────────────────────────────────────────────────

echo "Looking for debug symbols under '$prefix/'"

for platform in $INPUT_PLATFORMS; do
    archive="debug-symbols-${platform}.tar.gz"
    target="${download_dir}/${archive}"

    curl_status=0
    status="$(curl --silent --show-error --config "$credentials" \
        --aws-sigv4 "aws:amz:${INPUT_SPACE_REGION}:s3" \
        --output "$target" --write-out '%{http_code}' \
        "${endpoint}/${prefix}/${archive}")" || curl_status=$?

    if [[ "$curl_status" -ne 0 ]]; then
        echo "::error::Downloading '$archive' failed, could not reach ${endpoint} (curl exit $curl_status)"
        exit 1
    fi

    case "$status" in
        200)
            downloaded=$((downloaded + 1))
            echo "Downloaded $archive"
            ;;
        404)
            rm -f "$target"
            echo "No symbols stored for '$platform'"
            ;;
        *)
            echo "::error::Downloading '$archive' failed with HTTP $status"
            cat "$target" || true
            exit 1
            ;;
    esac
done

echo "Downloaded $downloaded archive(s)"
