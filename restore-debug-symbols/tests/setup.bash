TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
DOWNLOAD_SCRIPT="${TESTS_DIR}/../scripts/download_debug_symbols.sh"
EXTRACT_SCRIPT="${TESTS_DIR}/../scripts/extract_debug_symbols.sh"

BUILD_NUMBER="1764500000"
KEY_PREFIX="kaarlo-mobile/debug-symbols/${BUILD_NUMBER}"

# Build an archive with the layout store-debug-symbols produces.
make_archive() {
    local platform="$1" target="$2" release="${3-1.4.0+${BUILD_NUMBER}}"
    local staging="${BATS_TEST_TMPDIR}/staging-${platform}"

    rm -rf "$staging"
    mkdir -p "${staging}/dsyms" "${staging}/dart-symbols" "${staging}/proguard"
    echo "dwarf" > "${staging}/dsyms/App"
    echo "symbols" > "${staging}/dart-symbols/app.${platform}.symbols"
    echo '{"a":"b"}' > "${staging}/dart-symbols/obfuscation.map.json"
    echo "mapping" > "${staging}/proguard/mapping.txt"
    printf 'platform=%s\nrelease=%s\nbuild_number=%s\n' "$platform" "$release" "$BUILD_NUMBER" > "${staging}/metadata.env"

    mkdir -p "$(dirname "$target")"
    tar -C "$staging" -czf "$target" .
}

# Serve a directory over HTTP so the download script can be exercised end to end.
start_space() {
    SPACE_ROOT="${BATS_TEST_TMPDIR}/space"
    mkdir -p "$SPACE_ROOT"
    SPACE_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    SPACES_ENDPOINT="http://127.0.0.1:${SPACE_PORT}"

    python3 -m http.server "$SPACE_PORT" --bind 127.0.0.1 --directory "$SPACE_ROOT" >/dev/null 2>&1 &
    SPACE_PID="$!"

    local attempt=0
    until curl --silent --output /dev/null "${SPACES_ENDPOINT}/"; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 50 ] || {
            echo "the test HTTP server did not come up" >&2
            return 1
        }
        sleep 0.1
    done
}

stop_space() {
    [ -n "${SPACE_PID:-}" ] && kill "$SPACE_PID" 2>/dev/null
    return 0
}

# Put an archive into the served "Space" under the key the action looks for.
publish_archive() {
    local platform="$1"
    make_archive "$platform" "${SPACE_ROOT}/${KEY_PREFIX}/debug-symbols-${platform}.tar.gz"
}

run_download() {
    mkdir -p "${BATS_TEST_TMPDIR}/temp"
    run env \
        RUNNER_TEMP="${BATS_TEST_TMPDIR}/temp" \
        GITHUB_REPOSITORY="QuickBirdEng/kaarlo-mobile" \
        GITHUB_RUN_ID="16512345678" \
        SPACES_ENDPOINT="${SPACES_ENDPOINT:-}" \
        INPUT_ACCESS_KEY="DO00ACCESSKEY" \
        INPUT_SECRET_KEY="s3cr3t/key+with=chars" \
        INPUT_SPACE_NAME="quickbird-artifacts" \
        INPUT_SPACE_REGION="fra1" \
        INPUT_BUILD_NUMBER="${INPUT_BUILD_NUMBER-$BUILD_NUMBER}" \
        INPUT_PLATFORMS="${INPUT_PLATFORMS-ios android-apk android-aab}" \
        bash "$DOWNLOAD_SCRIPT"
}

run_extract() {
    mkdir -p "${BATS_TEST_TMPDIR}/temp"
    GITHUB_OUTPUT_FILE="$(mktemp)"
    WORKSPACE="${BATS_TEST_TMPDIR}/workspace"
    mkdir -p "$WORKSPACE"
    cd "$WORKSPACE"
    run env \
        RUNNER_TEMP="${BATS_TEST_TMPDIR}/temp" \
        GITHUB_OUTPUT="${GITHUB_OUTPUT_FILE}" \
        INPUT_DESTINATION="${INPUT_DESTINATION-debug-symbols}" \
        INPUT_FAIL_IF_EMPTY="${INPUT_FAIL_IF_EMPTY-true}" \
        bash "$EXTRACT_SCRIPT"
    if [ -s "$GITHUB_OUTPUT_FILE" ]; then
        output="${output}"$'\n'"$(cat "$GITHUB_OUTPUT_FILE")"
    fi
}

# Return the value of a key written to GITHUB_OUTPUT by the script.
github_output_value() {
    local key="$1"
    grep "^${key}=" "$GITHUB_OUTPUT_FILE" | tail -1 | cut -d= -f2-
}

downloaded_archives() {
    ls -1 "${BATS_TEST_TMPDIR}/temp/qb-debug-symbols-download" 2>/dev/null | sort
}
