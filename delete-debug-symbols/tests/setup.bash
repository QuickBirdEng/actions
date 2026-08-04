TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
SCRIPT="${TESTS_DIR}/../scripts/delete_debug_symbols.sh"
FAKE_SPACE="${TESTS_DIR}/fake_space.py"

BUILD_NUMBER="1764500000"
KEY_PREFIX="kaarlo-mobile/debug-symbols/${BUILD_NUMBER}"

start_space() {
    SPACE_ROOT="${BATS_TEST_TMPDIR}/space"
    mkdir -p "${SPACE_ROOT}/${KEY_PREFIX}"
    SPACE_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    SPACES_ENDPOINT="http://127.0.0.1:${SPACE_PORT}"

    python3 "$FAKE_SPACE" "$SPACE_ROOT" "$SPACE_PORT" >/dev/null 2>&1 &
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

publish_archive() {
    local platform="$1"
    echo "archive" > "${SPACE_ROOT}/${KEY_PREFIX}/debug-symbols-${platform}.tar.gz"
}

run_delete() {
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
        bash "$SCRIPT"
}

remaining_keys() {
    ls -1 "${SPACE_ROOT}/${KEY_PREFIX}" 2>/dev/null | sort
}
