TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
UPLOAD_SCRIPT="${TESTS_DIR}/../scripts/upload_debug_symbols_to_sentry.sh"
RELEASE_SCRIPT="${TESTS_DIR}/../scripts/create_sentry_release.sh"

# Put a fake sentry-cli on PATH that records its arguments. The body decides
# whether the call succeeds, so failure handling can be exercised too.
stub_sentry_cli() {
    local body="${1:-exit 0}"
    STUB_DIR="${BATS_TEST_TMPDIR}/bin"
    CALLS="${BATS_TEST_TMPDIR}/sentry-calls.log"
    mkdir -p "$STUB_DIR"
    : > "$CALLS"
    {
        echo '#!/usr/bin/env bash'
        echo "echo \"\$*\" >> \"${CALLS}\""
        echo "$body"
    } > "${STUB_DIR}/sentry-cli"
    chmod +x "${STUB_DIR}/sentry-cli"
}

# Build the tree `actions/download-artifact` produces: one folder per artifact,
# each keeping the paths the build produced.
setup_downloaded_symbols() {
    WORKSPACE="${BATS_TEST_TMPDIR}/workspace"
    local ios="${WORKSPACE}/debug-symbols/debug-symbols-ios"
    mkdir -p "${ios}/build/ios/archive/Runner.xcarchive/dSYMs/App.dSYM/Contents/Resources/DWARF" "${ios}/app_symbols"
    echo "dwarf" > "${ios}/build/ios/archive/Runner.xcarchive/dSYMs/App.dSYM/Contents/Resources/DWARF/App"
    echo "symbols" > "${ios}/app_symbols/app.ios-arm64.symbols"
    echo '{"a":"b"}' > "${ios}/app_symbols/obfuscation.map.json"

    local android="${WORKSPACE}/debug-symbols/debug-symbols-android-aab"
    mkdir -p "${android}/build/app/outputs/mapping/release" "${android}/app_symbols"
    echo "mapping" > "${android}/build/app/outputs/mapping/release/mapping.txt"
    echo "symbols" > "${android}/app_symbols/app.android-arm64.symbols"
    echo '{"a":"b"}' > "${android}/app_symbols/obfuscation.map.json"
}

# And the raw build outputs, for the explicit-path inputs.
setup_build_outputs() {
    WORKSPACE="${WORKSPACE:-${BATS_TEST_TMPDIR}/workspace}"
    mkdir -p "${WORKSPACE}/build/ios/archive/Runner.xcarchive/dSYMs" "${WORKSPACE}/app_symbols"
    echo "dwarf" > "${WORKSPACE}/build/ios/archive/Runner.xcarchive/dSYMs/App"
    echo "symbols" > "${WORKSPACE}/app_symbols/app.ios-arm64.symbols"
    echo '{"a":"b"}' > "${WORKSPACE}/app_symbols/obfuscation.map.json"
    echo "mapping" > "${WORKSPACE}/mapping.txt"
}

run_upload() {
    cd "$WORKSPACE"
    run env \
        PATH="${STUB_DIR}:${PATH}" \
        SENTRY_AUTH_TOKEN="secret-token" \
        INPUT_URL="${INPUT_URL-https://sentry.quickbirdstudios.com}" \
        INPUT_ORGANIZATION="quickbird" \
        INPUT_PROJECT="kaarlo" \
        INPUT_SYMBOLS_DIR="${INPUT_SYMBOLS_DIR:-}" \
        INPUT_DSYMS_PATH="${INPUT_DSYMS_PATH:-}" \
        INPUT_PROGUARD_MAPPING_FILE_PATH="${INPUT_PROGUARD_MAPPING_FILE_PATH:-}" \
        INPUT_DART_SYMBOLS_FILE_PATH="${INPUT_DART_SYMBOLS_FILE_PATH:-}" \
        INPUT_DART_OBFUSCATION_MAP_FILE_PATH="${INPUT_DART_OBFUSCATION_MAP_FILE_PATH:-}" \
        bash "$UPLOAD_SCRIPT"
}

run_release() {
    run env \
        PATH="${STUB_DIR}:${PATH}" \
        SENTRY_AUTH_TOKEN="secret-token" \
        INPUT_URL="${INPUT_URL-https://sentry.quickbirdstudios.com}" \
        INPUT_ORGANIZATION="quickbird" \
        INPUT_RELEASE="${INPUT_RELEASE:-1.4.0+1764500000}" \
        bash "$RELEASE_SCRIPT"
}

sentry_calls() {
    cat "$CALLS"
}

sentry_call_count() {
    grep -c '.' "$CALLS" || true
}

# The subcommand of each recorded call, in order.
sentry_subcommands() {
    sed 's/^--url [^ ]* //' "$CALLS" | sed 's/^releases --org [^ ]* //' | cut -d' ' -f1
}
