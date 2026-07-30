TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
SCRIPT="${TESTS_DIR}/../scripts/store_debug_symbols.sh"

setup_build_outputs() {
    WORKSPACE="${BATS_TEST_TMPDIR}/workspace"
    mkdir -p "${WORKSPACE}/build/ios/archive/Runner.xcarchive/dSYMs/Runner.app.dSYM/Contents/Resources/DWARF"
    echo "dwarf" > "${WORKSPACE}/build/ios/archive/Runner.xcarchive/dSYMs/Runner.app.dSYM/Contents/Resources/DWARF/Runner"
    mkdir -p "${WORKSPACE}/app_symbols"
    echo "symbols" > "${WORKSPACE}/app_symbols/app.ios-arm64.symbols"
    echo '{"a":"b"}' > "${WORKSPACE}/app_symbols/obfuscation.map.json"
    mkdir -p "${WORKSPACE}/build/app/outputs/mapping/release"
    echo "com.example.App -> a.a:" > "${WORKSPACE}/build/app/outputs/mapping/release/mapping.txt"
}

run_store() {
    GITHUB_OUTPUT_FILE="$(mktemp)"
    cd "${WORKSPACE}"
    run env \
        RUNNER_TEMP="${BATS_TEST_TMPDIR}/temp" \
        GITHUB_OUTPUT="${GITHUB_OUTPUT_FILE}" \
        GITHUB_REPOSITORY="QuickBirdEng/kaarlo-mobile" \
        GITHUB_RUN_ID="16512345678" \
        GITHUB_RUN_ATTEMPT="1" \
        GITHUB_SHA="deadbeef" \
        GITHUB_REF="refs/tags/1.4.0" \
        INPUT_PLATFORM="${INPUT_PLATFORM-ios}" \
        INPUT_BUILD_NUMBER="${INPUT_BUILD_NUMBER:-}" \
        INPUT_DSYMS_PATH="${INPUT_DSYMS_PATH:-}" \
        INPUT_PROGUARD_MAPPING_FILE_PATH="${INPUT_PROGUARD_MAPPING_FILE_PATH:-}" \
        INPUT_DART_SYMBOLS_FILE_PATH="${INPUT_DART_SYMBOLS_FILE_PATH:-}" \
        INPUT_DART_OBFUSCATION_MAP_FILE_PATH="${INPUT_DART_OBFUSCATION_MAP_FILE_PATH:-}" \
        INPUT_RELEASE="${INPUT_RELEASE:-}" \
        bash "$SCRIPT"
    if [ -s "$GITHUB_OUTPUT_FILE" ]; then
        output="${output}"$'\n'"$(cat "$GITHUB_OUTPUT_FILE")"
    fi
}

# Return the value of a key written to GITHUB_OUTPUT by the script.
github_output_value() {
    local key="$1"
    grep "^${key}=" "$GITHUB_OUTPUT_FILE" | tail -1 | cut -d= -f2-
}

# List the paths inside the archive the script produced.
archive_contents() {
    tar -tzf "$(github_output_value archive)" | sed 's|^\./||' | grep -v '^$' | sort
}
