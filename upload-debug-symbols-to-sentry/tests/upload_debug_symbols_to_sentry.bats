#!/usr/bin/env bats

load "setup.bash"

setup() {
    stub_sentry_cli
    setup_restored_symbols
}

# ── Restored directory ────────────────────────────────────────────────────────

@test "uploads dSYMs, dart symbols, obfuscation maps and the mapping of every platform" {
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    [ "$(sentry_call_count)" -eq 6 ]
    sentry_calls | grep -q "debug-files upload --org quickbird --project kaarlo debug-symbols/ios/dsyms$"
    sentry_calls | grep -q "debug-files upload --org quickbird --project kaarlo debug-symbols/ios/dart-symbols$"
    sentry_calls | grep -q "debug-files upload --org quickbird --project kaarlo debug-symbols/android-aab/dart-symbols$"
    sentry_calls | grep -q "upload-proguard --org quickbird --project kaarlo debug-symbols/android-aab/proguard/mapping.txt$"
    [ "$(sentry_calls | grep -c 'dart-symbol-map upload')" -eq 2 ]
}

@test "every call targets the configured sentry server" {
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    [ "$(sentry_calls | grep -c '^--url https://sentry.quickbirdstudios.com ')" -eq 6 ]
}

@test "falls back to sentry.io when no url is configured" {
    INPUT_URL="" \
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    [ "$(sentry_calls | grep -c '^--url https://sentry.io ')" -eq 6 ]
}

@test "the auth token never reaches the command line" {
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    ! sentry_calls | grep -q "secret-token"
}

@test "the metadata file is never uploaded as a debug file" {
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    ! sentry_calls | grep -q "metadata.env"
}

@test "a failing sentry-cli fails the step" {
    stub_sentry_cli 'echo boom >&2; exit 1'
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -ne 0 ]
}

@test "a symbols dir without any symbols is an error" {
    mkdir -p "${WORKSPACE}/empty/some-platform"
    INPUT_SYMBOLS_DIR="empty" \
    run_upload
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::No debug symbols found under 'empty'"* ]]
    [ "$(sentry_call_count)" -eq 0 ]
}

@test "a missing symbols dir is an error" {
    INPUT_SYMBOLS_DIR="does-not-exist" \
    run_upload
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::symbols-dir 'does-not-exist' does not exist"* ]]
}

@test "a platform folder holding only dSYMs is uploaded" {
    rm -rf "${WORKSPACE}/debug-symbols/android-aab" "${WORKSPACE}/debug-symbols/ios/dart-symbols"
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    [ "$(sentry_call_count)" -eq 1 ]
}

@test "dart symbols without an obfuscation map skip the map upload" {
    rm -f "${WORKSPACE}/debug-symbols/ios/dart-symbols/obfuscation.map.json"
    rm -rf "${WORKSPACE}/debug-symbols/android-aab"
    INPUT_SYMBOLS_DIR="debug-symbols" \
    run_upload
    [ "$status" -eq 0 ]
    ! sentry_calls | grep -q "dart-symbol-map upload"
}

# ── Explicit paths ────────────────────────────────────────────────────────────

@test "uploads from the individual path inputs" {
    setup_build_outputs
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    INPUT_DART_SYMBOLS_FILE_PATH="app_symbols" \
    INPUT_DART_OBFUSCATION_MAP_FILE_PATH="app_symbols/obfuscation.map.json" \
    INPUT_PROGUARD_MAPPING_FILE_PATH="mapping.txt" \
    run_upload
    [ "$status" -eq 0 ]
    sentry_calls | grep -q "debug-files upload --org quickbird --project kaarlo app_symbols$"
    sentry_calls | grep -q "dart-symbol-map upload --org quickbird --project kaarlo app_symbols/obfuscation.map.json app_symbols/app.ios-arm64.symbols$"
    sentry_calls | grep -q "debug-files upload --org quickbird --project kaarlo build/ios/archive/Runner.xcarchive/dSYMs$"
    sentry_calls | grep -q "upload-proguard --org quickbird --project kaarlo mapping.txt$"
}

@test "a path that does not exist warns and is skipped" {
    setup_build_outputs
    INPUT_DSYMS_PATH="nope" \
    INPUT_PROGUARD_MAPPING_FILE_PATH="also-nope.txt" \
    run_upload
    [ "$status" -eq 0 ]
    [[ "$output" == *"::warning::No dSYMs found at 'nope' - skipping"* ]]
    [[ "$output" == *"::warning::No proguard mapping found at 'also-nope.txt' - skipping"* ]]
    [ "$(sentry_call_count)" -eq 0 ]
}

@test "no inputs at all warns instead of failing" {
    run_upload
    [ "$status" -eq 0 ]
    [[ "$output" == *"::warning::Nothing was uploaded to Sentry"* ]]
    [ "$(sentry_call_count)" -eq 0 ]
}
