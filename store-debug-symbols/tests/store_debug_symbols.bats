#!/usr/bin/env bats

load "setup.bash"

setup() {
    setup_build_outputs
}

# ── iOS ───────────────────────────────────────────────────────────────────────

@test "ios: collects dSYMs, dart symbols and the obfuscation map into one archive" {
    INPUT_PLATFORM="ios" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    INPUT_DART_SYMBOLS_FILE_PATH="app_symbols" \
    INPUT_DART_OBFUSCATION_MAP_FILE_PATH="app_symbols/obfuscation.map.json" \
    run_store
    [ "$status" -eq 0 ]
    [ "$(github_output_value stored)" = "true" ]
    archive_contents | grep -q "^dsyms/Runner.app.dSYM/Contents/Resources/DWARF/Runner$"
    archive_contents | grep -q "^dart-symbols/app.ios-arm64.symbols$"
    archive_contents | grep -q "^dart-symbols/obfuscation.map.json$"
    archive_contents | grep -q "^metadata.env$"
}

@test "ios: does not put a proguard mapping into the archive" {
    INPUT_PLATFORM="ios" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 0 ]
    ! archive_contents | grep -q "proguard"
}

# ── Android ───────────────────────────────────────────────────────────────────

@test "android: collects the proguard mapping under a fixed name" {
    INPUT_PLATFORM="android-aab" \
    INPUT_PROGUARD_MAPPING_FILE_PATH="build/app/outputs/mapping/release/mapping.txt" \
    INPUT_DART_SYMBOLS_FILE_PATH="app_symbols" \
    run_store
    [ "$status" -eq 0 ]
    archive_contents | grep -q "^proguard/mapping.txt$"
}

@test "the archive is named after the platform" {
    INPUT_PLATFORM="android-apk" \
    INPUT_PROGUARD_MAPPING_FILE_PATH="build/app/outputs/mapping/release/mapping.txt" \
    run_store
    [ "$status" -eq 0 ]
    [[ "$(github_output_value archive)" == *"/debug-symbols-android-apk.tar.gz" ]]
}

# ── Key prefix ────────────────────────────────────────────────────────────────

@test "key prefix uses the repository name and the build number" {
    INPUT_BUILD_NUMBER="1764500000" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 0 ]
    [ "$(github_output_value key-prefix)" = "kaarlo-mobile/debug-symbols/1764500000" ]
}

@test "key prefix falls back to the run id when no build number is given" {
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 0 ]
    [ "$(github_output_value key-prefix)" = "kaarlo-mobile/debug-symbols/16512345678" ]
}

@test "an invalid build number is rejected" {
    INPUT_BUILD_NUMBER="../../etc" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Invalid build number"* ]]
}

@test "an empty platform label is rejected" {
    INPUT_PLATFORM="" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Invalid platform label"* ]]
}

@test "an invalid platform label is rejected" {
    INPUT_PLATFORM="../evil" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Invalid platform label"* ]]
}

# ── Metadata ──────────────────────────────────────────────────────────────────

@test "the release name travels with the archive" {
    INPUT_BUILD_NUMBER="1764500000" \
    INPUT_RELEASE="1.4.0+1764500000" \
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    run_store
    [ "$status" -eq 0 ]
    tar -xzf "$(github_output_value archive)" -O ./metadata.env | grep -q "^release=1.4.0+1764500000$"
    tar -xzf "$(github_output_value archive)" -O ./metadata.env | grep -q "^build_number=1764500000$"
}

# ── Nothing to collect ────────────────────────────────────────────────────────

@test "fails when a requested path does not exist" {
    INPUT_PROGUARD_MAPPING_FILE_PATH="build/app/outputs/mapping/release/nope.txt" \
    run_store
    [ "$status" -eq 1 ]
    [ "$(github_output_value stored)" = "false" ]
    [[ "$output" == *"::error::None of the 1 requested debug symbol paths exist"* ]]
}

@test "warns but succeeds when no paths are given at all" {
    run_store
    [ "$status" -eq 0 ]
    [ "$(github_output_value stored)" = "false" ]
    [[ "$output" == *"::warning::No debug symbol paths given"* ]]
}

@test "skips a missing path but still stores what is there" {
    INPUT_DSYMS_PATH="build/ios/archive/Runner.xcarchive/dSYMs" \
    INPUT_PROGUARD_MAPPING_FILE_PATH="build/app/outputs/mapping/release/nope.txt" \
    run_store
    [ "$status" -eq 0 ]
    [ "$(github_output_value stored)" = "true" ]
    [[ "$output" == *"::warning::No ProGuard mapping found"* ]]
    archive_contents | grep -q "^dsyms/"
}

@test "an empty dSYMs folder counts as missing" {
    mkdir -p "${WORKSPACE}/empty-dsyms"
    INPUT_DSYMS_PATH="empty-dsyms" \
    run_store
    [ "$status" -eq 1 ]
    [ "$(github_output_value stored)" = "false" ]
}
