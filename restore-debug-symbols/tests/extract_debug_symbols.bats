#!/usr/bin/env bats

load "setup.bash"

setup() {
    DOWNLOAD_DIR="${BATS_TEST_TMPDIR}/temp/qb-debug-symbols-download"
    mkdir -p "$DOWNLOAD_DIR"
}

stage_downloaded() {
    make_archive "$1" "${DOWNLOAD_DIR}/debug-symbols-$1.tar.gz" ${2+"$2"}
}

@test "extracts every archive into a folder named after its platform" {
    stage_downloaded "ios"
    stage_downloaded "android-aab"
    run_extract
    [ "$status" -eq 0 ]
    [ "$(github_output_value found)" = "true" ]
    [ "$(github_output_value platforms)" = "android-aab ios" ]
    [ -f "${WORKSPACE}/debug-symbols/ios/dsyms/App" ]
    [ -f "${WORKSPACE}/debug-symbols/android-aab/proguard/mapping.txt" ]
}

@test "reports the directory it extracted into" {
    stage_downloaded "ios"
    run_extract
    [ "$status" -eq 0 ]
    [ "$(github_output_value symbols-dir)" = "debug-symbols" ]
}

@test "honours a custom destination" {
    stage_downloaded "ios"
    INPUT_DESTINATION="symbols" \
    run_extract
    [ "$status" -eq 0 ]
    [ -f "${WORKSPACE}/symbols/ios/dsyms/App" ]
    [ "$(github_output_value symbols-dir)" = "symbols" ]
}

@test "recovers the release name from the archive metadata" {
    stage_downloaded "ios" "2.0.0+1764500000"
    run_extract
    [ "$status" -eq 0 ]
    [ "$(github_output_value release)" = "2.0.0+1764500000" ]
}

@test "an archive without a release name yields an empty release" {
    stage_downloaded "ios" ""
    run_extract
    [ "$status" -eq 0 ]
    [ -z "$(github_output_value release)" ]
}

@test "a stale destination from a previous attempt is cleared" {
    stage_downloaded "ios"
    run_extract
    [ "$status" -eq 0 ]
    touch "${WORKSPACE}/debug-symbols/stale.txt"
    run_extract
    [ "$status" -eq 0 ]
    [ ! -f "${WORKSPACE}/debug-symbols/stale.txt" ]
}

@test "an empty destination is rejected before anything is deleted" {
    stage_downloaded "ios"
    INPUT_DESTINATION="" \
    run_extract
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::destination must not be empty"* ]]
    # the working directory must be untouched
    [ -d "${WORKSPACE}" ]
    [ -f "${DOWNLOAD_DIR}/debug-symbols-ios.tar.gz" ]
}

@test "fails when nothing was downloaded" {
    run_extract
    [ "$status" -eq 1 ]
    [ "$(github_output_value found)" = "false" ]
    [[ "$output" == *"::error::No debug symbols were stored for this build"* ]]
}

@test "warns instead of failing when fail-if-empty is false" {
    INPUT_FAIL_IF_EMPTY="false" \
    run_extract
    [ "$status" -eq 0 ]
    [ "$(github_output_value found)" = "false" ]
    [[ "$output" == *"::warning::No debug symbols were stored for this build"* ]]
}
