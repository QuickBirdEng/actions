#!/usr/bin/env bats

load "setup.bash"

setup() {
    start_space
}

teardown() {
    stop_space
}

@test "deletes the archive of every platform" {
    publish_archive "ios"
    publish_archive "android-apk"
    publish_archive "android-aab"
    run_delete
    [ "$status" -eq 0 ]
    [ -z "$(remaining_keys)" ]
}

@test "deletes only the platforms it was given" {
    publish_archive "ios"
    publish_archive "android-aab"
    INPUT_PLATFORMS="ios" \
    run_delete
    [ "$status" -eq 0 ]
    [ "$(remaining_keys)" = "debug-symbols-android-aab.tar.gz" ]
}

@test "a platform that was never stored is not an error" {
    publish_archive "ios"
    run_delete
    [ "$status" -eq 0 ]
    [ -z "$(remaining_keys)" ]
}

@test "reports how many keys it removed" {
    publish_archive "ios"
    INPUT_PLATFORMS="ios android-aab" \
    run_delete
    [ "$status" -eq 0 ]
    [[ "$output" == *"Deleted 2 of 2 key(s)"* ]]
}

@test "leaves the archives of other builds alone" {
    publish_archive "ios"
    mkdir -p "${SPACE_ROOT}/kaarlo-mobile/debug-symbols/1700000000"
    echo "other" > "${SPACE_ROOT}/kaarlo-mobile/debug-symbols/1700000000/debug-symbols-ios.tar.gz"
    run_delete
    [ "$status" -eq 0 ]
    [ -f "${SPACE_ROOT}/kaarlo-mobile/debug-symbols/1700000000/debug-symbols-ios.tar.gz" ]
}

@test "a rejected delete warns instead of failing the job" {
    publish_archive "ios"
    INPUT_PLATFORMS="forbidden" \
    run_delete
    [ "$status" -eq 0 ]
    [[ "$output" == *"::warning::Deleting 'debug-symbols-forbidden.tar.gz' answered HTTP 403"* ]]
}

@test "an unreachable Space warns instead of failing the job" {
    stop_space
    SPACES_ENDPOINT="http://127.0.0.1:${SPACE_PORT}" \
    run_delete
    [ "$status" -eq 0 ]
    [[ "$output" == *"::warning::Could not reach"* ]]
}

@test "an invalid build number is rejected before any request" {
    INPUT_BUILD_NUMBER="../../etc" \
    run_delete
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Invalid build number"* ]]
}

@test "the build number falls back to the run id" {
    INPUT_BUILD_NUMBER="" \
    run_delete
    [ "$status" -eq 0 ]
    [[ "$output" == *"kaarlo-mobile/debug-symbols/16512345678/"* ]]
}

@test "the credentials file is removed when the script exits" {
    publish_archive "ios"
    run_delete
    [ "$status" -eq 0 ]
    [ ! -f "${BATS_TEST_TMPDIR}/temp/qb-spaces-curl.conf" ]
}
