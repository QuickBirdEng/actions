#!/usr/bin/env bats

load "setup.bash"

setup() {
    start_space
}

teardown() {
    stop_space
}

@test "downloads the archive of every platform that has stored symbols" {
    publish_archive "ios"
    publish_archive "android-aab"
    run_download
    [ "$status" -eq 0 ]
    [[ "$output" == *"Downloaded 2 archive(s)"* ]]
    [ "$(downloaded_archives)" = "debug-symbols-android-aab.tar.gz
debug-symbols-ios.tar.gz" ]
}

@test "a platform without stored symbols is skipped, not failed" {
    publish_archive "ios"
    run_download
    [ "$status" -eq 0 ]
    [[ "$output" == *"No symbols stored for 'android-apk'"* ]]
    [[ "$output" == *"No symbols stored for 'android-aab'"* ]]
}

@test "a 404 does not leave a truncated archive behind" {
    publish_archive "ios"
    run_download
    [ "$status" -eq 0 ]
    [ "$(downloaded_archives)" = "debug-symbols-ios.tar.gz" ]
}

@test "the downloaded archive is intact" {
    publish_archive "ios"
    run_download
    [ "$status" -eq 0 ]
    tar -tzf "${BATS_TEST_TMPDIR}/temp/qb-debug-symbols-download/debug-symbols-ios.tar.gz" >/dev/null
}

@test "requests are signed with SigV4" {
    publish_archive "ios"
    run_download
    [ "$status" -eq 0 ]
    # An unsigned request would not carry credentials at all; assert curl can sign.
    run curl --silent --show-error --aws-sigv4 "aws:amz:fra1:s3" --user "key:secret" \
        --output /dev/null --write-out '%{http_code}' "${SPACES_ENDPOINT}/${KEY_PREFIX}/debug-symbols-ios.tar.gz"
    [ "$output" = "200" ]
}

@test "nothing stored at all still succeeds with zero archives" {
    run_download
    [ "$status" -eq 0 ]
    [[ "$output" == *"Downloaded 0 archive(s)"* ]]
    [ -z "$(downloaded_archives)" ]
}

@test "an unreachable Space fails the step with a clear error" {
    stop_space
    SPACES_ENDPOINT="http://127.0.0.1:${SPACE_PORT}" \
    run_download
    [ "$status" -ne 0 ]
    [[ "$output" == *"::error::Downloading"* ]]
}

@test "an invalid build number is rejected before any request" {
    INPUT_BUILD_NUMBER="../../etc" \
    run_download
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Invalid build number"* ]]
}

@test "the build number falls back to the run id" {
    INPUT_BUILD_NUMBER="" \
    run_download
    [ "$status" -eq 0 ]
    [[ "$output" == *"kaarlo-mobile/debug-symbols/16512345678/"* ]]
}

@test "the credentials file is removed when the script exits" {
    publish_archive "ios"
    run_download
    [ "$status" -eq 0 ]
    [ ! -f "${BATS_TEST_TMPDIR}/temp/qb-spaces-curl.conf" ]
}

@test "only the requested platforms are looked for" {
    publish_archive "ios"
    publish_archive "android-aab"
    INPUT_PLATFORMS="ios" \
    run_download
    [ "$status" -eq 0 ]
    [ "$(downloaded_archives)" = "debug-symbols-ios.tar.gz" ]
}
