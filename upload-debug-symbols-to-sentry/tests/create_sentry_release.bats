#!/usr/bin/env bats

load "setup.bash"

setup() {
    stub_sentry_cli
}

@test "creates, associates commits and finalizes, in that order" {
    run_release
    [ "$status" -eq 0 ]
    [ "$(sentry_subcommands)" = "new
set-commits
finalize" ]
}

@test "associates commits automatically from the git history" {
    run_release
    [ "$status" -eq 0 ]
    sentry_calls | grep -q "set-commits 1.4.0+1764500000 --auto$"
}

@test "the release is finalized even when the commit association fails" {
    stub_sentry_cli 'if [[ "$*" == *set-commits* ]]; then echo "could not find commits" >&2; exit 1; fi; exit 0'
    run_release
    [ "$status" -ne 0 ]
    sentry_calls | grep -q "finalize 1.4.0+1764500000$"
}

@test "a failed commit association fails the step with an actionable error" {
    stub_sentry_cli 'if [[ "$*" == *set-commits* ]]; then exit 1; fi; exit 0'
    run_release
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::Could not associate commits with release '1.4.0+1764500000'"* ]]
    [[ "$output" == *"fetch-depth: 0"* ]]
}

@test "a failed finalize fails the step" {
    stub_sentry_cli 'if [[ "$*" == *finalize* ]]; then exit 1; fi; exit 0'
    run_release
    [ "$status" -ne 0 ]
}

@test "a failed create stops before finalizing" {
    stub_sentry_cli 'if [[ "$*" == *" new "* ]]; then exit 1; fi; exit 0'
    run_release
    [ "$status" -ne 0 ]
    ! sentry_calls | grep -q "finalize"
}

@test "the auth token never reaches the command line" {
    run_release
    [ "$status" -eq 0 ]
    ! sentry_calls | grep -q "secret-token"
}

@test "falls back to sentry.io when no url is configured" {
    INPUT_URL="" \
    run_release
    [ "$status" -eq 0 ]
    [ "$(sentry_calls | grep -c '^--url https://sentry.io ')" -eq 3 ]
}
