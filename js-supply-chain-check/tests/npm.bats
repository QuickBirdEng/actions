#!/usr/bin/env bats

load "setup.bash"

# ── npm-exotic ────────────────────────────────────────────────────────────────

@test "npm-exotic: exits 1" {
    run_script "npm-exotic"
    [ "$status" -eq 1 ]
}

@test "npm-exotic: emits ::error for npm release-age limitation" {
    run_script "npm-exotic"
    [[ "$output" == *"npm cannot enforce minimumReleaseAge"* ]]
}

@test "npm-exotic: emits ::error for exotic dep in package-lock.json" {
    run_script "npm-exotic"
    [[ "$output" == *"Exotic dep 'shady-fork' in package-lock.json"* ]]
}

@test "npm-exotic: emits ::error for missing ignore-scripts" {
    run_script "npm-exotic"
    [[ "$output" == *"ignore-scripts must be true"* ]]
}

@test "npm-exotic: reports 3 errors in summary" {
    run_script "npm-exotic"
    [[ "$output" == *"Errors:           3"* ]]
}

# ── npm-ok ────────────────────────────────────────────────────────────────────

@test "npm-ok: with release-age disabled, exits 0" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/npm-ok" \
        INPUT_FAIL_ON_FOUND=true \
        INPUT_MINIMUM_RELEASE_AGE_MINUTES=0 \
        bash "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *"::error"* ]]
}

@test "npm-ok: still emits release-age error with default settings" {
    run_script "npm-ok"
    [ "$status" -eq 1 ]
    [[ "$output" == *"npm cannot enforce minimumReleaseAge"* ]]
}

@test "npm-ok: no exotic-dep error when all deps are from registry" {
    FAIL_ON_FOUND=false run_script "npm-ok"
    [[ "$output" != *"Exotic dep"* ]]
}

@test "npm-ok: no install-scripts error when ignore-scripts=true" {
    FAIL_ON_FOUND=false run_script "npm-ok"
    [[ "$output" != *"ignore-scripts must be true"* ]]
}
