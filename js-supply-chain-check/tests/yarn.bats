#!/usr/bin/env bats

load "setup.bash"

# ── yarn-berry-414-ok ─────────────────────────────────────────────────────────

@test "yarn-berry-414-ok: exits 0, no annotations" {
    run_script "yarn-berry-414-ok"
    [ "$status" -eq 0 ]
    [[ "$output" != *"::error"* ]]
    [[ "$output" != *"::warning"* ]]
}

@test "yarn-berry-414-ok: reports 0 errors in summary" {
    run_script "yarn-berry-414-ok"
    [[ "$output" == *"Errors:           0"* ]]
}

@test "yarn-berry-414-ok: scans exactly 1 project" {
    run_script "yarn-berry-414-ok"
    [[ "$output" == *"Projects scanned: 1"* ]]
}

# ── yarn-berry-age-too-low ───────────────────────────────────────────────────

@test "yarn-berry-age-too-low: exits 1 when npmMinimalAgeGate is set but below threshold" {
    run_script "yarn-berry-age-too-low"
    [ "$status" -eq 1 ]
}

@test "yarn-berry-age-too-low: emits ::error naming the actual value and required value" {
    run_script "yarn-berry-age-too-low"
    [[ "$output" == *"npmMinimalAgeGate=60 is below required 4320"* ]]
}

@test "yarn-berry-age-too-low: reports 1 error in summary" {
    run_script "yarn-berry-age-too-low"
    [[ "$output" == *"Errors:           1"* ]]
}

# ── yarn-berry-age-duration (duration strings: 1d < 7d threshold) ────────────

@test "yarn-berry-age-duration: exits 1 when npmMinimalAgeGate uses duration string below threshold" {
    run_script "yarn-berry-age-duration"
    [ "$status" -eq 1 ]
}

@test "yarn-berry-age-duration: emits ::error with raw value and converted minutes" {
    run_script "yarn-berry-age-duration"
    [[ "$output" == *"npmMinimalAgeGate=1d (1440 min) is below required 4320"* ]]
}

# ── yarn-berry-414-duration-ok (7d = 10080 min, above 3d = 4320 min threshold) ──

@test "yarn-berry-414-duration-ok: exits 0 when npmMinimalAgeGate is set as 7d" {
    run_script "yarn-berry-414-duration-ok"
    [ "$status" -eq 0 ]
    [[ "$output" != *"::error"* ]]
}

@test "yarn-berry-414-duration-ok: reports 0 errors in summary" {
    run_script "yarn-berry-414-duration-ok"
    [[ "$output" == *"Errors:           0"* ]]
}

# ── yarn-berry-old ────────────────────────────────────────────────────────────

@test "yarn-berry-old: exits 1" {
    run_script "yarn-berry-old"
    [ "$status" -eq 1 ]
}

@test "yarn-berry-old: emits ::error mentioning old yarn version" {
    run_script "yarn-berry-old"
    [[ "$output" == *"yarn 3.6.4 is too old"* ]]
}

@test "yarn-berry-old: reports 1 error in summary" {
    run_script "yarn-berry-old"
    [[ "$output" == *"Errors:           1"* ]]
}

# ── yarn-classic-scripts-on ───────────────────────────────────────────────────

@test "yarn-classic-scripts-on: exits 1" {
    run_script "yarn-classic-scripts-on"
    [ "$status" -eq 1 ]
}

@test "yarn-classic-scripts-on: emits ::error for yarn 1.x release-age limitation" {
    run_script "yarn-classic-scripts-on"
    [[ "$output" == *"yarn 1.x cannot enforce minimumReleaseAge"* ]]
}

@test "yarn-classic-scripts-on: emits ::error for ignore-scripts false" {
    run_script "yarn-classic-scripts-on"
    [[ "$output" == *"ignore-scripts must be true"* ]]
}

@test "yarn-classic-scripts-on: reports 2 errors in summary" {
    run_script "yarn-classic-scripts-on"
    [[ "$output" == *"Errors:           2"* ]]
}

# ── yarn-classic-ok ───────────────────────────────────────────────────────────

@test "yarn-classic-ok: with release-age disabled, exits 0" {
    FAIL_ON_FOUND=true run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/yarn-classic-ok" \
        INPUT_FAIL_ON_FOUND=true \
        INPUT_MINIMUM_RELEASE_AGE_MINUTES=0 \
        bash "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *"::error"* ]]
}

@test "yarn-classic-ok: still emits release-age error with default settings" {
    run_script "yarn-classic-ok"
    [ "$status" -eq 1 ]
    [[ "$output" == *"yarn 1.x cannot enforce minimumReleaseAge"* ]]
}
