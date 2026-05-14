#!/usr/bin/env bats

load "setup.bash"

# ── empty dir ─────────────────────────────────────────────────────────────────

@test "empty dir: exits 0 when no lockfiles found" {
    run_script "empty"
    [ "$status" -eq 0 ]
}

@test "empty dir: prints 'No JS lockfiles found'" {
    run_script "empty"
    [[ "$output" == *"No JS lockfiles found"* ]]
}

@test "empty dir: no annotations emitted" {
    run_script "empty"
    [[ "$output" != *"::error"* ]]
    [[ "$output" != *"::warning"* ]]
}

# ── non-existent search directory ────────────────────────────────────────────

@test "non-existent search dir: exits non-zero with error message" {
    run env \
        INPUT_SEARCH_DIRECTORY="/tmp/this-path-does-not-exist-$(date +%s)" \
        INPUT_FAIL_ON_FOUND=true \
        bash "$SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"does not exist"* ]]
}

# ── monorepo ──────────────────────────────────────────────────────────────────

@test "monorepo: scans exactly 2 projects (one passing, one failing)" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/monorepo" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"Projects scanned: 2"* ]]
}

@test "monorepo: per-project breakdown includes failing project" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/monorepo" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"packages/api"* ]]
}

@test "monorepo: total errors come only from failing project" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/monorepo" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"Errors:           2"* ]]
}

@test "monorepo: api project (missing settings) contributes errors" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/monorepo" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"packages/api"* ]]
    [[ "$output" == *"::error"* ]]
}

# ── exclude patterns ──────────────────────────────────────────────────────────

@test "exclude: lockfile in excluded path produces no annotations" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/monorepo" \
        INPUT_EXCLUDE="packages/api/**" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"Projects scanned: 1"* ]]
    [[ "$output" != *"::error"*"packages/api"* ]]
    [[ "$output" == *"Errors:           0"* ]]
}

@test "exclude: excluding all lockfiles results in Projects scanned: 0" {
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/pnpm-ok" \
        INPUT_EXCLUDE="**" \
        INPUT_FAIL_ON_FOUND=false \
        bash "$SCRIPT"
    [[ "$output" == *"Projects scanned: 0"* ]]
}
