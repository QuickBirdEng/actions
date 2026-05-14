#!/usr/bin/env bats

load "setup.bash"

# ── pnpm-ok ───────────────────────────────────────────────────────────────────

@test "pnpm-ok: exits 0, no error or warning annotations" {
    run_script "pnpm-ok"
    [ "$status" -eq 0 ]
    [[ "$output" != *"::error"* ]]
    [[ "$output" != *"::warning"* ]]
}

@test "pnpm-ok: reports 0 errors and 0 warnings in summary" {
    run_script "pnpm-ok"
    [[ "$output" == *"Errors:           0"* ]]
    [[ "$output" == *"Warnings:         0"* ]]
}

@test "pnpm-ok: scans exactly 1 project" {
    run_script "pnpm-ok"
    [[ "$output" == *"Projects scanned: 1"* ]]
}

# ── pnpm-missing-age ──────────────────────────────────────────────────────────

@test "pnpm-missing-age: exits 1" {
    run_script "pnpm-missing-age"
    [ "$status" -eq 1 ]
}

@test "pnpm-missing-age: emits ::error for missing minimumReleaseAge" {
    run_script "pnpm-missing-age"
    [[ "$output" == *"minimumReleaseAge"* ]]
    [[ "$output" == *"::error"* ]]
}

@test "pnpm-missing-age: emits ::warning for missing blockExoticSubdeps" {
    run_script "pnpm-missing-age"
    [[ "$output" == *"blockExoticSubdeps"* ]]
    [[ "$output" == *"::warning"* ]]
}

@test "pnpm-missing-age: reports 2 errors in summary" {
    run_script "pnpm-missing-age"
    [[ "$output" == *"Errors:           2"* ]]
}

@test "pnpm-missing-age: with FAIL_ON_FOUND=false exits 0 despite findings" {
    FAIL_ON_FOUND=false run_script "pnpm-missing-age"
    [ "$status" -eq 0 ]
    [[ "$output" == *"::error"* ]]
}

# ── pnpm-old-version ──────────────────────────────────────────────────────────

@test "pnpm-old-version: exits 1" {
    run_script "pnpm-old-version"
    [ "$status" -eq 1 ]
}

@test "pnpm-old-version: emits ::error mentioning old pnpm version" {
    run_script "pnpm-old-version"
    [[ "$output" == *"pnpm 8.15.0 is too old"* ]]
}

@test "pnpm-old-version: reports 1 error in summary" {
    run_script "pnpm-old-version"
    [[ "$output" == *"Errors:           1"* ]]
}

# ── pnpm-exotic-lockfile ──────────────────────────────────────────────────────

@test "pnpm-exotic-lockfile: exits 1" {
    run_script "pnpm-exotic-lockfile"
    [ "$status" -eq 1 ]
}

@test "pnpm-exotic-lockfile: emits ::error for exotic resolution in lockfile" {
    run_script "pnpm-exotic-lockfile"
    [[ "$output" == *"Exotic resolution in pnpm-lock.yaml"* ]]
}

@test "pnpm-exotic-lockfile: reports 1 error in summary" {
    run_script "pnpm-exotic-lockfile"
    [[ "$output" == *"Errors:           1"* ]]
}
