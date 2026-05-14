#!/usr/bin/env bats

load "setup.bash"

setup() {
    _JS_SC_TESTING=1 \
    INPUT_SEARCH_DIRECTORY="${FIXTURES}/pnpm-ok" \
        source "$SCRIPT"
    set +e +u +o pipefail
}

# ── split_list ────────────────────────────────────────────────────────────────

@test "split_list: strips trailing yaml inline comments" {
    result="$(split_list "@types/node # CVE-2024-1234")"
    [ "$result" = "@types/node" ]
}

@test "split_list: strips comment with colon inside" {
    result="$(split_list "esbuild # native: build tool")"
    [ "$result" = "esbuild" ]
}

@test "split_list: deduplicates entries" {
    result="$(split_list "a,b,a")"
    [ "$(echo "$result" | wc -l | tr -d ' ')" = "2" ]
}

@test "split_list: handles comma-separated input" {
    result="$(split_list "a,b,c")"
    [ "$(echo "$result" | wc -l | tr -d ' ')" = "3" ]
}

@test "split_list: handles newline-separated input" {
    result="$(split_list $'a\nb\nc')"
    [ "$(echo "$result" | wc -l | tr -d ' ')" = "3" ]
}

@test "split_list: strips leading and trailing whitespace from entries" {
    result="$(split_list "  lodash  ,  express  ")"
    [ "$(echo "$result" | grep -c 'lodash')" = "1" ]
    [ "$(echo "$result" | grep -c 'express')" = "1" ]
}

@test "split_list: empty input produces empty output" {
    result="$(split_list "")"
    [ -z "$result" ]
}

# ── is_true ───────────────────────────────────────────────────────────────────

@test "is_true: accepts 'true'" {
    is_true "true"
    [ $? -eq 0 ]
}

@test "is_true: accepts 'True' (case-insensitive)" {
    is_true "True"
    [ $? -eq 0 ]
}

@test "is_true: accepts '1'" {
    is_true "1"
    [ $? -eq 0 ]
}

@test "is_true: accepts 'yes'" {
    is_true "yes"
    [ $? -eq 0 ]
}

@test "is_true: accepts 'YES'" {
    is_true "YES"
    [ $? -eq 0 ]
}

@test "is_true: rejects 'false'" {
    is_true "false"
    [ $? -ne 0 ]
}

@test "is_true: rejects '0'" {
    is_true "0"
    [ $? -ne 0 ]
}

@test "is_true: rejects 'no'" {
    is_true "no"
    [ $? -ne 0 ]
}

@test "is_true: rejects empty string" {
    is_true ""
    [ $? -ne 0 ]
}

# ── version_cmp ───────────────────────────────────────────────────────────────

@test "version_cmp: equal versions echo 0" {
    result="$(version_cmp 4.14.0 4.14.0)"
    [ "$result" = "0" ]
}

@test "version_cmp: older < newer echoes -1" {
    result="$(version_cmp 4.13.0 4.14.0)"
    [ "$result" = "-1" ]
}

@test "version_cmp: newer > older echoes 1" {
    result="$(version_cmp 4.14.0 4.13.0)"
    [ "$result" = "1" ]
}

@test "version_cmp: major version comparison (10.0.0 vs 9.15.3)" {
    result="$(version_cmp 10.0.0 9.15.3)"
    [ "$result" = "1" ]
}

@test "version_cmp: major version comparison (9.15.3 vs 10.0.0)" {
    result="$(version_cmp 9.15.3 10.0.0)"
    [ "$result" = "-1" ]
}

@test "version_cmp: strips leading v prefix" {
    result="$(version_cmp v4.14.0 v4.14.0)"
    [ "$result" = "0" ]
}

@test "version_cmp: strips pre-release suffix" {
    result="$(version_cmp 4.14.0-rc.1 4.14.0)"
    [ "$result" = "0" ]
}

# ── parse_duration_minutes ────────────────────────────────────────────────────

@test "parse_duration_minutes: plain integer treated as minutes" {
    result="$(parse_duration_minutes "10080")"
    [ "$result" = "10080" ]
}

@test "parse_duration_minutes: Nd converts days to minutes" {
    result="$(parse_duration_minutes "7d")"
    [ "$result" = "10080" ]
}

@test "parse_duration_minutes: 1d = 1440 minutes" {
    result="$(parse_duration_minutes "1d")"
    [ "$result" = "1440" ]
}

@test "parse_duration_minutes: Nh converts hours to minutes" {
    result="$(parse_duration_minutes "24h")"
    [ "$result" = "1440" ]
}

@test "parse_duration_minutes: Nm suffix treated as minutes" {
    result="$(parse_duration_minutes "60m")"
    [ "$result" = "60" ]
}

@test "parse_duration_minutes: unrecognised format returns empty string" {
    result="$(parse_duration_minutes "1w")"
    [ -z "$result" ]
}

@test "parse_duration_minutes: empty input returns empty string" {
    result="$(parse_duration_minutes "")"
    [ -z "$result" ]
}

# ── normalize_csv ─────────────────────────────────────────────────────────────

@test "normalize_csv: collapses multiple commas" {
    result="$(normalize_csv "a,,b")"
    [ "$result" = "a,b" ]
}

@test "normalize_csv: strips leading comma" {
    result="$(normalize_csv ",a,b")"
    [ "$result" = "a,b" ]
}

@test "normalize_csv: strips trailing comma" {
    result="$(normalize_csv "a,b,")"
    [ "$result" = "a,b" ]
}

@test "normalize_csv: converts newlines to commas" {
    result="$(normalize_csv $'a\nb')"
    [ "$result" = "a,b" ]
}
