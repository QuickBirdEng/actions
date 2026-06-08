#!/usr/bin/env bats

load "setup.bash"

# ── No inputs ─────────────────────────────────────────────────────────────────

@test "no consumer file and no base file: outputs empty file key" {
    INPUT_CONSUMER_FILE="${FIXTURES}/nonexistent.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -z "$result" ]
}

# ── Consumer file only ────────────────────────────────────────────────────────

@test "consumer file with paths: outputs merged file containing those paths" {
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-paths-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -n "$result" ]
    grep -q "test/fixtures/\*\*" "$result"
    grep -q "docs/fake-creds.txt" "$result"
}

@test "consumer file with paths only: output contains exactly those paths" {
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-paths-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ "$(grep -c '.' "$result")" -eq 2 ]
}

@test "consumer file with acknowledged_findings only: outputs empty file key and emits notice" {
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-ack-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -z "$result" ]
    echo "$output" | grep -q "::notice::"
}

@test "consumer file with both paths and acknowledged_findings: outputs paths, emits notice for ack findings" {
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-both.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -n "$result" ]
    grep -q "test/fixtures/\*\*" "$result"
    echo "$output" | grep -q "::notice::"
}

@test "consumer file with empty paths list: outputs empty file key" {
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-empty-paths.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -z "$result" ]
}

# ── Base file only ────────────────────────────────────────────────────────────

@test "base file only, no consumer file: passes through base file path unchanged" {
    INPUT_BASE_EXCLUDE_PATHS="${FIXTURES}/base-excludes.txt" \
    INPUT_CONSUMER_FILE="${FIXTURES}/nonexistent.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ "$result" = "${FIXTURES}/base-excludes.txt" ]
}

# ── Both files ────────────────────────────────────────────────────────────────

@test "base file and consumer paths: merged file contains patterns from both" {
    INPUT_BASE_EXCLUDE_PATHS="${FIXTURES}/base-excludes.txt" \
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-paths-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ -n "$result" ]
    grep -q "legacy/exclude/\*\*" "$result"
    grep -q "test/fixtures/\*\*" "$result"
    grep -q "docs/fake-creds.txt" "$result"
}

@test "base file and consumer paths: merged file has more lines than either source alone" {
    INPUT_BASE_EXCLUDE_PATHS="${FIXTURES}/base-excludes.txt" \
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-paths-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    base_count="$(grep -c '.' "${FIXTURES}/base-excludes.txt")"
    merged_count="$(grep -c '.' "$result")"
    [ "$merged_count" -gt "$base_count" ]
}

@test "base file and consumer file with no paths: passes through base file path" {
    INPUT_BASE_EXCLUDE_PATHS="${FIXTURES}/base-excludes.txt" \
    INPUT_CONSUMER_FILE="${FIXTURES}/consumer-ack-only.yaml" \
    run_merge
    [ "$status" -eq 0 ]
    result="$(github_output_value file)"
    [ "$result" = "${FIXTURES}/base-excludes.txt" ]
}
