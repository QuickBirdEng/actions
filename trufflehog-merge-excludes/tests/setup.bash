TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
FIXTURES="${TESTS_DIR}/fixtures"
SCRIPT="${TESTS_DIR}/../scripts/merge_excludes.sh"

run_merge() {
    local tmp_output
    tmp_output="$(mktemp)"
    run env \
        RUNNER_TEMP="${BATS_TMPDIR}" \
        GITHUB_OUTPUT="${tmp_output}" \
        INPUT_BASE_EXCLUDE_PATHS="${INPUT_BASE_EXCLUDE_PATHS:-}" \
        INPUT_CONSUMER_FILE="${INPUT_CONSUMER_FILE:-}" \
        bash "$SCRIPT"
    # surface the GITHUB_OUTPUT content in $output alongside stdout
    if [ -s "$tmp_output" ]; then
        output="${output}"$'\n'"$(cat "$tmp_output")"
    fi
    rm -f "$tmp_output"
}

# Return the value of a key written to GITHUB_OUTPUT by the script.
# Usage: github_output_value "file"
github_output_value() {
    local key="$1"
    echo "$output" | grep "^${key}=" | tail -1 | cut -d= -f2-
}
