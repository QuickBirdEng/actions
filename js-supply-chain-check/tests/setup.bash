TESTS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
FIXTURES="${TESTS_DIR}/fixtures"
SCRIPT="${TESTS_DIR}/../scripts/js_supply_chain_check.sh"

run_script() {
    local fixture="$1"; shift
    run env \
        INPUT_SEARCH_DIRECTORY="${FIXTURES}/${fixture}" \
        INPUT_FAIL_ON_FOUND="${FAIL_ON_FOUND:-true}" \
        "${@}" \
        bash "$SCRIPT"
}
