SCRIPT="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)/../scripts/check_migration_order.sh"

# Build a scratch git repo and cd into it. Each call gets its own directory,
# so a test needing a second, unrelated repo can call this again.
init_repo() {
    REPO="${BATS_TEST_TMPDIR}/repo-$RANDOM"
    mkdir -p "$REPO"
    cd "$REPO" || return 1
    git init -q
    git config user.email test@test.com
    git config user.name test
}

# add_migrations <dir> <folder-name>...
# Create empty migration folders under <dir> and commit them. Also drops a
# migration_lock.toml next to them, since every real Prisma migrations dir has one.
add_migrations() {
    local dir="$1"
    shift
    mkdir -p "$dir"
    touch "$dir/migration_lock.toml"
    for name in "$@"; do
        mkdir -p "$dir/$name"
        touch "$dir/$name/migration.sql"
    done
    git add -A
    git commit -qm "migrations: $*"
}

run_check() {
    local tmp_output
    tmp_output="$(mktemp)"
    run env \
        GITHUB_OUTPUT="$tmp_output" \
        INPUT_MIGRATIONS_DIR="${INPUT_MIGRATIONS_DIR:-prisma/migrations}" \
        INPUT_BASE_REF="${INPUT_BASE_REF:-base}" \
        INPUT_END_REF="${INPUT_END_REF:-HEAD}" \
        bash "$SCRIPT"
    # surface the GITHUB_OUTPUT content in $output alongside stdout
    if [ -s "$tmp_output" ]; then
        output="${output}"$'\n'"$(cat "$tmp_output")"
    fi
    rm -f "$tmp_output"
}
