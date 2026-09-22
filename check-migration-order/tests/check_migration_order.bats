#!/usr/bin/env bats

load "setup.bash"

setup() {
    init_repo
    add_migrations "prisma/migrations" "20260826000000_a" "20260827000000_b"
    git branch base HEAD
}

# ── No new migrations ─────────────────────────────────────────────────────────

@test "no new migrations: exits 0 and no-ops" {
    run_check
    [ "$status" -eq 0 ]
    [[ "$output" == *"No new migrations"* ]]
}

# ── Backdated migration ───────────────────────────────────────────────────────

@test "backdated new migration: fails and names the offending folder" {
    git checkout -qb feature
    add_migrations "prisma/migrations" "20260810000000_backdated"

    INPUT_END_REF="feature" run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::"* ]]
    [[ "$output" == *"20260810000000_backdated"* ]]
    [[ "$output" == *"20260827000000"* ]]
}

@test "multiple new migrations, only one backdated: reports only the offender" {
    git checkout -qb feature
    add_migrations "prisma/migrations" "20260810000000_backdated" "20260901000000_good"

    INPUT_END_REF="feature" run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"20260810000000_backdated"* ]]

    error_lines="$(echo "$output" | grep '::error::' || true)"
    [ "$(echo "$error_lines" | grep -c '::error::')" -eq 1 ]
}

# ── Properly ordered migration ────────────────────────────────────────────────

@test "properly ordered new migration: passes" {
    git checkout -qb feature
    add_migrations "prisma/migrations" "20260901000000_good"

    INPUT_END_REF="feature" run_check
    [ "$status" -eq 0 ]
    [[ "$output" == *"correctly ordered"* ]]
}

# ── No existing migrations on base ────────────────────────────────────────────

@test "no existing migrations on base: fails instead of silently passing" {
    init_repo
    echo hi > README.md
    git add -A && git commit -qm "no migrations yet"
    git branch empty-base HEAD
    add_migrations "prisma/migrations" "20260901000000_first"

    INPUT_BASE_REF="empty-base" run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::"* ]]
}

@test "migrations-dir matches nothing on either ref: fails" {
    init_repo
    echo hi > README.md
    git add -A && git commit -qm "no migrations at all"
    git branch base2 HEAD

    INPUT_MIGRATIONS_DIR="wrong/path" INPUT_BASE_REF="base2" INPUT_END_REF="base2" run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::"* ]]
    [[ "$output" == *"wrong/path"* ]]
}

# ── Unparseable folder name ───────────────────────────────────────────────────

@test "new folder without a matching timestamp: warns and does not fail" {
    git checkout -qb feature
    add_migrations "prisma/migrations" "not_a_timestamped_folder"

    INPUT_END_REF="feature" run_check
    [ "$status" -eq 0 ]
    [[ "$output" == *"::warning::"* ]]
}

# ── Custom migrations-dir ─────────────────────────────────────────────────────

@test "custom migrations-dir input is honored" {
    init_repo
    add_migrations "web/prisma/migrations" "20260826000000_a"
    git branch custom-base HEAD
    git checkout -qb feature
    add_migrations "web/prisma/migrations" "20260810000000_backdated"

    INPUT_MIGRATIONS_DIR="web/prisma/migrations" INPUT_BASE_REF="custom-base" INPUT_END_REF="feature" run_check
    [ "$status" -eq 1 ]
    [[ "$output" == *"20260810000000_backdated"* ]]
}
