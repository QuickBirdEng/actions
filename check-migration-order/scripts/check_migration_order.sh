#!/usr/bin/env bash
set -euo pipefail

# Prisma applies pending migrations in filename-sorted order. A migration
# folder timestamped earlier than what is already on base-ref still applies,
# but it sorts before migrations that were written assuming it did not exist.
# This check fails a PR that adds a migration not timestamped after base-ref.

# Prisma's own migration generator always names a folder with this prefix.
timestamp_regex='^[0-9]{14}'

is_true() {
  case "${1:-}" in
    [Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]|[Yy]) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -z "${INPUT_BASE_REF:-}" ]; then
  echo "::error::base-ref is empty. Pass an explicit base-ref, or trigger the caller on pull_request so github.event.pull_request.base.ref is set."
  exit 1
fi

if is_true "${INPUT_FETCH_BASE_REF:-true}"; then
  git fetch origin "${INPUT_BASE_REF}:${INPUT_BASE_REF}" || true
fi

if ! git rev-parse --verify --quiet "${INPUT_BASE_REF}^{commit}" >/dev/null; then
  echo "::error::base-ref '$INPUT_BASE_REF' does not resolve to a commit. Check the branch name, and that fetch-base-ref can reach it."
  exit 1
fi

if ! git rev-parse --verify --quiet "${INPUT_END_REF}^{commit}" >/dev/null; then
  echo "::error::end-ref '$INPUT_END_REF' does not resolve to a commit."
  exit 1
fi

# List migration folder names at a ref. Return nothing when the path is absent,
# instead of running basename with no input.
list_migrations() {
  local ref="$1"
  local names
  names="$(git ls-tree --name-only "$ref" -- "${INPUT_MIGRATIONS_DIR}/" 2>/dev/null || true)"
  [ -z "$names" ] && return 0
  printf '%s\n' "$names" | xargs -n1 basename | sort
}

existing="$(list_migrations "$INPUT_BASE_REF")"
current="$(list_migrations "$INPUT_END_REF")"

if [ -z "$existing" ] && [ -z "$current" ]; then
  echo "::error::No migrations found under '$INPUT_MIGRATIONS_DIR' on either $INPUT_BASE_REF or $INPUT_END_REF. Check migrations-dir is set to the right path."
  exit 1
fi

max_existing_ts="$(printf '%s\n' "$existing" | grep -oE "$timestamp_regex" | sort -n | tail -1 || true)"
echo "max-existing-timestamp=$max_existing_ts" >> "$GITHUB_OUTPUT"

new_migrations="$(comm -13 <(printf '%s\n' "$existing") <(printf '%s\n' "$current"))"

{
  echo "new-migrations<<MIGRATION_ORDER_EOF"
  echo "$new_migrations"
  echo "MIGRATION_ORDER_EOF"
} >> "$GITHUB_OUTPUT"

if [ -z "$new_migrations" ]; then
  echo "No new migrations in $INPUT_END_REF relative to $INPUT_BASE_REF."
  exit 0
fi

if [ -z "$max_existing_ts" ]; then
  echo "::error::No migration under '$INPUT_MIGRATIONS_DIR' on $INPUT_BASE_REF has a name starting with a 14-digit timestamp. Check migrations-dir is set to the right path, and that existing migrations follow Prisma's naming convention."
  exit 1
fi

echo "Latest migration timestamp already on $INPUT_BASE_REF: $max_existing_ts"
echo "New migration(s) in $INPUT_END_REF:"
echo "$new_migrations"
echo ""

failed=0
while IFS= read -r migration; do
  [ -z "$migration" ] && continue
  ts="$(printf '%s' "$migration" | grep -oE "$timestamp_regex" || true)"
  if [ -z "$ts" ]; then
    echo "::warning::'$migration' does not start with a 14-digit timestamp - skipping the order check for it."
    continue
  fi
  if [ "$ts" -le "$max_existing_ts" ]; then
    echo "::error::Migration '$migration' is timestamped $ts, which is not after the latest migration already on $INPUT_BASE_REF ($max_existing_ts). Rename the folder with a current UTC timestamp so it applies after everything already merged, or rebase if the base has moved."
    failed=1
  fi
done <<< "$new_migrations"

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "All new migrations are correctly ordered after $INPUT_BASE_REF."
