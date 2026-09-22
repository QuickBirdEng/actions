#!/usr/bin/env bash
set -euo pipefail

# Prisma applies pending migrations in filename-sorted order. A migration
# folder timestamped earlier than what is already on base-ref still applies,
# but it sorts before migrations that were written assuming it did not exist.
# This check fails a PR that adds a migration not timestamped after base-ref.

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

max_existing_ts="$(printf '%s\n' "$existing" | grep -oE "$INPUT_TIMESTAMP_REGEX" | sort -n | tail -1 || true)"
echo "max-existing-timestamp=$max_existing_ts" >> "$GITHUB_OUTPUT"

if [ -z "$max_existing_ts" ]; then
  echo "No existing migrations found on $INPUT_BASE_REF - nothing to compare against."
  exit 0
fi

echo "Latest migration timestamp already on $INPUT_BASE_REF: $max_existing_ts"
echo "New migration(s) in $INPUT_END_REF:"
echo "$new_migrations"
echo ""

failed=0
while IFS= read -r migration; do
  [ -z "$migration" ] && continue
  ts="$(printf '%s' "$migration" | grep -oE "$INPUT_TIMESTAMP_REGEX" || true)"
  if [ -z "$ts" ]; then
    echo "::warning::Could not match timestamp-regex against '$migration' - skipping the order check for it."
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
