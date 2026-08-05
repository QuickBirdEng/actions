#!/usr/bin/env bash
set -euo pipefail

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

is_true() {
  case "${1:-}" in
    [Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]|[Yy]) return 0 ;;
    *) return 1 ;;
  esac
}

branch_name="${INPUT_BRANCH_NAME:-${GITHUB_REF_NAME:-}}"
if [ -z "$branch_name" ]; then
  echo "No branch name was provided and GITHUB_REF_NAME is empty."
  exit 1
fi

if is_true "$INPUT_SKIP_DEPENDABOT" && { [[ "$branch_name" == dependabot* ]] || [[ "${GITHUB_ACTOR:-}" == "dependabot[bot]" ]]; }; then
  echo "Skipping for Dependabot."
  echo "ticket-identifier=" >> "$GITHUB_OUTPUT"
  echo "match-count=0" >> "$GITHUB_OUTPUT"
  exit 0
fi

echo "BRANCH_NAME: $branch_name"

matcher="$INPUT_TICKET_REGEX"
if [ -n "$(trim "$INPUT_TICKET_PREFIXES")" ]; then
  prefix_patterns=()
  while IFS= read -r raw_prefix; do
    prefix="$(trim "$raw_prefix")"
    [ -z "$prefix" ] && continue
    prefix_patterns+=("$(printf '%s' "$prefix" | sed 's/[][(){}.^$?*+|\\/]/\\&/g')")
  done < <(printf '%s\n' "$INPUT_TICKET_PREFIXES" | tr ',' '\n')

  if [ "${#prefix_patterns[@]}" -gt 0 ]; then
    matcher="($(IFS='|'; echo "${prefix_patterns[*]}")-[0-9X]+)"
  fi
fi

if [[ "$branch_name" =~ $matcher ]]; then
  ticket_identifier="${BASH_REMATCH[1]:-}"
else
  echo "Couldn't extract ticket identifier from branch name: $branch_name"
  echo "ticket-identifier=" >> "$GITHUB_OUTPUT"
  echo "match-count=0" >> "$GITHUB_OUTPUT"
  if is_true "$INPUT_FAIL_ON_MISSING_TICKET"; then
    exit 1
  fi
  exit 0
fi

if [ -z "$ticket_identifier" ]; then
  echo "The configured matcher must expose the ticket identifier as the first capture group."
  exit 1
fi

echo "Extracted ticket identifier: $ticket_identifier"
echo "ticket-identifier=$ticket_identifier" >> "$GITHUB_OUTPUT"

if [ ! -e "$INPUT_SEARCH_DIRECTORY" ]; then
  echo "Search directory does not exist: $INPUT_SEARCH_DIRECTORY"
  exit 1
fi

grep_args=(-RInw --binary-files=without-match)

while IFS= read -r raw_dir; do
  excluded_dir="$(trim "$raw_dir")"
  [ -z "$excluded_dir" ] && continue
  grep_args+=("--exclude-dir=$excluded_dir")
done < <(printf '%s\n' "$INPUT_SEARCH_EXCLUDE_DIRS" | tr ',' '\n')

while IFS= read -r raw_glob; do
  excluded_glob="$(trim "$raw_glob")"
  [ -z "$excluded_glob" ] && continue
  grep_args+=("--exclude=$excluded_glob")
done < <(printf '%s\n' "$INPUT_SEARCH_EXCLUDE_GLOBS" | tr ',' '\n')

matches="$(grep "${grep_args[@]}" -e "$ticket_identifier" "$INPUT_SEARCH_DIRECTORY" || true)"
if [ -z "$matches" ]; then
  printf 'No matches found for identifier %s in %s.\n' "$ticket_identifier" "$INPUT_SEARCH_DIRECTORY"
  echo "match-count=0" >> "$GITHUB_OUTPUT"
  exit 0
fi

match_count="$(printf '%s\n' "$matches" | awk 'NF { count++ } END { print count + 0 }')"
echo "match-count=$match_count" >> "$GITHUB_OUTPUT"

echo ""
printf 'Found identifier %s in code matching branch %s.\n\n' "$ticket_identifier" "$branch_name"
echo "Please resolve these TODOs in your PR"
echo ""
echo "Matches:"
echo "=========="
printf '%s\n' "$matches"
echo "=========="
echo ""
echo "If this is a mismatch and the found file should not be counted, adjust the search exclusions."
echo ""
exit 1
