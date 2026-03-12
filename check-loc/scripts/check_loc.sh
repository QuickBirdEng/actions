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

default_ignore_patterns=(
  ":!*/**/*.spec.*"
  ":!*/**/*.md"
  ":!*/**/*.json"
  ":!*/**/*.sql"
  ":!*/**/*.xls"
  ":!*/**/*.xlsx"
  ":!*/**/*.csv"
  ":!*/**/*.data"
  ":!*/**/*.html"
  ":!*/**/*.pdf"
  ":!*/**/*.png"
  ":!**/package-lock.json"
  ":!**/yarn.lock"
  ":!**/pnpm-lock.yaml"
  ":!**/pubspec.lock"
  ":!**/*.freezed.dart"
  ":!**/*.g.dart"
  ":!**/gen/*"
  ":!test/*"
  ":!.github/**/*"
  ":!*/**/promis-domain-map.ts"
)

candidate_base_branches=()
if [ -n "$(trim "${INPUT_BASE_REF:-}")" ]; then
  candidate_base_branches+=("$(trim "$INPUT_BASE_REF")")
else
  while IFS= read -r raw_branch; do
    base_branch="$(trim "$raw_branch")"
    [ -z "$base_branch" ] && continue
    candidate_base_branches+=("$base_branch")
  done < <(printf '%s\n' "${INPUT_BASE_BRANCHES:-main}" | tr ',' '\n')
fi

if [ "${#candidate_base_branches[@]}" -eq 0 ]; then
  candidate_base_branches=("main")
fi

if is_true "${INPUT_FETCH_BASE_BRANCHES:-true}"; then
  for base_branch in "${candidate_base_branches[@]}"; do
    git fetch origin "${base_branch}:${base_branch}" || true
  done
fi

resolved_base_ref=""
merge_base=""
for base_branch in "${candidate_base_branches[@]}"; do
  candidate_merge_base="$(git merge-base "$base_branch" "$INPUT_END_REF" 2>/dev/null || true)"
  [ -z "$candidate_merge_base" ] && continue

  if [ -z "$merge_base" ] || git merge-base --is-ancestor "$merge_base" "$candidate_merge_base"; then
    resolved_base_ref="$base_branch"
    merge_base="$candidate_merge_base"
  fi
done

if [ -z "$resolved_base_ref" ]; then
  resolved_base_ref="${candidate_base_branches[0]}"
  merge_base="$(git merge-base "$resolved_base_ref" "$INPUT_END_REF")"
fi

ignore_patterns=("${default_ignore_patterns[@]}")
if [ -n "${INPUT_IGNORE_PATTERNS:-}" ]; then
  while IFS= read -r pattern; do
    pattern="${pattern%$'\r'}"
    [ -z "$pattern" ] && continue
    ignore_patterns+=("$pattern")
  done <<< "$INPUT_IGNORE_PATTERNS"
fi

echo "LoC upper limit: $INPUT_LOC_LIMIT"
echo "Candidate base branches: ${candidate_base_branches[*]}"
echo "Resolved base ref: $resolved_base_ref"
echo "End ref: $INPUT_END_REF"
echo "Merge base: $merge_base"

echo "resolved-base-ref=$resolved_base_ref" >> "$GITHUB_OUTPUT"
echo "merge-base=$merge_base" >> "$GITHUB_OUTPUT"

branch_changes="$(git diff --stat "$merge_base..$INPUT_END_REF" -- "${ignore_patterns[@]}" || true)"
staged_changes="$(git diff --stat --staged -- "${ignore_patterns[@]}" || true)"

echo ""
echo "Branch changes:"
if [ -n "$branch_changes" ]; then
  printf '%s\n' "$branch_changes"
else
  echo "<none>"
fi
echo ""
echo "This commit changes:"
if [ -n "$staged_changes" ]; then
  printf '%s\n' "$staged_changes"
else
  echo "<none>"
fi

summary="$(
  {
    git diff --shortstat "$merge_base..$INPUT_END_REF" -- "${ignore_patterns[@]}" || true
    git diff --shortstat --staged -- "${ignore_patterns[@]}" || true
  } | awk -v loc_limit="$INPUT_LOC_LIMIT" -v exit_code_on_limit="$INPUT_EXIT_CODE_ON_LIMIT" '
      BEGIN { files = 0; ins = 0; del = 0 }
      /file[s]* changed/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+$/ && $(i + 1) ~ /^file/) {
            files += $i
          }
          if ($i ~ /^[0-9]+$/ && $(i + 1) ~ /^insertion/) {
            ins += $i
          }
          if ($i ~ /^[0-9]+$/ && $(i + 1) ~ /^deletion/) {
            del += $i
          }
        }
      }
      END {
        total = ins + del
        printf("files=%d\ninsertions=%d\ndeletions=%d\ntotal=%d\nexit_code=%d\n", files, ins, del, total, total > loc_limit ? exit_code_on_limit : 0)
      }'
)"

eval "$summary"

echo ""
echo "---------- LoC Check ----------"
echo "Files changed: $files"
echo "Inserts: $insertions"
echo "Deletes: $deletions"
echo "Total LoC change: $total"
echo "total-loc-change=$total" >> "$GITHUB_OUTPUT"

if [ "$exit_code" -ne 0 ]; then
  echo "LoC too much: $((total - INPUT_LOC_LIMIT))"
  echo "---------- LoC Check ----------"
  echo ""
  exit "$exit_code"
fi

echo "---------- LoC Check ----------"
echo ""
