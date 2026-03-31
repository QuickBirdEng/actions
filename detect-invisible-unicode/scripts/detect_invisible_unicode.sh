#!/usr/bin/env bash
set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

trim() { echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

is_true() {
    local val; val="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    [[ "$val" == "true" || "$val" == "1" || "$val" == "yes" || "$val" == "y" ]]
}

# ── configuration ─────────────────────────────────────────────────────────────

SEARCH_DIR="${INPUT_SEARCH_DIRECTORY:-.}"
EXCLUDE_DIRS_CSV="${INPUT_EXCLUDE_DIRS:-.git,node_modules,.idea,build,dist}"
EXCLUDE_PATTERNS_CSV="${INPUT_EXCLUDE_PATTERNS:-*.png,*.jpg,*.jpeg,*.gif,*.ico,*.pdf,*.zip,*.tar,*.gz,*.bin,*.dill}"
FAIL_ON_FOUND="${INPUT_FAIL_ON_FOUND:-true}"

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "ERROR: search-directory does not exist: $SEARCH_DIR" >&2
    exit 1
fi

# ── Unicode threat categories ─────────────────────────────────────────────────
# Format: "CATEGORY_NAME:PCRE_PATTERN"
# Patterns are UTF-8 byte sequences of the suspicious Unicode code points.

CHECKS=(
    # GlassWorm: Variation Selectors (U+FE00-U+FE0F)
    "VARIATION_SELECTOR:\xef\xb8[\x80-\x8f]"
    # GlassWorm: Variation Selectors Supplement (U+E0100-U+E01EF)
    "VARIATION_SELECTOR_SUPPLEMENT:\xf3\xa0[\x84-\x87][\x80-\xbf]"
    # Zero-width formatting characters (U+200B-U+200D, U+2060, U+180E)
    "ZERO_WIDTH:\xe2\x80[\x8b-\x8d]|\xe2\x81\xa0|\xe1\xa0\x8e"
    # Trojan Source: bidirectional control characters (U+200E-U+200F, U+202A-U+202E, U+2066-U+2069, U+061C)
    "BIDI_CONTROL:\xe2\x80[\x8e-\x8f]|\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]|\xd8\x9c"
    # BOM character (U+FEFF)
    "BOM:\xef\xbb\xbf"
    # Tags block (U+E0000-U+E007F)
    "TAGS_BLOCK:\xf3\xa0[\x80-\x81][\x80-\xbf]"
    # BMP Private Use Area (U+E000-U+F8FF)
    "PUA_BMP:\xee[\x80-\xbf][\x80-\xbf]|\xef[\x80-\xa3][\x80-\xbf]"
    # Supplementary Private Use Areas A+B (U+F0000-U+10FFFF)
    "PUA_SUPPLEMENTARY:\xf3[\xb0-\xbf][\x80-\xbf][\x80-\xbf]|\xf4[\x80-\x8f][\x80-\xbf][\x80-\xbf]"
)

# ── build grep exclude flags ───────────────────────────────────────────────────

GREP_EXCLUDES=()
IFS=',' read -ra _dirs <<< "$EXCLUDE_DIRS_CSV"
for _dir in "${_dirs[@]}"; do
    _dir="$(trim "$_dir")"
    [[ -n "$_dir" ]] && GREP_EXCLUDES+=("--exclude-dir=$_dir")
done
IFS=',' read -ra _pats <<< "$EXCLUDE_PATTERNS_CSV"
for _pat in "${_pats[@]}"; do
    _pat="$(trim "$_pat")"
    [[ -n "$_pat" ]] && GREP_EXCLUDES+=("--exclude=$_pat")
done

# ── scan ───────────────────────────────────────────────────────────────────────

echo "Scanning: $(realpath "$SEARCH_DIR")"
echo "Excluding dirs: $EXCLUDE_DIRS_CSV"
echo "Excluding patterns: $EXCLUDE_PATTERNS_CSV"
echo ""

declare -A FILE_CATEGORIES  # filepath -> "CAT1,CAT2,..."
AFFECTED_FILE_COUNT=0

for check in "${CHECKS[@]}"; do
    category="${check%%:*}"
    pattern="${check#*:}"

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        first_line="$(LC_ALL=C grep -Pn --binary-files=without-match "$pattern" "$file" 2>/dev/null \
            | head -1 | cut -d: -f1)"
        first_line="${first_line:-1}"

        rel_file="${file#"$SEARCH_DIR"/}"
        echo "::error file=${rel_file},line=${first_line}::Invisible Unicode [${category}] detected"

        if [[ -v FILE_CATEGORIES["$file"] ]]; then
            if [[ "${FILE_CATEGORIES[$file]}" != *"$category"* ]]; then
                FILE_CATEGORIES["$file"]+=",${category}"
            fi
        else
            FILE_CATEGORIES["$file"]="$category"
            (( AFFECTED_FILE_COUNT++ )) || true
        fi
    done < <(LC_ALL=C grep -rPl --binary-files=without-match \
        "${GREP_EXCLUDES[@]}" "$pattern" "$SEARCH_DIR" 2>/dev/null || true)
done

# ── report ────────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "Invisible Unicode Scan Summary"
echo "============================================================"

if [[ "$AFFECTED_FILE_COUNT" -eq 0 ]]; then
    echo "No invisible Unicode characters detected."
else
    echo "Found invisible Unicode in ${AFFECTED_FILE_COUNT} file(s):"
    for file in "${!FILE_CATEGORIES[@]}"; do
        echo "  ${file#"$SEARCH_DIR"/}  [${FILE_CATEGORIES[$file]}]"
    done
fi

echo "============================================================"

# ── github output ─────────────────────────────────────────────────────────────

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "findings=${AFFECTED_FILE_COUNT}" >> "$GITHUB_OUTPUT"
else
    echo "::set-output name=findings::${AFFECTED_FILE_COUNT}"
fi

if is_true "$FAIL_ON_FOUND" && [[ "$AFFECTED_FILE_COUNT" -gt 0 ]]; then
    exit 1
fi
