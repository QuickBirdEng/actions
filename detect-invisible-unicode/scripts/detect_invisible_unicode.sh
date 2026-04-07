#!/usr/bin/env bash
set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

trim() { echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

# Normalize comma- or newline-separated input into a clean comma-separated string.
normalize_csv() { echo "$1" | tr '\n' ',' | sed 's/,\+/,/g;s/^,//;s/,$//'; }

is_true() {
    local val; val="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    [[ "$val" == "true" || "$val" == "1" || "$val" == "yes" || "$val" == "y" ]]
}

# ── configuration ─────────────────────────────────────────────────────────────

SEARCH_DIR="${INPUT_SEARCH_DIRECTORY:-.}"
EXCLUDE_DIRS_CSV="$(normalize_csv "${INPUT_EXCLUDE_DIRS:-.git,node_modules,.idea,build,dist}")"
EXCLUDE_PATTERNS_CSV="$(normalize_csv "${INPUT_EXCLUDE_PATTERNS:-*.png,*.jpg,*.jpeg,*.gif,*.ico,*.pdf,*.zip,*.tar,*.gz,*.bin,*.dill}")"
EXCLUDE_FILES_CSV="$(normalize_csv "${INPUT_EXCLUDE_FILES:-}")"
FAIL_ON_FOUND="${INPUT_FAIL_ON_FOUND:-true}"

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "ERROR: search-directory does not exist: $SEARCH_DIR" >&2
    exit 1
fi

# ── Unicode threat categories ─────────────────────────────────────────────────
# Format: "CATEGORY_NAME:PCRE_PATTERN"
# Patterns are UTF-8 byte sequences of the suspicious Unicode code points.

declare -A CATEGORY_LINKS=(
    [VARIATION_SELECTOR]="https://unicode.org/faq/vs.html"
    [VARIATION_SELECTOR_SUPPLEMENT]="https://unicode.org/faq/vs.html"
    [ZERO_WIDTH]="https://en.wikipedia.org/wiki/Zero-width_space"
    [BIDI_CONTROL]="https://trojansource.codes/"
    [BOM]="https://unicode.org/faq/utf_bom.html#bom1"
    [TAGS_BLOCK]="https://en.wikipedia.org/wiki/Tags_(Unicode_block)"
    [PUA_BMP]="https://unicode.org/faq/private_use.html"
    [PUA_SUPPLEMENTARY]="https://unicode.org/faq/private_use.html"
)

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

# ── build grep exclude flags and path-based exclusion lists ───────────────────
# grep's --exclude-dir only matches directory names, not paths.
# Entries containing '/' are treated as path prefixes and filtered post-scan.

GREP_EXCLUDES=()
EXCLUDE_DIR_PATHS=()  # path-prefix based exclusions (contain '/')
IFS=',' read -ra _dirs <<< "$EXCLUDE_DIRS_CSV"
for _dir in "${_dirs[@]}"; do
    _dir="$(trim "$_dir")"
    [[ -z "$_dir" ]] && continue
    if [[ "$_dir" == */* ]]; then
        EXCLUDE_DIR_PATHS+=("${_dir%/}")  # strip trailing slash
    else
        GREP_EXCLUDES+=("--exclude-dir=$_dir")
    fi
done
IFS=',' read -ra _pats <<< "$EXCLUDE_PATTERNS_CSV"
for _pat in "${_pats[@]}"; do
    _pat="$(trim "$_pat")"
    [[ -n "$_pat" ]] && GREP_EXCLUDES+=("--exclude=$_pat")
done

EXCLUDE_FILES=()
if [[ -n "$EXCLUDE_FILES_CSV" ]]; then
    IFS=',' read -ra _files <<< "$EXCLUDE_FILES_CSV"
    for _file in "${_files[@]}"; do
        _file="$(trim "$_file")"
        [[ -n "$_file" ]] && EXCLUDE_FILES+=("$_file")
    done
fi

echo "Scanning: $(realpath "$SEARCH_DIR")"
echo "Excluding dirs: $EXCLUDE_DIRS_CSV"
echo "Excluding patterns: $EXCLUDE_PATTERNS_CSV"
[[ ${#EXCLUDE_FILES[@]} -gt 0 ]] && echo "Excluding files: $EXCLUDE_FILES_CSV"
echo ""

declare -A FILE_CATEGORIES  # filepath -> "CAT1,CAT2,..."
AFFECTED_FILE_COUNT=0

for check in "${CHECKS[@]}"; do
    category="${check%%:*}"
    pattern="${check#*:}"

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        rel_file="${file#"$SEARCH_DIR"/}"

        skip=false
        for _excl in "${EXCLUDE_FILES[@]}"; do
            if [[ "$rel_file" == "$_excl" || "$file" == "$_excl" ]]; then
                skip=true; break
            fi
        done
        if [[ "$skip" == false ]]; then
            for _excl in "${EXCLUDE_DIR_PATHS[@]}"; do
                if [[ "$rel_file" == "$_excl"/* || "$rel_file" == "$_excl" ]]; then
                    skip=true; break
                fi
            done
        fi
        [[ "$skip" == true ]] && continue

        first_line="$(LC_ALL=C grep -Pn --binary-files=without-match "$pattern" "$file" 2>/dev/null \
            | head -1 | cut -d: -f1)"
        first_line="${first_line:-1}"

        line_content="$(sed -n "${first_line}p" "$file" 2>/dev/null || true)"
        first_col="$(echo "$line_content" | LC_ALL=C grep -Pbo "$pattern" 2>/dev/null \
            | head -1 | cut -d: -f1)"
        first_col=$(( ${first_col:-0} + 1 ))  # convert to 1-based

        link="${CATEGORY_LINKS[$category]:-}"
        echo "::error file=${rel_file},line=${first_line},col=${first_col}::Invisible Unicode [${category}] at L${first_line}:${first_col} - ${link} "

        if [[ -v FILE_CATEGORIES["$file"] ]]; then
            if [[ "${FILE_CATEGORIES[$file]}" != *"$category"* ]]; then
                FILE_CATEGORIES["$file"]+=",${category}:${first_line}:${first_col}"
            fi
        else
            FILE_CATEGORIES["$file"]="${category}:${first_line}:${first_col}"
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
        cats="${FILE_CATEGORIES[$file]}"
        cats_with_links=""
        IFS=',' read -ra cat_list <<< "$cats"
        for entry in "${cat_list[@]}"; do
            cat="${entry%%:*}"
            rest="${entry#*:}"
            line="${rest%%:*}"
            col="${rest#*:}"
            link="${CATEGORY_LINKS[$cat]:-}"
            if [[ -n "$link" ]]; then
                cats_with_links+="${cats_with_links:+, }${cat} L${line}:${col} ( ${link} )"
            else
                cats_with_links+="${cats_with_links:+, }${cat} L${line}:${col}"
            fi
        done
        echo "  ${file#"$SEARCH_DIR"/}  [${cats_with_links}]"
    done
fi

echo "============================================================"

if [[ "$AFFECTED_FILE_COUNT" -gt 0 ]]; then
    echo ""
    echo "To suppress false positives, adjust the action inputs:"
    echo ""
    echo "  exclude-files   Comma-separated relative file paths to skip entirely."
    echo "                  Example: 'path/to/file.ts,other/fixture.csv'"
    echo ""
    echo "  exclude-dirs    Comma-separated directory names or paths to skip."
    echo "                  Example: 'test,fixtures,web/apps/rest/src/module/cannavigia/test'"
    echo ""
    echo "  exclude-patterns  Comma-separated file glob patterns to skip."
    echo "                  Example: '*.csv,*.pb.dart'"
fi

# ── github output ─────────────────────────────────────────────────────────────

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "findings=${AFFECTED_FILE_COUNT}" >> "$GITHUB_OUTPUT"
else
    echo "::set-output name=findings::${AFFECTED_FILE_COUNT}"
fi

if is_true "$FAIL_ON_FOUND" && [[ "$AFFECTED_FILE_COUNT" -gt 0 ]]; then
    exit 1
fi
