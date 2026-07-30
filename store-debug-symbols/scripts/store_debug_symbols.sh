#!/usr/bin/env bash
set -euo pipefail

# ── input validation ──────────────────────────────────────────────────────────

platform="${INPUT_PLATFORM:-}"
build_number="${INPUT_BUILD_NUMBER:-$GITHUB_RUN_ID}"

if [[ ! "$platform" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid platform label '$platform' (allowed: letters, digits, '.', '_', '-')"
    exit 1
fi

if [[ ! "$build_number" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid build number '$build_number' (allowed: letters, digits, '.', '_', '-')"
    exit 1
fi

# ── staging area ──────────────────────────────────────────────────────────────

staging="${RUNNER_TEMP}/qb-debug-symbols-staging/${platform}"
rm -rf "$staging"
mkdir -p "$staging"

requested=0
collected=0

# ── helpers ───────────────────────────────────────────────────────────────────

# Both helpers count what was asked for and what was actually there, so a build
# that stored nothing can be told apart from one that was asked for nothing.
stage_dir() {
    local source="$1" target="$2" label="$3"
    requested=$((requested + 1))
    if [[ -d "$source" ]] && [[ -n "$(ls -A "$source")" ]]; then
        mkdir -p "$staging/$target"
        cp -R "$source"/. "$staging/$target"/
        collected=$((collected + 1))
        echo "Collected $label from $source"
    else
        echo "::warning::No $label found at '$source' - skipping"
    fi
}

stage_file() {
    local source="$1" target="$2" label="$3"
    requested=$((requested + 1))
    if [[ -f "$source" ]]; then
        mkdir -p "$staging/$(dirname "$target")"
        cp "$source" "$staging/$target"
        collected=$((collected + 1))
        echo "Collected $label from $source"
    else
        echo "::warning::No $label found at '$source' - skipping"
    fi
}

# ── collect ───────────────────────────────────────────────────────────────────

if [[ -n "${INPUT_DSYMS_PATH:-}" ]]; then
    stage_dir "$INPUT_DSYMS_PATH" "dsyms" "iOS dSYMs"
fi

if [[ -n "${INPUT_DART_SYMBOLS_FILE_PATH:-}" ]]; then
    stage_dir "$INPUT_DART_SYMBOLS_FILE_PATH" "dart-symbols" "Dart symbols"
fi

if [[ -n "${INPUT_DART_OBFUSCATION_MAP_FILE_PATH:-}" ]]; then
    stage_file "$INPUT_DART_OBFUSCATION_MAP_FILE_PATH" "dart-symbols/obfuscation.map.json" "Dart obfuscation map"
fi

if [[ -n "${INPUT_PROGUARD_MAPPING_FILE_PATH:-}" ]]; then
    stage_file "$INPUT_PROGUARD_MAPPING_FILE_PATH" "proguard/mapping.txt" "ProGuard mapping"
fi

if [[ "$collected" -eq 0 ]]; then
    echo "stored=false" >> "$GITHUB_OUTPUT"
    if [[ "$requested" -gt 0 ]]; then
        echo "::error::None of the $requested requested debug symbol paths exist - nothing to store for '$platform'"
        exit 1
    fi
    echo "::warning::No debug symbol paths given for '$platform' - nothing to store"
    exit 0
fi

# ── metadata travelling with the archive ──────────────────────────────────────

{
    echo "platform=$platform"
    echo "release=${INPUT_RELEASE:-}"
    echo "build_number=$build_number"
    echo "run_id=${GITHUB_RUN_ID}"
    echo "run_attempt=${GITHUB_RUN_ATTEMPT}"
    echo "sha=${GITHUB_SHA}"
    echo "ref=${GITHUB_REF}"
} > "$staging/metadata.env"

# ── archive ───────────────────────────────────────────────────────────────────

archive_dir="${RUNNER_TEMP}/qb-debug-symbols"
mkdir -p "$archive_dir"
archive="${archive_dir}/debug-symbols-${platform}.tar.gz"
rm -f "$archive"
tar -C "$staging" -czf "$archive" .

{
    echo "stored=true"
    echo "archive=$archive"
    echo "key-prefix=${GITHUB_REPOSITORY##*/}/debug-symbols/${build_number}"
} >> "$GITHUB_OUTPUT"

echo "Archive: $(du -h "$archive" | cut -f1) at $archive"
tar -tzf "$archive"
