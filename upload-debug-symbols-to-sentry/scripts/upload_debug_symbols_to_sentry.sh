#!/usr/bin/env bash
set -euo pipefail

# ── configuration ─────────────────────────────────────────────────────────────

# sentry-cli talks to sentry.io unless a self-hosted server is configured. An
# empty --url would swallow the subcommand that follows it, so default it here.
url="${INPUT_URL:-https://sentry.io}"

# sentry-cli picks the token up from the environment, keeping it out of argv.
export SENTRY_AUTH_TOKEN="${INPUT_AUTH_TOKEN:-}"

# ── helpers ───────────────────────────────────────────────────────────────────

upload_debug_files() {
    echo "Uploading debug files from '$1'"
    sentry-cli --url "$url" debug-files upload --org "$INPUT_ORGANIZATION" --project "$INPUT_PROJECT" "$1"
}

# Sentry needs the obfuscation map paired with each individual .symbols file.
upload_dart_symbol_map() {
    local map="$1" symbols_dir="$2" debug_file
    for debug_file in "$symbols_dir"/*.symbols; do
        [[ -f "$debug_file" ]] || continue
        echo "Uploading obfuscation map for '$debug_file'"
        sentry-cli --url "$url" dart-symbol-map upload --org "$INPUT_ORGANIZATION" --project "$INPUT_PROJECT" "$map" "$debug_file"
    done
}

upload_proguard_mapping() {
    echo "Uploading proguard mapping '$1'"
    sentry-cli --url "$url" upload-proguard --org "$INPUT_ORGANIZATION" --project "$INPUT_PROJECT" "$1"
}

uploaded=0

# ── restored symbols directory (one folder per platform) ──────────────────────

if [[ -n "${INPUT_SYMBOLS_DIR:-}" ]]; then
    if [[ ! -d "$INPUT_SYMBOLS_DIR" ]]; then
        echo "::error::symbols-dir '$INPUT_SYMBOLS_DIR' does not exist"
        exit 1
    fi

    for platform_dir in "$INPUT_SYMBOLS_DIR"/*/; do
        platform_dir="${platform_dir%/}"
        [[ -d "$platform_dir" ]] || continue
        echo "::group::Sentry upload for $(basename "$platform_dir")"

        if [[ -d "$platform_dir/dsyms" ]]; then
            upload_debug_files "$platform_dir/dsyms"
            uploaded=$((uploaded + 1))
        fi

        if [[ -d "$platform_dir/dart-symbols" ]]; then
            upload_debug_files "$platform_dir/dart-symbols"
            uploaded=$((uploaded + 1))

            if [[ -f "$platform_dir/dart-symbols/obfuscation.map.json" ]]; then
                upload_dart_symbol_map "$platform_dir/dart-symbols/obfuscation.map.json" "$platform_dir/dart-symbols"
            fi
        fi

        if [[ -f "$platform_dir/proguard/mapping.txt" ]]; then
            upload_proguard_mapping "$platform_dir/proguard/mapping.txt"
            uploaded=$((uploaded + 1))
        fi

        echo "::endgroup::"
    done

    # Restoring symbols and then uploading nothing means the build stored nothing.
    if [[ "$uploaded" -eq 0 ]]; then
        echo "::error::No debug symbols found under '$INPUT_SYMBOLS_DIR'"
        exit 1
    fi
fi

# ── explicit paths, for callers that upload straight from a build job ─────────

# A path that does not exist is skipped with a warning: a release build without
# minification has no mapping file, and that must not fail the job.

if [[ -n "${INPUT_DART_SYMBOLS_FILE_PATH:-}" ]]; then
    if [[ -d "$INPUT_DART_SYMBOLS_FILE_PATH" ]]; then
        upload_debug_files "$INPUT_DART_SYMBOLS_FILE_PATH"
        uploaded=$((uploaded + 1))

        if [[ -n "${INPUT_DART_OBFUSCATION_MAP_FILE_PATH:-}" && -f "${INPUT_DART_OBFUSCATION_MAP_FILE_PATH}" ]]; then
            upload_dart_symbol_map "$INPUT_DART_OBFUSCATION_MAP_FILE_PATH" "$INPUT_DART_SYMBOLS_FILE_PATH"
        fi
    else
        echo "::warning::No dart symbols found at '$INPUT_DART_SYMBOLS_FILE_PATH' - skipping"
    fi
fi

if [[ -n "${INPUT_DSYMS_PATH:-}" ]]; then
    if [[ -d "$INPUT_DSYMS_PATH" ]]; then
        upload_debug_files "$INPUT_DSYMS_PATH"
        uploaded=$((uploaded + 1))
    else
        echo "::warning::No dSYMs found at '$INPUT_DSYMS_PATH' - skipping"
    fi
fi

if [[ -n "${INPUT_PROGUARD_MAPPING_FILE_PATH:-}" ]]; then
    if [[ -f "$INPUT_PROGUARD_MAPPING_FILE_PATH" ]]; then
        upload_proguard_mapping "$INPUT_PROGUARD_MAPPING_FILE_PATH"
        uploaded=$((uploaded + 1))
    else
        echo "::warning::No proguard mapping found at '$INPUT_PROGUARD_MAPPING_FILE_PATH' - skipping"
    fi
fi

if [[ "$uploaded" -eq 0 ]]; then
    echo "::warning::Nothing was uploaded to Sentry - no symbol paths were given"
fi
