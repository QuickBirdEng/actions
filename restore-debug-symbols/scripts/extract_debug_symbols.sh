#!/usr/bin/env bash
set -euo pipefail

download_dir="${RUNNER_TEMP}/qb-debug-symbols-download"
symbols_dir="${INPUT_DESTINATION}"

rm -rf "$symbols_dir"
mkdir -p "$symbols_dir"

platforms=""
release=""

for archive in "$download_dir"/debug-symbols-*.tar.gz; do
    [[ -f "$archive" ]] || continue

    name="$(basename "$archive" .tar.gz)"
    platform="${name#debug-symbols-}"
    target="${symbols_dir}/${platform}"

    mkdir -p "$target"
    tar -xzf "$archive" -C "$target"
    platforms="${platforms:+$platforms }$platform"
    echo "Restored '$platform' from $(basename "$archive")"

    if [[ -z "$release" && -f "$target/metadata.env" ]]; then
        release="$(sed -n 's/^release=//p' "$target/metadata.env" | head -1)"
    fi
done

if [[ -z "$platforms" ]]; then
    {
        echo "found=false"
        echo "platforms="
        echo "release="
        echo "symbols-dir=$symbols_dir"
    } >> "$GITHUB_OUTPUT"

    if [[ "${INPUT_FAIL_IF_EMPTY}" == "true" ]]; then
        echo "::error::No debug symbols were stored for this build - check the 'Store debug symbols for Sentry' step of the build jobs"
        exit 1
    fi

    echo "::warning::No debug symbols were stored for this build"
    exit 0
fi

{
    echo "found=true"
    echo "platforms=$platforms"
    echo "release=$release"
    echo "symbols-dir=$symbols_dir"
} >> "$GITHUB_OUTPUT"

echo "Restored platforms: $platforms"
echo "Sentry release: ${release:-<none>}"
