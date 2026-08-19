#!/usr/bin/env bash
# Filter a Gradle combined lockfile down to the runtimeClasspath entries: the true shipped
# closure.
#
# dependencyLocking { lockAllConfigurations() } writes every configuration onto one shared
# file, each dependency line tagged with every configuration it resolves in, e.g.
#   com.squareup.okhttp3:mockwebserver:4.9.0=testCompileClasspath,testRuntimeClasspath
# Reading the file undifferentiated treats every locked coordinate as shipped. Measured on a
# real lockfile: 56 of 143 components were tagged only with test/build-tooling configurations
# and never ship, yet got real classified findings and remediation burden.
#
# A line with no discernible configuration tag is kept, not dropped: not knowing whether
# something ships is not the same as knowing it does not.
#
# The output is always named gradle.lockfile, never something else: syft's gradle-lockfile
# cataloger triggers on that literal filename, not on content, so a filtered copy under any
# other name is invisible to it.
#
# Usage: filter-gradle-lockfile.sh <gradle.lockfile> <out-dir>

set -uo pipefail

IN="${1:?usage: filter-gradle-lockfile.sh <gradle.lockfile> <out-dir>}"
OUT_DIR="${2:?missing output directory}"

[[ -f "$IN" ]] || { echo "::error::not found: $IN" >&2; exit 1; }
mkdir -p "$OUT_DIR"

awk -F'=' '
  /^#/ || /^empty=/ { next }
  NF < 2 { print; next }
  {
    n = split($NF, cfgs, ",")
    keep = 0
    for (i = 1; i <= n; i++) if (cfgs[i] == "runtimeClasspath") keep = 1
    if (keep) print
  }
' "$IN" > "$OUT_DIR/gradle.lockfile"

TOTAL=$(grep -vcE '^#|^empty=' "$IN")
KEPT=$(wc -l < "$OUT_DIR/gradle.lockfile" | tr -d ' ')
echo "gradle lockfile: kept $KEPT of $TOTAL entries as the runtimeClasspath closure" >&2
