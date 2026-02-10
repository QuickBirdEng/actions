#!/bin/bash
set -euo pipefail

if [ $# -lt 4 ]; then
    echo "Usage: $0 <type> <package> <version> <months>"
    echo "type: dart | node"
    exit 1
fi

TYPE=${1//\"/}
PACKAGE=${2//\"/}
VERSION=${3//\"/}
MONTHS=${4//\"/}

output_error() {
    local msg="$1"
    CSV_LINE=$(printf '%s,%s,%s,"%s","%s","%s"\n' "$PACKAGE" "$VERSION" "ERROR: $msg" "N/A" "N/A" "N/A")
    echo "$CSV_LINE"
    exit 0
}

IS_DISCONTINUED="false"
DEPRECATION_TEXT=""

if [[ "$TYPE" == *"dart"* ]]; then
    URL="https://pub.dev/api/packages/$PACKAGE"
    JSON=$(curl -s "$URL") || output_error "failed to fetch package"

    IS_DISCONTINUED=$(echo "$JSON" | jq -r '.isDiscontinued // false')
    PUBLISHED=$(echo "$JSON" | jq -r --arg v "$VERSION" '.versions[] | select(.version==$v) | .published')
    [ -z "$PUBLISHED" ] && output_error "package not found $URL"
    [ "$PUBLISHED" == "null" ] && output_error "version not found"
elif [ "$TYPE" == "node" ]; then
    URL="https://registry.npmjs.org/$PACKAGE"
    JSON=$(curl -s "$URL") || output_error "failed to fetch package"
    PUBLISHED=$(echo "$JSON" | jq -r --arg v "$VERSION" '.time[$v] // empty')
    [ -z "$PUBLISHED" ] && output_error "package or version not found"

    DEPRECATED=$(echo "$JSON" | jq -r --arg v "$VERSION" '.versions[$v].deprecated // empty')
    if [ -n "$DEPRECATED" ]; then
        IS_DISCONTINUED="true"
        DEPRECATION_TEXT="${DEPRECATED//,/;}"
    fi
else
    output_error "unknown package type: '$TYPE'"
fi

if ! date -d "$PUBLISHED" >/dev/null 2>&1; then
    output_error "Package or version not found / invalid published date"
    exit 0
fi

to_epoch() {
    local ts="$1"
    date -d "$ts" +%s
}

PUBLISHED_TS=$(to_epoch "$PUBLISHED")
TODAY_EPOCH=$(date +%s)
TODAY_ISO=$(date -d "@$TODAY_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
REF_TS=$(date -d "$TODAY_ISO -$MONTHS months" +%s)

DIFF_SECONDS=$(( TODAY_EPOCH - PUBLISHED_TS ))
DIFF_DAYS=$(( DIFF_SECONDS / 86400 ))
DIFF_MONTHS=$(( DIFF_DAYS / 30 ))

if [ "$IS_DISCONTINUED" == "true" ]; then
    STATUS="DISCONTINUED ($DEPRECATION_TEXT)"
elif [ "$PUBLISHED_TS" -ge "$REF_TS" ]; then
    STATUS="OK"
else
    STATUS="EXCEEDS_LIMIT (of $MONTHS months)"
fi

# Compute the last 2 version families ignoring patches (group by major.minor),
# then check if the current version's major.minor is one of the last 2.
INPUT_MAJOR=$(echo "$VERSION" | cut -d. -f1)
INPUT_MINOR=$(echo "$VERSION" | cut -d. -f2)
CURRENT_FAMILY="${INPUT_MAJOR}.${INPUT_MINOR}"

if [[ "$TYPE" == *"dart"* ]]; then
    ALL_VERSIONS_RAW=$(echo "$JSON" | jq -r '[.versions[].version] | .[]' 2>/dev/null)
else
    ALL_VERSIONS_RAW=$(echo "$JSON" | jq -r '[.time | keys[] | select(. != "created" and . != "modified")] | .[]' 2>/dev/null)
fi

# Extract unique major.minor families, sort by major then minor numerically, take last 2
FAMILIES=$(echo "$ALL_VERSIONS_RAW" | grep -oE '^[0-9]+\.[0-9]+' | sort -t. -k1,1n -k2,2n -u | tail -n 2 | sort -t. -k1,1n -k2,2n -r | tr '\n' ' ' | xargs)

FAMILIES_STR=$(echo "$FAMILIES" | tr ' ' '|')
if echo " $FAMILIES " | grep -qw "$CURRENT_FAMILY"; then
    VERSION_RECENCY="OK"
else
    VERSION_RECENCY="OUTDATED"
fi

CSV_LINE=$(printf '%s,%s,%s,"%s","%s","%s"\n' "$PACKAGE" "$VERSION" "$STATUS" "${DIFF_MONTHS} months (${DIFF_DAYS} days)" "$FAMILIES_STR" "$VERSION_RECENCY")
echo "$CSV_LINE"
