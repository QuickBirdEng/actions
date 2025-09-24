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
    CSV_LINE=$(printf '%s,%s,%s,"%s"\n' "$PACKAGE" "$VERSION" "ERROR: $msg" "N/A")
    echo "$CSV_LINE"
    exit 0
}

get_published_date() {    
    if [[ "$TYPE" == *"dart"* ]]; then
        local url="https://pub.dev/api/packages/$PACKAGE"
        local json=$(curl -s "$url") || output_error "failed to fetch package"
        local pub=$(echo "$json" | jq -r --arg v "$VERSION" '.versions[] | select(.version==$v) | .published')
        [ -z "$pub" ] && output_error "package not found $url"
        [ "$pub" == "null" ] && output_error "version not found"
        echo "$pub"
    elif [ "$TYPE" == "node" ]; then
        local url="https://registry.npmjs.org/$PACKAGE"
        local json=$(curl -s "$url") || output_error "failed to fetch package"
        local pub=$(echo "$json" | jq -r --arg v "$VERSION" '.time[$v] // empty')
        [ -z "$pub" ] && output_error "package or version not found ($PACKAGE@$VERSION)"
        echo "$pub"
    else
        output_error "unknown package type: '$TYPE'"
    fi
}

PUBLISHED=$(get_published_date "$TYPE" "$PACKAGE" "$VERSION")

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

if [ "$PUBLISHED_TS" -ge "$REF_TS" ]; then
    STATUS="OK"
else
    STATUS="EXCEEDS_LIMIT (of $MONTHS months)"
fi


CSV_LINE=$(printf '%s,%s,%s,"%s"\n' "$PACKAGE" "$VERSION" "$STATUS" "${DIFF_MONTHS} months (${DIFF_DAYS} days)")
echo "$CSV_LINE"
