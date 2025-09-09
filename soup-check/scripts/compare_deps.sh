#!/bin/bash

BASE_SHA="$1"
CURRENT_FILE="$2"

if [[ -n "$3" ]]; then
    echo "Dependencies Not Following Semantic Versioning: $3"
    NON_SEMVER_DEP_LIST="$3"
fi

if [[ ! -f "$CURRENT_FILE" ]]; then
    echo "Please pass package.json or pubspec.yaml!"
    exit 1
fi

REF_FILE="package_${BASE_SHA}.json"
git show "$BASE_SHA:$CURRENT_FILE" > $REF_FILE

EXT="${CURRENT_FILE##*.}"

if [[ "$EXT" == "json" ]]; then
    CURRENT_DEPS=$(jq -r '.dependencies // {} | to_entries[] | "\(.key)=\(.value)"' "$CURRENT_FILE")
    REF_DEPS=$(jq -r '.dependencies // {} | to_entries[] | "\(.key)=\(.value)"' "$REF_FILE")
elif [[ "$EXT" == "yaml" || "$EXT" == "yml" ]]; then
    CURRENT_DEPS=$(awk '/^dependencies:/{flag=1;next}/^[^ ]/{flag=0}flag' "$CURRENT_FILE" \
      | sed 's/^[ \t]*//' \
      | awk -F: '/^[^ ]+:/ {print $1"="$2}' \
      | sed 's/ //g' \
      | grep -v '=') # ignore lines without a version
    REF_DEPS=$(awk '/^dependencies:/{flag=1;next}/^[^ ]/{flag=0}flag' "$REF_FILE" \
      | sed 's/^[ \t]*//' \
      | awk -F: '/^[^ ]+:/ {print $1"="$2}' \
      | sed 's/ //g' \
      | grep -v '=') # ignore lines without a version
else
    echo "Unsupported file type: $EXT"
    exit 1
fi

TMP_CUR=$(mktemp)
TMP_REF=$(mktemp)
echo "$CURRENT_DEPS" | sort > "$TMP_CUR"
echo "$REF_DEPS" | sort > "$TMP_REF"

ADDED=$(comm -23 <(cut -d= -f1 "$TMP_CUR") <(cut -d= -f1 "$TMP_REF") | while read dep; do
    ver=$(grep "^$dep=" "$TMP_CUR" | cut -d= -f2)
    echo "$dep ($ver)"
done)

REMOVED=$(comm -13 <(cut -d= -f1 "$TMP_CUR") <(cut -d= -f1 "$TMP_REF") | while read dep; do
    ver=$(grep "^$dep=" "$TMP_REF" | cut -d= -f2)
    echo "$dep ($ver)"
done)

CHANGED=""
if [[ "$EXT" == "json" ]]; then
    for dep in $(jq -r '.dependencies | keys[]' "$CURRENT_FILE"); do
        cur_ver=$(jq -r ".dependencies.\"$dep\"" "$CURRENT_FILE")
        ref_ver=$(jq -r ".dependencies.\"$dep\"" "$REF_FILE")
        if [[ "$ref_ver" != "null" && "$cur_ver" != "$ref_ver" ]]; then
            CHANGED+="$dep:$ref_ver->$cur_ver"$'\n'
        fi
    done
else
    for dep in $(cut -d= -f1 "$TMP_CUR"); do
        cur_ver=$(grep "^$dep=" "$TMP_CUR" | cut -d= -f2)
        ref_ver=$(grep "^$dep=" "$TMP_REF" | cut -d= -f2)
        if [[ -n "$ref_ver" && "$cur_ver" != "$ref_ver" ]]; then
            CHANGED+="$dep:$ref_ver->$cur_ver"$'\n'
        fi
    done
fi

breaking_major_changes=""
breaking_minor_changes=""

while IFS= read -r line; do
    dep=$(echo "$line" | cut -d: -f1)
    old_ver=$(echo "$line" | cut -d: -f2 | cut -d- -f1 | tr -d ' ^~><=')
    new_ver=$(echo "$line" | cut -d: -f2 | cut -d- -f2 | tr -d ' ^~><=' | sed 's/^>//')

    old_major=$(echo "$old_ver" | cut -d. -f1)
    old_minor=$(echo "$old_ver" | cut -d. -f2)
    new_major=$(echo "$new_ver" | cut -d. -f1)
    new_minor=$(echo "$new_ver" | cut -d. -f2)

    if [[ -n "$old_major" && -n "$new_major" ]]; then
        if [[ "$old_major" != "$new_major" ]]; then
            breaking_major_changes+="$dep ($old_ver -> $new_ver)\n"
        elif [[ "$old_major" == "0" && "$new_minor" != "$old_minor" ]]; then
            breaking_minor_changes+="$dep ($old_ver -> $new_ver)\n"
        elif [[ "$NON_SEMVER_DEP_LIST" == *"$dep"* ]]; then
            breaking_major_changes+="$dep ($old_ver -> $new_ver)\n"
        fi
    fi
done <<< "$CHANGED"

bang_bang="‼️ "
echo -e "🚨 RISK REPORT for $CURRENT_FILE 🚨\n"
[[ -n "$ADDED" ]] && echo -e "=== 🌱 Added: ===\n$ADDED\n"
[[ -n "$REMOVED" ]] && echo -e "=== ❌ Removed: ===\n$REMOVED\n"
[[ -n "$CHANGED" ]] && echo -e "=== 🔄 All Changes: ===\n$CHANGED\n"
[[ -n "$breaking_major_changes" ]] && echo -e "=== $bang_bang Breaking Changes (Major + Non-SemVer) : ===\n$breaking_major_changes\n"
[[ -n "$breaking_minor_changes" ]] && echo -e "=== ❗️ Breaking Changes (Minor i.e. 0.x.-): ===\n$breaking_minor_changes\n"

summary=""
[[ -n "$ADDED" ]] && summary+="additions,"
[[ -n "$REMOVED" ]] && summary+="deletions,"
[[ -n "$breaking_major_changes" || -n "$breaking_minor_changes" ]] && summary+="changes"
summary="${summary%,}"

[[ -n "$summary" ]] && echo "$summary" || echo "nothing"

rm "$TMP_CUR" "$TMP_REF"
