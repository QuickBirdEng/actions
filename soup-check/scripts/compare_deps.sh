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

EXT="${CURRENT_FILE##*.}"

REF_FILE="package_${BASE_SHA}.$EXT"
git show "$BASE_SHA:$CURRENT_FILE" > "$REF_FILE"

if [[ "$EXT" == "json" ]]; then
    CURRENT_DEPS=$(jq -r '.dependencies // {} | to_entries[] | "\(.key)=\(.value)"' "$CURRENT_FILE")
    REF_DEPS=$(jq -r '.dependencies // {} | to_entries[] | "\(.key)=\(.value)"' "$REF_FILE")
elif [[ "$EXT" == "yaml" || "$EXT" == "yml" ]]; then
    TMP_JSON=$(mktemp)
    yq e -o=json '.' "$CURRENT_FILE" > "$TMP_JSON"
    CURRENT_DEPS=$(jq -r '
        .dependencies as $deps |
        $deps
        | to_entries[]
        | select((.value | type != "object" or (.sdk // "") != "flutter"))
        | "\(.key)=\(
            if (.value | type == "string") then
                .value
            elif (.value | type == "object" and has("git")) then
                .value.git.url + (if (.value.git.ref // empty) != "" then "@" + .value.git.ref else "" end)
            elif (.value | type == "object" and has("version")) then
                .value.version
            else
                "unknown"
            end
        )"
    ' "$TMP_JSON")
    TMP_JSON_REF=$(mktemp)
    yq e -o=json '.' "$REF_FILE" > "$TMP_JSON_REF"
    REF_DEPS=$(jq -r '
        .dependencies as $deps |
        $deps
        | to_entries[]
        | select((.value | type != "object" or (.sdk // "") != "flutter"))
        | "\(.key)=\(
            if (.value | type == "string") then
                .value
            elif (.value | type == "object" and has("git")) then
                .value.git.url + (if (.value.git.ref // empty) != "" then "@" + .value.git.ref else "" end)
            elif (.value | type == "object" and has("version")) then
                .value.version
            else
                "unknown"
            end
        )"
    ' "$TMP_JSON_REF")
    rm "$TMP_JSON" "$TMP_JSON_REF"
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
for dep in $(cut -d= -f1 "$TMP_CUR"); do
    cur_ver=$(grep "^$dep=" "$TMP_CUR" | cut -d= -f2)
    ref_ver=$(grep "^$dep=" "$TMP_REF" | cut -d= -f2)
    if [[ -n "$ref_ver" && "$cur_ver" != "$ref_ver" ]]; then
        CHANGED+="$dep:$ref_ver->$cur_ver"$'\n'
    fi
done

breaking_major_changes=""
breaking_minor_changes=""

while IFS= read -r line; do
    dep="${line%%:*}"
    old_ver="${line#*:}"
    old_ver="${old_ver%%->*}"
    new_ver="${line##*->}"

if [[ "$old_ver" == *"git"* || "$new_ver" == *"git"* ]]; then
    old_url="${old_ver%@*}"
    new_url="${new_ver%@*}"

    if [[ "$old_url" != "$new_url" ]]; then
        breaking_major_changes+="$dep (Git dependency changed: $old_ver -> $new_ver)\n"
        continue
    else
        old_ref="${old_ver##*@}"
        old_ref="${old_ref#v}"

        new_ref="${new_ver##*@}"
        new_ref="${new_ref#v}"

        old_ver="$old_ref"
        new_ver="$new_ref"
    fi

fi

    old_clean=$(echo "$old_ver" | tr -d ' ^~><=')
    new_clean=$(echo "$new_ver" | tr -d ' ^~><=')

    old_major=$(echo "$old_clean" | cut -d. -f1)
    old_minor=$(echo "$old_clean" | cut -d. -f2)
    new_major=$(echo "$new_clean" | cut -d. -f1)
    new_minor=$(echo "$new_clean" | cut -d. -f2)
 
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
[[ -n "$breaking_minor_changes" ]] && echo -e "=== ❗️ Breaking Changes (Minor i.e. 0.x.- or Git ref changes): ===\n$breaking_minor_changes\n"

summary=""
[[ -n "$ADDED" ]] && summary+="additions,"
[[ -n "$REMOVED" ]] && summary+="deletions,"
[[ -n "$breaking_major_changes" || -n "$breaking_minor_changes" ]] && summary+="changes"
summary="${summary%,}"

[[ -n "$summary" ]] && echo "$summary" || echo "nothing"

rm "$TMP_CUR" "$TMP_REF"
