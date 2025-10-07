#!/bin/bash

set -e
BASE_REF="$1"
CURRENT_FILE="$2"

if [[ -n "$3" ]]; then
    echo "Dependencies Not Following Semantic Versioning: $3"
    NON_SEMVER_DEP_LIST="$3"
fi

if [[ ! -f "$CURRENT_FILE" ]]; then
    echo "Please pass a valid package.json or pubspec.yaml!"
    exit 1
fi

EXT="${CURRENT_FILE##*.}"

REF_FILE="package_ref.$EXT"
git show "$BASE_REF:$CURRENT_FILE" > "$REF_FILE" 2>/dev/null || true

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
    [[ -n "$dep" ]] && {
        ver=$(grep "^$dep=" "$TMP_CUR" | cut -d= -f2)
        clean_ver=$(echo "$ver" | tr -d ' ^~><=')
        jq -n --arg dep "$dep" --arg ver "$clean_ver" '{name: $dep, version: $ver}'
    }
done | jq -s '.')

REMOVED=$(comm -13 <(cut -d= -f1 "$TMP_CUR") <(cut -d= -f1 "$TMP_REF") | while read dep; do
    [[ -n "$dep" ]] && {
        ver=$(grep "^$dep=" "$TMP_REF" | cut -d= -f2)
        clean_ver=$(echo "$ver" | tr -d ' ^~><=')
        jq -n --arg dep "$dep" --arg ver "$clean_ver" '{name: $dep, version: $ver}'
    }
done | jq -s '.')

CHANGED=()
BREAKING_MAJOR_CHANGES=()
BREAKING_MINOR_CHANGES=()

calculate_major_or_minor_breaking_changes() {
    dep="$1"
    old_ver="$2"
    new_ver="$3"

if [[ "$old_ver" == *"git"* || "$new_ver" == *"git"* ]]; then
    old_url="${old_ver%@*}"
    new_url="${new_ver%@*}"

    if [[ "$old_url" != "$new_url" ]]; then
        BREAKING_MAJOR_CHANGES+=($(jq -n --arg dep "$dep" --arg old_ver "$old_ver" --arg new_ver "$new_ver" '{name: $dep, old_version: $old_ver, version: $new_ver}'))
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
            BREAKING_MAJOR_CHANGES+=($(jq -n --arg dep "$dep" --arg old_ver "$old_clean" --arg new_ver "$new_clean" '{name: $dep, old_version: $old_ver, version: $new_ver}'))
        elif [[ "$old_major" == "0" && "$new_minor" != "$old_minor" ]]; then
            BREAKING_MINOR_CHANGES+=($(jq -n --arg dep "$dep" --arg old_ver "$old_clean" --arg new_ver "$new_clean" '{name: $dep, old_version: $old_ver, version: $new_ver}'))
        elif [[ "$NON_SEMVER_DEP_LIST" == *"$dep"* ]]; then
            BREAKING_MAJOR_CHANGES+=($(jq -n --arg dep "$dep" --arg old_ver "$old_clean" --arg new_ver "$new_clean" '{name: $dep, old_version: $old_ver, version: $new_ver}'))
        fi
    fi
}


for dep in $(cut -d= -f1 "$TMP_CUR"); do
    cur_ver=$(grep "^$dep=" "$TMP_CUR" | cut -d= -f2)
    ref_ver=$(grep "^$dep=" "$TMP_REF" | cut -d= -f2)
    if [[ -n "$ref_ver" && "$cur_ver" != "$ref_ver" ]]; then
        CHANGED+=($(jq -n --arg dep "$dep" --arg old_ver "$ref_ver" --arg new_ver "$cur_ver" '{name: $dep, old_version: $old_ver, version: $new_ver}'))
        calculate_major_or_minor_breaking_changes "$dep" "$ref_ver" "$cur_ver"
    fi
done

CHANGED=$(echo "${CHANGED[@]}" | tr ' ' '\n' | jq -s '.')
BREAKING_MAJOR_CHANGES=$(echo "${BREAKING_MAJOR_CHANGES[@]}" | tr ' ' '\n' | jq -s '.')
BREAKING_MINOR_CHANGES=$(echo "${BREAKING_MINOR_CHANGES[@]}" | tr ' ' '\n' | jq -s '.')

jq -n \
  --argjson added "$ADDED" \
  --argjson removed "$REMOVED" \
  --argjson changed "$CHANGED" \
  --argjson breaking_major "$BREAKING_MAJOR_CHANGES" \
  --argjson breaking_minor "$BREAKING_MINOR_CHANGES" \
  '{
      changed: ($added + $breaking_major + $breaking_minor),
      removed: $removed,
  }'

rm "$TMP_CUR" "$TMP_REF" "$REF_FILE"