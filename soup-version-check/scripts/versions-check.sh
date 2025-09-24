#!/bin/bash

SCRIPT="./version-check.sh"

if [[ -z $MONTHS ]]; then
    MONTHS=6
fi

if [[ -z $OUTPUT_FILE ]]; then
    OUTPUT_FILE="versions-report.csv"
fi

DART_DEPENDENCIES_OUTPUT='dart_dependencies.csv'
NODE_DEPENDENCIES_OUTPUT='node_dependencies.csv'
OUTPUT_FILE_TMP='tmp.csv'

rm -r $DART_DEPENDENCIES_OUTPUT $NODE_DEPENDENCIES_OUTPUT $OUTPUT_FILE $OUTPUT_FILE_TMP

fetch_dependencies() { 
    mkdir -p results

    FILES=$(git ls-files | grep -E "package\.json$|pubspec\.yaml$" || true)

    for FILE in $FILES; do
      EXT="${FILE##*.}"
      if [[ "$EXT" == "json" ]]; then
        jq -r '.dependencies // {} | to_entries[] | "\(.key),\(.value)"' "$FILE" | sort >> ${NODE_DEPENDENCIES_OUTPUT}
      elif [[ "$EXT" == "yaml" ]]; then
        TMP_JSON=$(mktemp)
        yq e -o=json '.' "$FILE" > "$TMP_JSON"

        jq -r '
            .dependencies as $deps |
            $deps
            | to_entries[]
            | select(
                # Keep only entries that are NOT {sdk: "flutter"}
                (.value | type != "object" or (.sdk // "") != "flutter")
              )
            | {
                name: .key,
                version_or_url: (
                    if (.value | type == "string") then
                        .value
                    elif (.value | type == "object" and has("version")) then
                        .value.version
                    else
                        "unknown"
                    end
                )
            }
            | select(.version_or_url != "unknown") 
            | [.name, .version_or_url]
            | @csv
        ' "$TMP_JSON" >> ${DART_DEPENDENCIES_OUTPUT}
        rm "$TMP_JSON"
        fi
    done
}


verify_version() {
    RUNTIME=$1
    NAME=$2
    VERSION=$3
    
    CLEAN_VERSION=$(echo "$VERSION" | sed -E 's/^[^0-9]*//; s/^["'\'']//; s/["'\'']$//')

    JSON_OUTPUT=$("$SCRIPT" "$RUNTIME" "$NAME" "$CLEAN_VERSION" "$MONTHS")
    echo "$RUNTIME,$JSON_OUTPUT" | tee -a $OUTPUT_FILE_TMP
}

verify_versions() {
    FILE="$1"
    TYPE="$2"

    while IFS=',' read -r name version
    do
        verify_version "$TYPE" "$name" "$version"
    done < "$FILE"
}

fetch_dependencies

verify_versions "$NODE_DEPENDENCIES_OUTPUT" "node" || true
verify_versions "$DART_DEPENDENCIES_OUTPUT" "dart" || true

echo "Ecosystem,Name,Version,Status,Age" > $OUTPUT_FILE
sort -t',' -k4,4 -k1,1 -k2,2 $OUTPUT_FILE_TMP >> $OUTPUT_FILE