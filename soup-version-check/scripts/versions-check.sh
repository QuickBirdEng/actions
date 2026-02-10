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

rm -rf $DART_DEPENDENCIES_OUTPUT $NODE_DEPENDENCIES_OUTPUT $OUTPUT_FILE $OUTPUT_FILE_TMP

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
    
    JSON_OUTPUT=$("$SCRIPT" "$RUNTIME" "$NAME" "$VERSION" "$MONTHS")
    echo "$RUNTIME,$JSON_OUTPUT" | tee -a $OUTPUT_FILE_TMP
}

verify_versions() {
    FILE="$1"
    TYPE="$2"
    
    while IFS=',' read -r PACKAGE VERSION
    do
        if [ "$TYPE" == "dart" ]; then
            DEPS_FILE="dart-deps.csv"
        elif [ "$TYPE" == "node" ]; then
            DEPS_FILE="yarn-deps.csv"
        else
            echo "Unknown type: $TYPE"
            exit 1
        fi
        
        CLEAN_PACKAGE=$(echo "$PACKAGE" | tr -d '"')        
        RESOLVED_VERSION=$(awk -F, -v pkg="$CLEAN_PACKAGE" '
            {
                # Remove quotes from first field
                gsub(/^"|"$/, "", $1)
                if ($1 == pkg) {
                    gsub(/^"|"$/, "", $2)
                    print $2
                    exit
                }
            }' "$DEPS_FILE")

        if [ -z "$RESOLVED_VERSION" ] || [ "$RESOLVED_VERSION" = "null" ]; then
            CLEAN_VERSION=$(echo "$VERSION" | sed -E 's/^[^0-9]*//; s/^["'\'']//; s/["'\'']$//')
            echo "Warning: Could not find version for $PACKAGE in $TYPE dependencies, using provided version '$CLEAN_VERSION'"
            FINAL_VERSION="$CLEAN_VERSION"
        else
            FINAL_VERSION="$RESOLVED_VERSION"
        fi

        verify_version "$TYPE" "$PACKAGE" "$FINAL_VERSION"
    done < "$FILE"
}

fetch_dependencies

verify_versions "$NODE_DEPENDENCIES_OUTPUT" "node" || true
verify_versions "$DART_DEPENDENCIES_OUTPUT" "dart" || true

echo "Ecosystem,Name,Version,Status,Age,Last Versions,Version Recency" > $OUTPUT_FILE
sort -t',' -k4,4 -k1,1 -k2,2 $OUTPUT_FILE_TMP >> $OUTPUT_FILE