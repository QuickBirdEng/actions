DEPS_YARN_FILE="yarn-deps.csv"
DEPS_DART_FILE="dart-deps.csv"
DEPS_YARN_RESOLVED_FILE="yarn-deps-resolved.csv"
DEPS_DART_RESOLVED_FILE="dart-deps-resolved.csv"

source ./fetch-dependencies.sh
source ./soup-utils.sh

get_yarn_dependencies "$DEPS_YARN_FILE"
get_dart_dependencies "$DEPS_DART_FILE"
get_yarn_resolved_dependencies "$DEPS_YARN_RESOLVED_FILE"
get_dart_resolved_dependencies "$DEPS_DART_RESOLVED_FILE"

DEPS_YARN_FINAL_FILE="yarn-deps-final.csv"
DEPS_DART_FINAL_FILE="dart-deps-final.csv"

[ ! -z $DEBUG ] && echo "---- Yarn Dependencies ----"
calculate_final_versions_for_dependencies $DEPS_YARN_FILE $DEPS_YARN_RESOLVED_FILE $DEPS_YARN_FINAL_FILE

[ ! -z $DEBUG ] && echo "---- Dart Dependencies ----"
calculate_final_versions_for_dependencies $DEPS_DART_FILE $DEPS_DART_RESOLVED_FILE $DEPS_DART_FINAL_FILE

normalized_version() {
    local version="$1"

    local core="${version%%-*}"

    if [[ "$core" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"

        if (( major > 0 )); then
            echo "${major}.x.x"
        else
            echo "0.${minor}.x"
        fi
    else
        echo "$version"
    fi
}

generate_soups() { 
    FILE="$1"
    TYPE="$2"
        
    while IFS=',' read -r PACKAGE VERSION
    do            
        echo "$PACKAGE => $VERSION"
        NORMALIZED_VERSION=$(normalized_version "$VERSION")
        NORMALIZED_PACKAGE=$(echo "$PACKAGE" | tr '/' '-')

        FILE_PATH=$SOUPS_DIR/$TYPE/$NORMALIZED_PACKAGE-$NORMALIZED_VERSION.json

        if [[ -f "$FILE_PATH" ]]; then
            if jq -e '.metadata.approval.by != null and .metadata.approval.by != "" and
                      .metadata.approval.date != null and .metadata.approval.date != ""' "$FILE_PATH" > /dev/null; then
              APPROVAL_DATE=$(jq -r '.metadata.approval.date' "$FILE_PATH")
              echo "ℹ️$FILE_PATH already exists and is approved on $APPROVAL_DATE, skipping..."
              continue
            fi
        fi

        CREATION_DATE=""
        [ -f "$FILE_PATH" ] && CREATION_DATE=$(jq -r '.metadata.created // ""' "$FILE_PATH" 2>/dev/null || echo "")


        [ ! -z "$CREATION_DATE" ] && echo "Creation Date: $CREATION_DATE"

        bash generate-soup.sh "$TYPE" "$PACKAGE" "$VERSION" "$NORMALIZED_VERSION" "$CREATION_DATE" > $FILE_PATH
    done < "$FILE"
}

generate_soups $DEPS_YARN_FINAL_FILE npm
generate_soups $DEPS_DART_FINAL_FILE dart