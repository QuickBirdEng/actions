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

generate_soups() { 
    FILE="$1"
    TYPE="$2"
        
    while IFS=',' read -r PACKAGE VERSION
    do            
        VERSION=$(echo "$VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        echo "$PACKAGE => $VERSION"
        NORMALIZED_VERSION=$(normalized_version "$VERSION")
        NORMALIZED_PACKAGE=$(echo "$PACKAGE" | tr '/' '-')

        FILE_PATH=$SOUPS_DIR/$TYPE/$NORMALIZED_PACKAGE-$NORMALIZED_VERSION.json

        retire_soup_older_versions_if_present "$NORMALIZED_PACKAGE" "$TYPE" "$NORMALIZED_VERSION"
        check_if_soup_exists_and_is_approved "$FILE_PATH"
        if [[ $? -ne 0 ]]; then
            continue
        fi

        CREATION_DATE=""
        [ -f "$FILE_PATH" ] && CREATION_DATE=$(jq -r '.metadata.created // ""' "$FILE_PATH" 2>/dev/null || echo "")
        [ ! -z "$CREATION_DATE" ] && echo "Creation Date: $CREATION_DATE"

        bash generate-soup.sh "$TYPE" "$PACKAGE" "$VERSION" "$NORMALIZED_VERSION" "$CREATION_DATE" > $FILE_PATH
    done < "$FILE"
}

generate_soups $DEPS_YARN_FINAL_FILE npm
generate_soups $DEPS_DART_FINAL_FILE dart
