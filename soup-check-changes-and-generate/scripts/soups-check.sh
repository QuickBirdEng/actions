source ./soup-utils.sh

BASE_REF="$1"

echo "Base Ref: $BASE_REF"

find . \( -name "package.json" -o -name "pubspec.yaml" \) | while read -r FILE; do
    echo "---- Checking $FILE ----"
    RESULT=$(bash soup-check.sh "$BASE_REF" "$FILE")
    echo "$RESULT"
    
    TYPE=$([[ "$FILE" == *"package.json"* ]] && echo "npm" || echo "dart")
    for object in $(jq -c '.changed[]' <<< "$RESULT"); do
        PACKAGE=$(jq -r '.name' <<< "$object")
        VERSION=$(jq -r '.version' <<< "$object")
        
        NORMALIZED_VERSION=$(normalized_version "$VERSION")
        NORMALIZED_PACKAGE=$(echo "$PACKAGE" | tr '/' '-')

        FILE_PATH=$SOUPS_DIR/$TYPE/$NORMALIZED_PACKAGE-$NORMALIZED_VERSION.json

        retire_soup_older_versions_if_present "$NORMALIZED_PACKAGE" "$TYPE" "$NORMALIZED_VERSION"
        check_if_soup_exists_and_is_approved "$FILE_PATH"
        if [[ $? -ne 0 ]]; then
            continue
        fi

        echo "Generating soup for $PACKAGE -> $VERSION"
        bash generate-soup.sh "$TYPE" "$PACKAGE" "$VERSION" "$NORMALIZED_VERSION" > $FILE_PATH
    done

    for object in $(jq -c '.removed[]' <<< "$RESULT"); do
        PACKAGE=$(jq -r '.name' <<< "$object")
        VERSION=$(jq -r '.version' <<< "$object")
        
        echo "Removed $PACKAGE -> $VERSION"
    done
done