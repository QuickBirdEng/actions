SOUPS_DIR=".soups"
mkdir -p $SOUPS_DIR/npm
mkdir -p $SOUPS_DIR/dart

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

normalized_versions_before_this_version() {
    local version="$1"

    if [[ "$version" =~ ^([0-9]+)\.x\.x$ ]]; then
        local major="${BASH_REMATCH[1]}"
        for ((n=0; n<=9; n++)); do
            echo "0.${n}.x"
        done
        for ((m=1; m<major; m++)); do
            echo "${m}.x.x"
        done

    elif [[ "$version" =~ ^0\.([0-9]+)\.x$ ]]; then
        local minor="${BASH_REMATCH[1]}"
        for ((n=0; n<minor; n++)); do
            echo "0.${n}.x"
        done

    else
        echo "invalid normalized version format: $version" >&2
        return 1
    fi
}

retire_soup_older_versions_if_present() { 
    local PACKAGE="$1"
    local TYPE="$2"
    local VERSION="$3"

    OLD_VERSIONS_SOUPS=$(normalized_versions_before_this_version "$VERSION")

    for OLD_VERSIONS_SOUP in $OLD_VERSIONS_SOUPS; do
        local FILE=$SOUPS_DIR/$TYPE/$PACKAGE-$OLD_VERSIONS_SOUP.json
        if [[ -f "$FILE" ]]; then
            echo "ℹ️ Retiring Old SOUP: $(basename "$FILE")"
            rm -rf "$FILE"
        fi
    done
}

check_if_soup_exists_and_is_approved() {
    local FILE="$1"

    if [[ -f "$FILE" ]]; then
        if jq -e '.metadata.approval.by != null and .metadata.approval.by != "" and
                  .metadata.approval.date != null and .metadata.approval.date != ""' "$FILE" > /dev/null; then
          APPROVAL_DATE=$(jq -r '.metadata.approval.date' "$FILE")
    
          echo "ℹ️$(basename "$FILE") already exists and is approved on $APPROVAL_DATE"
          return 1
        fi
    fi

    return 0
}
