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
