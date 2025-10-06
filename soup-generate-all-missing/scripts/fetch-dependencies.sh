get_yarn_dependencies() {
    OUTPUT_FILE="$1"
    > "$OUTPUT_FILE"

    find . -name "package.json" | while read -r FILE; do     
        jq -r '.dependencies // {} | to_entries[] | "\(.key),\(.value)"' "$FILE" | sort >> ${OUTPUT_FILE}
    done
}

get_dart_dependencies() {
    OUTPUT_FILE="$1"
    > "$OUTPUT_FILE"

    TMP_JSON=$(mktemp)
    find . -name "pubspec.yaml" | while read -r FILE; do
        yq e -o=json '.' "$FILE" > "$TMP_JSON"

        jq -r '
            .dependencies as $deps |
            $deps
            | to_entries[]
            | select(
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
        ' "$TMP_JSON" >> ${OUTPUT_FILE}
        rm "$TMP_JSON"
    done
}

get_dart_resolved_dependencies() {
    OUTPUT_FILE="$1"
    > "$OUTPUT_FILE"

    find . -name "pubspec.lock" | while read -r LOCK_FILE; do
        PACKAGES_JSON=$(yq -o=json eval '.packages' "$LOCK_FILE")

        echo "$PACKAGES_JSON" | jq -r 'to_entries[] | "\(.key),\(.value.version)"' >> "$OUTPUT_FILE"
    done
}

get_yarn_resolved_dependencies() {
    OUTPUT_FILE="$1"
    > "$OUTPUT_FILE"

    find . -name "yarn.lock" -not -path "*/node_modules/*" -exec awk '
      /^"?[^"]*"?:$/ {
            line = $0
            sub(/:$/,"",line)
            gsub(/^"/,"",line)
            gsub(/"$/,"",line)

            n = split(line, keys, ", *")
            delete pkgnames
            for (i=1; i<=n; i++) {
                k = keys[i]
                gsub(/^ *"/,"",k)
                gsub(/" *$/,"",k)

                if (substr(k,1,1)=="@") {
                    if (match(k, /@[^\/]*\/[^@]*@/)) {
                        pkgname = substr(k, 1, RSTART + RLENGTH - 2)
                    } else {
                        pkgname = k
                    }
                } else {
                    if (match(k, /@[^@]*$/)) {
                        pkgname = substr(k, 1, RSTART-1)
                    } else {
                        pkgname = k
                    }
                }
                pkgnames[pkgname] = 1
            }
            next
            }

            /^  version / {
                gsub(/^[[:space:]]*version[[:space:]]*"/,"")
                gsub(/".*$/,"")
                version = $0
                for (p in pkgnames) {
                    print p "," version
                }
                delete pkgnames
            }
          ' {} + >> "$OUTPUT_FILE"
}

calculate_final_versions_for_dependencies() {
    DEPS_FILE="$1"
    RESOLVED_DEPS_FILE="$2"
    OUTPUT_FILE="${3:-$DEPS_FILE.resolved.csv}"

    TMP_FILE=$(mktemp)

    while IFS=',' read -r PACKAGE VERSION
    do        
        CLEAN_PACKAGE=$(echo "$PACKAGE" | tr -d '"')        
        RESOLVED_VERSION=$(awk -F, -v pkg="$CLEAN_PACKAGE" '
            {
                gsub(/^"|"$/, "", $1)
                if ($1 == pkg) {
                    gsub(/^"|"$/, "", $2)
                    print $2
                    exit
                }
            }' "$RESOLVED_DEPS_FILE")

        if [ -z "$RESOLVED_VERSION" ] || [ "$RESOLVED_VERSION" = "null" ]; then
            CLEAN_VERSION=$(echo "$VERSION" | sed -E 's/^[^0-9]*//; s/^["'\'']//; s/["'\'']$//')
            echo "Warning: Could not find version for $PACKAGE in dependencies, using provided version '$CLEAN_VERSION'"
            FINAL_VERSION="$CLEAN_VERSION"
        else
            FINAL_VERSION="$RESOLVED_VERSION"
        fi


        echo "$CLEAN_PACKAGE,$FINAL_VERSION" >> "$TMP_FILE"

        if [ -n "$DEBUG" ]; then
            echo "$CLEAN_PACKAGE => Original: $VERSION, Resolved: $FINAL_VERSION"
        fi
    done < "$DEPS_FILE"

    sort -t, -k1,1 "$TMP_FILE" > "$OUTPUT_FILE"

    rm -f "$TMP_FILE"
    echo "Resolved dependencies written to $OUTPUT_FILE"
}
