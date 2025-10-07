#!/bin/bash

TYPE=$1
PACKAGE=$2
INPUT_VERSION=$3
NORMALIZED_VERSION=$4
ORIGINAL_CREATION_DATE=${5:-""}
JSON_ONLY=${6:-true}
MONTHS=${7:-6}
MIN_RELEASES=${8:-2}

ALLOWED_LICENSES=${ALLOWED_LICENSES:-"mit,apache-2.0,bsd-2-clause,bsd-3-clause,isc,mpl-2.0,0bsd"}

if [ -z "$PACKAGE" ] || [ -z "$TYPE" ]; then
    echo "Usage: $0 <type> <package_name> [months] [min_releases]"
    exit 1
fi

if [ "$TYPE" == "dart" ]; then
    API_URL="https://pub.dev/api/packages/$PACKAGE"
    COUNT_QUERY='[.versions[] | select(.published >= $cutoff)] | length'
    DISPLAY_QUERY='[.versions[] | select(.published >= $cutoff)] | sort_by(.published) | reverse | .[] | "  " + .version + " - " + (.published | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | strftime("%B %d, %Y"))'
    VERSION_OBJECT_QUERY='[.versions[] | select(.published >= $cutoff)] | sort_by(.published) | reverse | map({(.version): (.published | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | strftime("%B %d, %Y"))}) | add'
    
    INFO_QUERY='
        (
            if (.latest.pubspec.repository? | type) == "object" then
                .latest.pubspec.repository.url // ""
            elif (.latest.pubspec.repository? | type) == "string" then
                .latest.pubspec.repository
            elif (.latest.pubspec.homepage? | type) == "object" then
                .latest.pubspec.homepage.url // ""
            elif (.latest.pubspec.homepage? | type) == "string" then
                .latest.pubspec.homepage
            else
                ""
            end
        )
        | capture("https://github\\.com/(?<org>[^/]+)/(?<repo>[^/]+)") 
        | "https://github.com/\(.org)/\(.repo)"
        as $repo
        | {
            name: .name,
            description: (.latest.pubspec.description // "N/A"),
            homepage: (.latest.pubspec.homepage // ("https://pub.dev/packages/" + .name)),
            repository: $repo,
            documentation: (.latest.pubspec.documentation // ("https://pub.dev/packages/" + .name)),
            issues: (.latest.pubspec.issue_tracker // ""),
            publisher: ($repo | capture("github\\.com/(?<owner>[^/]+)").owner?),
            license: (.latest.pubspec.license // "N/A"),
            license_spdx_id: "N/A",
            license_key: "N/A",
            license_url: "N/A",
            stars_count: 0,
            watchers_count: 0,
            forks_count: 0,
            subscribers_count: 0,
            network_count: 0,
            total_events: 0,
            push_events: 0,
            create_events: 0,
            watch_events: 0,
            fork_events: 0,
            pull_request_events: 0,
            issues_events: 0
        }'
elif [ "$TYPE" == "npm" ]; then
    API_URL="https://registry.npmjs.org/$PACKAGE"
    COUNT_QUERY='[.time | to_entries[] | select(.key != "created" and .key != "modified" and .value >= $cutoff)] | length'
    DISPLAY_QUERY='.time | to_entries | map(select(.key != "created" and .key != "modified" and .value >= $cutoff)) | sort_by(.value) | reverse | .[] | "  " + .key + " - " + (.value | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | strftime("%B %d, %Y"))'
    VERSION_OBJECT_QUERY='.time | to_entries | map(select(.key != "created" and .key != "modified" and .value >= $cutoff)) | sort_by(.value) | reverse | map({(.key): (.value | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | strftime("%B %d, %Y"))}) | add'
    
    INFO_QUERY='."dist-tags".latest as $v | {
        name: .name,
        description: (.versions[$v].description // "N/A"),
        homepage: (.versions[$v].homepage // "N/A"),
        repository: (if (.versions[$v].repository | type) == "object" then .versions[$v].repository.url else .versions[$v].repository end // .versions[$v].homepage // "N/A"),
        documentation: (.versions[$v].homepage // "N/A"),
        issues: (if (.versions[$v].bugs | type) == "object" then .versions[$v].bugs.url else .versions[$v].bugs end // "N/A"),
        publisher: (
        if (.versions[$v].repository? | type) == "object" then
            (.versions[$v].repository.url? | capture("github\\.com/(?<owner>[^/]+)").owner?)
        elif (.versions[$v].repository? | type) == "string" then
            (.versions[$v].repository | capture("github\\.com/(?<owner>[^/]+)").owner?)
        else
            empty
        end
        // (
            if (.versions[$v].homepage? | tostring | test("github\\.com")) then
            (.versions[$v].homepage | capture("github\\.com/(?<owner>[^/]+)").owner?)
            else
            empty
            end
        )
        // ""
        ),
        license: (.versions[$v].license // "N/A"),
        license_spdx_id: "N/A", 
        license_key: "N/A",
        license_url: "N/A",
        stars_count: 0,
        watchers_count: 0,
        forks_count: 0,
        subscribers_count: 0,
        network_count: 0,
        total_events: 0,
        push_events: 0,
        create_events: 0,
        watch_events: 0,
        fork_events: 0,
        pull_request_events: 0,
        issues_events: 0
    }'
else
    echo "Error: Unknown package type '$TYPE'. Use 'dart' or 'npm'"
    exit 1
fi

get_github_repo_url() { 
    local publisher="$1"
    local package="$2"
    local provider_url="$3"

    provider_url="${provider_url#git+}"
    provider_url="${provider_url%.git}"

    if [[ "$provider_url" =~ github\.com/([^/]+)/([^/]+)(\.git)?$ ]]; then
        owner="${BASH_REMATCH[1]}"
        repo="${BASH_REMATCH[2]}"
        echo "https://api.github.com/repos/${owner}/${repo}"
    else
        echo "https://api.github.com/repos/${publisher}/${package}"
    fi
}

get_github_info() {
    local publisher="$1"
    local package="$2"
    local provider_url="$3"

    base_url=$(get_github_repo_url "$publisher" "$package" "$provider_url")

    if [[ -n "$publisher" && "$publisher" != "N/A" ]]; then
        local repo_json=$(curl -s -H "Authorization: token $GH_API_TOKEN" "$base_url" 2>/dev/null)
        local license_json=$(curl -s -H "Authorization: token $GH_API_TOKEN" "$base_url/license" 2>/dev/null)
        local events_json=$(curl -s -H "Authorization: token $GH_API_TOKEN" "https://api.github.com/users/$publisher/events/public" 2>/dev/null)

        if echo "$repo_json" | jq -e . >/dev/null 2>&1; then
            local license_info='{"license_name": "N/A", "license_spdx_id": "N/A", "license_key": "N/A", "license_url": "N/A"}'
            if echo "$license_json" | jq -e . >/dev/null 2>&1; then
                license_info=$(echo "$license_json" | jq -r '{
                    license_name: (.license.name // "N/A"),
                    license_spdx_id: (.license.spdx_id // "N/A"),
                    license_key: (.license.key // "N/A"),
                    license_url: (.html_url // "N/A")
                }' 2>/dev/null || echo '{"license_name": "N/A", "license_spdx_id": "N/A", "license_key": "N/A", "license_url": "N/A"}')
            fi
            
            local activity_stats='{"total_events": 0, "push_events": 0, "create_events": 0, "watch_events": 0, "fork_events": 0, "pull_request_events": 0, "issues_events": 0}'
            if echo "$events_json" | jq -e . >/dev/null 2>&1; then
                activity_stats=$(echo "$events_json" | jq -r '{
                    total_events: length,
                    push_events: [.[] | select(.type == "PushEvent")] | length,
                    create_events: [.[] | select(.type == "CreateEvent")] | length,
                    watch_events: [.[] | select(.type == "WatchEvent")] | length,
                    fork_events: [.[] | select(.type == "ForkEvent")] | length,
                    pull_request_events: [.[] | select(.type == "PullRequestEvent")] | length,
                    issues_events: [.[] | select(.type == "IssuesEvent")] | length
                }' 2>/dev/null || echo '{"total_events": 0, "push_events": 0, "create_events": 0, "watch_events": 0, "fork_events": 0, "pull_request_events": 0, "issues_events": 0}')
            fi
            
            echo "$repo_json" | jq -r --argjson license "$license_info" --argjson activity "$activity_stats" '{
                license_name: $license.license_name,
                license_spdx_id: $license.license_spdx_id,
                license_key: $license.license_key,
                license_url: $license.license_url,
                stars_count: (.stargazers_count // 0),
                watchers_count: (.watchers_count // 0),
                forks_count: (.forks_count // 0),
                subscribers_count: (.subscribers_count // 0),
                network_count: (.network_count // 0),
                issues_url: (.issues_url // "N/A"),
                total_events: $activity.total_events,
                push_events: $activity.push_events,
                create_events: $activity.create_events,
                watch_events: $activity.watch_events,
                fork_events: $activity.fork_events,
                pull_request_events: $activity.pull_request_events,
                issues_events: $activity.issues_events
            }' 2>/dev/null || echo '{"license_name": "N/A", "license_spdx_id": "N/A", "license_key": "N/A", "license_url": "N/A", "stars_count": 0, "watchers_count": 0, "forks_count": 0, "subscribers_count": 0, "network_count": 0, "issues_url": "N/A", "total_events": 0, "push_events": 0, "create_events": 0, "watch_events": 0, "fork_events": 0, "pull_request_events": 0, "issues_events": 0}'
        else
            echo '{"license_name": "N/A", "license_spdx_id": "N/A", "license_key": "N/A", "license_url": "N/A", "stars_count": 0, "watchers_count": 0, "forks_count": 0, "subscribers_count": 0, "network_count": 0, "issues_url": "N/A", "total_events": 0, "push_events": 0, "create_events": 0, "watch_events": 0, "fork_events": 0, "pull_request_events": 0, "issues_events": 0}'
        fi
    else
        echo '{"license_name": "N/A", "license_spdx_id": "N/A", "license_key": "N/A", "license_url": "N/A", "stars_count": 0, "watchers_count": 0, "forks_count": 0, "subscribers_count": 0, "network_count": 0, "issues_url": "N/A", "total_events": 0, "push_events": 0, "create_events": 0, "watch_events": 0, "fork_events": 0, "pull_request_events": 0, "issues_events": 0}'
    fi
}

check_license_compliance_status() {
    local license_key="$1"
    local license_name="$2"

    if [[ -z "$license_key" || "$license_key" == "N/A" ]]; then
        echo "UNKNOWN: License not available"
        return 2
    fi
    
    local license_lower=$(echo "$license_key" | tr '[:upper:]' '[:lower:]')
    local allowed_lower=$(echo "$ALLOWED_LICENSES" | tr '[:upper:]' '[:lower:]')
    local name_lower=$(echo "$license_name" | tr '[:upper:]' '[:lower:]')
    
    if [[ ",$allowed_lower," == *",$license_lower,"* ]]; then
        echo "ALLOWED: License '$license_key' is in allowed list"
        return 0
    else
        for allowed in $(echo "$allowed_lower" | tr ',' ' '); do
            if [[ "$name_lower" == *"$allowed"* ]]; then
                echo "ALLOWED: License '$license_key' (matched by name) is in allowed list"
                return 0
            fi
        done

        echo "NOT ALLOWED: License '$license_key' is not in allowed list"
        return 1
    fi
}

get_cve_info() {
    local package_type="$1"
    local package_name="$2"
    local version="$3"
        
    local ecosystem="$package_type"
    if [ "$package_type" == "dart" ]; then
        ecosystem="Pub"
    fi

    local cve_result=$(bash cve-check.sh "$ecosystem" "$package_name" "$version" 2>/dev/null)
    if [[ $? -eq 0 && -n "$cve_result" ]]; then
        echo "$cve_result"
    else
        echo '{"package": "'$package_name'", "checked_version": "'$version'", "vulnerabilities": {}, "earliest_safe_version": null}'
    fi
}

PACKAGE_JSON=$(curl -s "$API_URL")
if ! echo "$PACKAGE_JSON" | jq . >/dev/null 2>&1; then
    echo "Failed to fetch package info or invalid JSON."
    exit 1
fi

CUTOFF_DATE=$(date -d "$MONTHS months ago" -u +%Y-%m-%dT%H:%M:%SZ)
RECENT_RELEASES=$(echo "$PACKAGE_JSON" | jq --arg cutoff "$CUTOFF_DATE" "$COUNT_QUERY")
RECENT_VERSIONS=$(echo "$PACKAGE_JSON" | jq -r --arg cutoff "$CUTOFF_DATE" "[$DISPLAY_QUERY] | join(\", \")")
RECENT_VERSIONS_OBJECT=$(echo "$PACKAGE_JSON" | jq --arg cutoff "$CUTOFF_DATE" "$VERSION_OBJECT_QUERY")


if [[ -z "$RECENT_VERSIONS" || "$RECENT_VERSIONS" == "" ]]; then
    EXTENDED_MONTHS=$((MONTHS + 18))
    CUTOFF_DATE=$(date -d "$EXTENDED_MONTHS months ago" -u +%Y-%m-%dT%H:%M:%SZ)
    EXTENDED_RECENT_RELEASES=$(echo "$PACKAGE_JSON" | jq --arg cutoff "$CUTOFF_DATE" "$COUNT_QUERY")
    EXTENDED_RECENT_VERSIONS=$(echo "$PACKAGE_JSON" | jq -r --arg cutoff "$CUTOFF_DATE" "[$DISPLAY_QUERY] | join(\", \")")
    EXTENDED_RECENT_VERSIONS_OBJECT=$(echo "$PACKAGE_JSON" | jq --arg cutoff "$CUTOFF_DATE" "$VERSION_OBJECT_QUERY")

    MOST_RECENT_VERSION=$(echo "$EXTENDED_RECENT_VERSIONS_OBJECT" | jq -r 'keys[]' | sort -V | tail -n 1)
else
    MOST_RECENT_VERSION=$(echo "$RECENT_VERSIONS_OBJECT" | jq -r 'keys[]' | sort -V | tail -n 1)
fi

if [[ -n "$MOST_RECENT_VERSION" && "$MOST_RECENT_VERSION" != "" ]]; then
    INPUT_VERSION_MAJOR=$(echo "$INPUT_VERSION" | cut -d. -f1)
    INPUT_VERSION_MINOR=$(echo "$INPUT_VERSION" | cut -d. -f2)

    RECENT_MAJOR_VERSION=$(echo "$MOST_RECENT_VERSION" | cut -d. -f1)
    RECENT_MINOR_VERSION=$(echo "$MOST_RECENT_VERSION" | cut -d. -f2)

    if [[ "$RECENT_MAJOR_VERSION" -gt "$INPUT_VERSION_MAJOR" ]] || 
    ( [[ "$RECENT_MAJOR_VERSION" -eq 0 ]] && [[ "$RECENT_MINOR_VERSION" -gt "$INPUT_VERSION_MINOR" ]] ); then 
        NEXT_MAJOR_RELEASE="$MOST_RECENT_VERSION"; 
    fi
fi

VERSION_IS_OBSOLETE=$([[ -z "$NEXT_MAJOR_RELEASE" ]] && echo false || echo true)

[[ "$JSON_ONLY" != "true" ]] && echo "=== PACKAGE INFORMATION ==="
if [ "$TYPE" == "dart" ]; then
    AUTHOR_LABEL="Author"
else
    AUTHOR_LABEL="Publisher/Provider"
fi

PACKAGE_INFO=$(echo "$PACKAGE_JSON" | jq -r "$INFO_QUERY")
PUBLISHER=$(echo "$PACKAGE_INFO" | jq -r '.publisher // ""')
PROVIDER_URL=$(echo "$PACKAGE_INFO" | jq -r '.repository // ""')
BASE_URL=$(get_github_repo_url "$PUBLISHER" "$PACKAGE" "$PROVIDER_URL")

if [[ -n "$PUBLISHER" && "$PUBLISHER" != "N/A" && "$PUBLISHER" != "" ]]; then
    GITHUB_INFO=$(get_github_info "$PUBLISHER" "$PACKAGE" "$PROVIDER_URL")
    
    PACKAGE_INFO=$(echo "$PACKAGE_INFO" | jq \
        --argjson github_info "$GITHUB_INFO" \
        '.license = (if .license != "N/A" then .license else $github_info.license_name end) |
         .license_spdx_id = $github_info.license_spdx_id | 
         .license_key = $github_info.license_key | 
         .license_url = $github_info.license_url |
         .stars_count = $github_info.stars_count |
         .watchers_count = $github_info.watchers_count |
         .forks_count = $github_info.forks_count |
         .subscribers_count = $github_info.subscribers_count |
         .network_count = $github_info.network_count |
         .total_events = $github_info.total_events |
         .push_events = $github_info.push_events |
         .create_events = $github_info.create_events |
         .watch_events = $github_info.watch_events |
         .fork_events = $github_info.fork_events |
         .pull_request_events = $github_info.pull_request_events |
         .issues_events = $github_info.issues_events |
         .issues = ($github_info.issues_url // .issues)')
fi

[[ "$JSON_ONLY" != "true" ]] && echo "$PACKAGE_INFO" | jq -r --arg label "$AUTHOR_LABEL" '
"Name: " + (.name // "N/A"),
"Description: " + (.description // "N/A"),
($label + ": ") + (.publisher // "N/A"),
"License: " + (.license // "N/A"),
"License SPDX ID: " + (.license_spdx_id // "N/A"),
"License Key: " + (.license_key // "N/A"),
"License URL: " + (.license_url // "N/A"),
"",
"=== REPOSITORY STATS ===",
"Stars: " + (.stars_count | tostring),
"Watchers: " + (.watchers_count | tostring),
"Forks: " + (.forks_count | tostring),
"Subscribers: " + (.subscribers_count | tostring),
"Network: " + (.network_count | tostring),
"",
"=== USER ACTIVITY (Recent Public Events) ===",
"Total Events: " + (.total_events | tostring),
"Push Events: " + (.push_events | tostring),
"Create Events: " + (.create_events | tostring),
"Watch Events: " + (.watch_events | tostring),
"Fork Events: " + (.fork_events | tostring),
"Pull Request Events: " + (.pull_request_events | tostring),
"Issues Events: " + (.issues_events | tostring),
"",
"=== LINKS ===",
"Homepage: " + (.homepage // "N/A"),
"Repository: " + (.repository // "N/A"),
"Documentation: " + (.documentation // "N/A"),
"Issues: " + (.issues // "N/A"),
""
'

if [[ "$JSON_ONLY" != "true" ]]; then
    echo "=== RELEASE ACTIVITY ==="
    echo "Releases in last $MONTHS months: $RECENT_RELEASES (min expected: $MIN_RELEASES)"
    echo "Recent versions:"
    echo "$PACKAGE_JSON" | jq -r --arg cutoff "$CUTOFF_DATE" "$DISPLAY_QUERY"

    echo ""
    echo "=== LICENSE CHECK ==="
    echo "Allowed licenses: $ALLOWED_LICENSES"
fi

LICENSE_KEY=$(echo "$GITHUB_INFO" | jq -r '.license_key // "N/A"')
LICENSE_NAME=$(echo "$PACKAGE_INFO" | jq -r '.license // "N/A"')

LICENSE_COMPLIANCE_TEXT=$(check_license_compliance_status "$LICENSE_KEY" "$LICENSE_NAME")
LICENSE_COMPLIANCE_CODE=$?

[[ $LICENSE_COMPLIANCE_CODE -eq 0 ]] && LICENSE_IS_COMPLIANT=true || LICENSE_IS_COMPLIANT=false
[[ "$JSON_ONLY" != "true" ]] && echo "$LICENSE_COMPLIANCE_TEXT"

if [[ "$JSON_ONLY" != "true" ]]; then
    echo ""
    echo "=== RELEASE STATUS ==="
fi

if [ "$RECENT_RELEASES" -ge "$MIN_RELEASES" ]; then
    [[ "$JSON_ONLY" != "true" ]] && echo "✅ PASS: Package has regular releases"
    RELEASE_STATUS="PASS"
else
    [[ "$JSON_ONLY" != "true" ]] && echo "❌ FAIL: Package lacks regular releases"
    RELEASE_STATUS="FAIL"
fi

[[ "$JSON_ONLY" != "true" ]] && echo ""
[[ "$JSON_ONLY" != "true" ]] && echo "=== JSON OUTPUT ==="

CURRENT_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LATEST_VERSION=$(echo "$PACKAGE_JSON" | jq -r 'if .latest then .latest.version else (."dist-tags".latest // "Unknown") end')


CVE_INFO=$(get_cve_info "$TYPE" "$PACKAGE" "$INPUT_VERSION")

CREATION_DATE="$CURRENT_DATE"
[[ -n "$ORIGINAL_CREATION_DATE" ]] && CREATION_DATE="$ORIGINAL_CREATION_DATE"

echo "$PACKAGE_INFO" | jq -r \
    --arg package_name "$PACKAGE" \
    --arg license_api_url "$BASE_URL/license" \
    --arg version "$INPUT_VERSION" \
    --arg normalized_version "$NORMALIZED_VERSION" \
    --arg current_date "$CURRENT_DATE" \
    --arg release_status "$RELEASE_STATUS" \
    --argjson license_is_compliant "$LICENSE_IS_COMPLIANT" \
    --arg license_compliance_text "$LICENSE_COMPLIANCE_TEXT" \
    --arg recent_releases "$RECENT_RELEASES" \
    --arg min_releases "$MIN_RELEASES" \
    --argjson recent_versions_object "$RECENT_VERSIONS_OBJECT" \
    --arg created_at "$CREATION_DATE" \
    --arg next_major_version "$NEXT_MAJOR_RELEASE" \
    --argjson version_is_obsolete "$VERSION_IS_OBSOLETE" \
    --arg newer_versions "$NEWER_VERSIONS" \
    --argjson cve_info "$CVE_INFO" \
    --arg months $MONTHS \
    '{
        "package": $package_name,
        "version": (if ($normalized_version // "") != "" then $normalized_version else $version end),
        "purpose": (.description // "N/A"),
        "provider": (.publisher // "N/A"),
        "license": (.license // "N/A"),
        "urls": {
           "provider": (.repository // "N/A"),
           "documentation": (.documentation // "N/A"),
           "known_issues": (.issues // "N/A" | sub("\\{/?number\\}"; ""))
        },
        "requirements": {
            "grq-1": (
                ($license_is_compliant) as $fulfilled |
                {
                    description: "Has a suitable license",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" elif $fulfilled == false then "\u274C" else "\u2753" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: {
                        license: (.license // "N/A"),
                        license_spdx_id: (.license_spdx_id // "N/A"),
                        license_key: (.license_key // "N/A"),
                        license_url: (.license_url // "N/A"),
                        compliance_status: $license_compliance_text,
                        license_api_url: $license_api_url
                    }
                }
            ),
            "grq-2": (
                (.documentation != "N/A" and (.documentation | length) > 0) as $fulfilled |
                {
                    description: "Comprehensive documentation is available",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u274C" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: (.documentation // "N/A")
                }
            ),
            "grq-3": (
                ($release_status == "PASS") as $fulfilled |
                {
                    description: "Is maintained and support is available",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u274C" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: {
                        analysis_period: ($months + " months"),
                        releases_found: ($recent_releases | tonumber),
                        min_expected: ($min_releases | tonumber),
                        recent_versions: $recent_versions_object
                    }
                }
            ),
            "grq-4": (
                ( (($cve_info.vulnerabilities_count // 0) == 0) or (($cve_info.earliest_safe_version // "") == $version) ) as $fulfilled |
                {
                    description: "Does not contain major or critical security issues.",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u274C" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: $cve_info
                }
            ),
            "grq-5": (
                ((.stars_count // 0) >= 1000 or (.forks_count // 0) >= 1000 or (.subscribers_count // 0) >= 1000 or ((.stars_count // 0) + (.forks_count // 0) + (.subscribers_count // 0) >= 2000)) as $fulfilled |
                {
                    description: "Provider is reliable, trustworthy and communicative",
                    fulfilled: (if $fulfilled then $fulfilled else "" end),
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u2753" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: {
                        stars: (.stars_count // 0),
                        forks: (.forks_count // 0),
                        watchers: (.watchers_count // 0),
                        subscribers: (.subscribers_count // 0),
                        network: (.network_count // 0),
                        total_events: (.total_events // 0),
                        push_events: (.push_events // 0),
                        create_events: (.create_events // 0),
                        watch_events: (.watch_events // 0),
                        fork_events: (.fork_events // 0),
                        pull_request_events: (.pull_request_events // 0),
                        issues_events: (.issues_events // 0)
                    }
                }
            ),
            "grq-6": (
                (if $recent_versions_object then (($recent_versions_object | keys | map(test("^\\d+\\.\\d+\\.\\d+([+-][0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")) | all) and (($recent_versions_object | keys | length) > 0)) else ($version | test("^\\d+\\.\\d+\\.\\d+([+-][0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")) end) as $fulfilled |
                {
                    description: "Conforms to Semantic Versioning",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u274C" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: {
                        total_versions_checked: (if $recent_versions_object then ($recent_versions_object | keys | length) else 1 end)
                    }
                }
            ),
            "version-check": (
                ($version_is_obsolete | not) as $fulfilled |
                {
                    description: "Is the latest Major (or Minor when Major = 0) of the SOUP",
                    fulfilled: $fulfilled,
                    fulfilled_visual: (if $fulfilled then "\u2705" else "\u274C" end),
                    reason_if_requirement_not_fulfilled: "",
                    metadata: {
                        is_obsolete: $version_is_obsolete,
                        most_recent_next_version: $next_major_version
                    }
                }
            )
        },
        "metadata": {
            "created": $created_at,
            "updated": $current_date,
            "input_version": $version,
            "approval": {
                "date": "",
                "by": "",
                "condition": ($cve_info.earliest_safe_version // "")
            }
        }
    }'
