#!/usr/bin/env bats

load "setup.bash"

setup() {
    _JS_SC_TESTING=1 \
    INPUT_SEARCH_DIRECTORY="${FIXTURES}/pnpm-ok" \
    INPUT_MINIMUM_RELEASE_AGE_MINUTES="4320" \
        source "$SCRIPT"
    set +e +u +o pipefail
    D="$BATS_TEST_TMPDIR"
}

# ── trim ─────────────────────────────────────────────────────────────────────

@test "trim: strips leading whitespace" {
    result="$(trim "  hello")"
    [ "$result" = "hello" ]
}

@test "trim: strips trailing whitespace" {
    result="$(trim "hello  ")"
    [ "$result" = "hello" ]
}

@test "trim: strips both ends" {
    result="$(trim "  hello world  ")"
    [ "$result" = "hello world" ]
}

@test "trim: leaves empty string empty" {
    result="$(trim "")"
    [ -z "$result" ]
}

# ── npmrc_get ─────────────────────────────────────────────────────────────────

@test "npmrc_get: reads a simple key=value" {
    printf 'minimum-release-age=10080\n' > "$D/.npmrc"
    result="$(npmrc_get "$D/.npmrc" "minimum-release-age")"
    [ "$result" = "10080" ]
}

@test "npmrc_get: tolerates spaces around =" {
    printf 'minimum-release-age = 10080\n' > "$D/.npmrc"
    result="$(npmrc_get "$D/.npmrc" "minimum-release-age")"
    [ "$result" = "10080" ]
}

@test "npmrc_get: returns empty for missing key" {
    printf 'block-exotic-subdeps=true\n' > "$D/.npmrc"
    result="$(npmrc_get "$D/.npmrc" "minimum-release-age")"
    [ -z "$result" ]
}

@test "npmrc_get: returns empty when file does not exist" {
    result="$(npmrc_get "$D/nonexistent.npmrc" "minimum-release-age")"
    [ -z "$result" ]
}

@test "npmrc_get: last value wins when key appears twice" {
    printf 'minimum-release-age=100\nminimum-release-age=10080\n' > "$D/.npmrc"
    result="$(npmrc_get "$D/.npmrc" "minimum-release-age")"
    [ "$result" = "10080" ]
}

@test "npmrc_get: strips surrounding double quotes from value" {
    printf 'minimum-release-age="10080"\n' > "$D/.npmrc"
    result="$(npmrc_get "$D/.npmrc" "minimum-release-age")"
    [ "$result" = "10080" ]
}

# ── yaml_get_scalar ───────────────────────────────────────────────────────────

@test "yaml_get_scalar: reads an integer value as JSON number" {
    printf 'npmMinimalAgeGate: 10080\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "npmMinimalAgeGate")"
    [ "$result" = "10080" ]
}

@test "yaml_get_scalar: reads a boolean true as JSON true" {
    printf 'enableScripts: true\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "enableScripts")"
    [ "$result" = "true" ]
}

@test "yaml_get_scalar: reads a boolean false as JSON false" {
    printf 'enableScripts: false\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "enableScripts")"
    [ "$result" = "false" ]
}

@test "yaml_get_scalar: reads a string value as JSON string" {
    printf 'nodeLinker: node-modules\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "nodeLinker")"
    [ "$result" = '"node-modules"' ]
}

@test "yaml_get_scalar: returns empty for missing key" {
    printf 'enableScripts: false\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "npmMinimalAgeGate")"
    [ -z "$result" ]
}

@test "yaml_get_scalar: returns empty when file does not exist" {
    result="$(yaml_get_scalar "$D/nonexistent.yml" "npmMinimalAgeGate")"
    [ -z "$result" ]
}

@test "yaml_get_scalar: reads a duration string value" {
    printf 'npmMinimalAgeGate: 7d\n' > "$D/.yarnrc.yml"
    result="$(yaml_get_scalar "$D/.yarnrc.yml" "npmMinimalAgeGate")"
    [ "$result" = '"7d"' ]
}

# ── pkg_json_get_only_built ───────────────────────────────────────────────────

@test "pkg_json_get_only_built: missing file → __NO_FILE__" {
    result="$(pkg_json_get_only_built "$D/nonexistent.json")"
    [ "$result" = "__NO_FILE__" ]
}

@test "pkg_json_get_only_built: no pnpm key → __NO_PNPM__" {
    printf '{"name":"foo"}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$result" = "__NO_PNPM__" ]
}

@test "pkg_json_get_only_built: pnpm key present but no onlyBuiltDependencies → __ABSENT__" {
    printf '{"pnpm":{}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$result" = "__ABSENT__" ]
}

@test "pkg_json_get_only_built: empty array → __EMPTY__" {
    printf '{"pnpm":{"onlyBuiltDependencies":[]}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$result" = "__EMPTY__" ]
}

@test "pkg_json_get_only_built: non-empty array → __LIST__ followed by names" {
    printf '{"pnpm":{"onlyBuiltDependencies":["esbuild","sharp"]}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$(echo "$result" | head -1)" = "__LIST__" ]
    [[ "$result" == *"esbuild"* ]]
    [[ "$result" == *"sharp"* ]]
}

@test "pkg_json_get_only_built: v9 allowAny:true → __ALLOW_ANY__" {
    printf '{"pnpm":{"onlyBuiltDependencies":{"allowAny":true}}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$result" = "__ALLOW_ANY__" ]
}

@test "pkg_json_get_only_built: v9 packages:[] → __EMPTY__" {
    printf '{"pnpm":{"onlyBuiltDependencies":{"packages":[]}}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$result" = "__EMPTY__" ]
}

@test "pkg_json_get_only_built: v9 packages:[esbuild] → __LIST__" {
    printf '{"pnpm":{"onlyBuiltDependencies":{"packages":["esbuild"]}}}\n' > "$D/package.json"
    result="$(pkg_json_get_only_built "$D/package.json")"
    [ "$(echo "$result" | head -1)" = "__LIST__" ]
    [[ "$result" == *"esbuild"* ]]
}

# ── pnpm_lock_exotic ──────────────────────────────────────────────────────────

@test "pnpm_lock_exotic: returns empty for registry-only lockfile" {
    cat > "$D/pnpm-lock.yaml" <<'EOF'
lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc}
EOF
    result="$(pnpm_lock_exotic "$D/pnpm-lock.yaml")"
    [ -z "$result" ]
}

@test "pnpm_lock_exotic: detects tarball resolution" {
    cat > "$D/pnpm-lock.yaml" <<'EOF'
lockfileVersion: '9.0'
packages:
  shady-fork@0.0.0:
    resolution: {tarball: 'https://github.com/attacker/repo/archive/abc.tar.gz'}
EOF
    result="$(pnpm_lock_exotic "$D/pnpm-lock.yaml")"
    [ -n "$result" ]
    [[ "$result" == *"tarball"* ]]
}

@test "pnpm_lock_exotic: detects git repo resolution" {
    cat > "$D/pnpm-lock.yaml" <<'EOF'
lockfileVersion: '9.0'
packages:
  shady-fork@0.0.0:
    resolution: {repo: 'https://github.com/attacker/repo', commit: 'abc123', type: git}
EOF
    result="$(pnpm_lock_exotic "$D/pnpm-lock.yaml")"
    [ -n "$result" ]
}

@test "pnpm_lock_exotic: returns empty for missing file" {
    result="$(pnpm_lock_exotic "$D/nonexistent.yaml")"
    [ -z "$result" ]
}

# ── yarn_lock_exotic ──────────────────────────────────────────────────────────

@test "yarn_lock_exotic: returns empty for registry-only classic lockfile" {
    cat > "$D/yarn.lock" <<'EOF'
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-abc
EOF
    result="$(yarn_lock_exotic "$D/yarn.lock")"
    [ -z "$result" ]
}

@test "yarn_lock_exotic: detects git+ resolved URL in classic lockfile" {
    cat > "$D/yarn.lock" <<'EOF'
# yarn lockfile v1

shady-fork@git+https://github.com/attacker/repo.git:
  version "0.0.0"
  resolved "git+https://github.com/attacker/repo.git#abc123"
EOF
    result="$(yarn_lock_exotic "$D/yarn.lock")"
    [ -n "$result" ]
    [[ "$result" == *"git+"* ]]
}

@test "yarn_lock_exotic: detects github: shorthand in classic lockfile" {
    cat > "$D/yarn.lock" <<'EOF'
# yarn lockfile v1

shady@github:attacker/repo#abc123:
  version "0.0.0"
  resolved "github:attacker/repo#abc123"
EOF
    result="$(yarn_lock_exotic "$D/yarn.lock")"
    [ -n "$result" ]
}

@test "yarn_lock_exotic: returns empty for registry-only berry lockfile" {
    cat > "$D/yarn.lock" <<'EOF'
__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abc
  languageName: node
  linkType: hard
EOF
    result="$(yarn_lock_exotic "$D/yarn.lock")"
    [ -z "$result" ]
}

@test "yarn_lock_exotic: detects git+ resolution in berry lockfile" {
    cat > "$D/yarn.lock" <<'EOF'
__metadata:
  version: 8

"shady-fork@git+https://github.com/attacker/repo.git":
  version: 0.0.0
  resolution: "shady-fork@git+https://github.com/attacker/repo.git#commit=abc123"
  languageName: node
  linkType: hard
EOF
    result="$(yarn_lock_exotic "$D/yarn.lock")"
    [ -n "$result" ]
    [[ "$result" == *"git+"* ]]
}

@test "yarn_lock_exotic: returns empty for missing file" {
    result="$(yarn_lock_exotic "$D/nonexistent.lock")"
    [ -z "$result" ]
}

# ── pnpm_get_release_age_exclude ──────────────────────────────────────────────

@test "pnpm_get_release_age_exclude: reads comma-separated exclude list from .npmrc" {
    printf 'minimum-release-age-exclude=lodash,express\n' > "$D/.npmrc"
    result="$(pnpm_get_release_age_exclude "$D")"
    [[ "$result" == *"lodash"* ]]
    [[ "$result" == *"express"* ]]
}

@test "pnpm_get_release_age_exclude: returns empty when key is absent" {
    printf 'minimum-release-age=10080\n' > "$D/.npmrc"
    result="$(pnpm_get_release_age_exclude "$D")"
    [ -z "$result" ]
}

@test "pnpm_get_release_age_exclude: returns empty when .npmrc does not exist" {
    result="$(pnpm_get_release_age_exclude "$D")"
    [ -z "$result" ]
}

@test "pnpm_get_release_age_exclude: reads minimumReleaseAgeExclude from pnpm-workspace.yaml" {
    cat > "$D/pnpm-workspace.yaml" <<'EOF'
minimumReleaseAgeExclude:
  - lodash
  - express
EOF
    result="$(pnpm_get_release_age_exclude "$D")"
    [[ "$result" == *"lodash"* ]]
    [[ "$result" == *"express"* ]]
}

# ── yarn_berry_get_release_age_exclude ────────────────────────────────────────

@test "yarn_berry_get_release_age_exclude: reads npmPreapprovedPackages list" {
    cat > "$D/.yarnrc.yml" <<'EOF'
npmPreapprovedPackages:
  - lodash
  - express
EOF
    result="$(yarn_berry_get_release_age_exclude "$D")"
    [[ "$result" == *"lodash"* ]]
    [[ "$result" == *"express"* ]]
}

@test "yarn_berry_get_release_age_exclude: empty list returns empty" {
    printf 'npmPreapprovedPackages: []\n' > "$D/.yarnrc.yml"
    result="$(yarn_berry_get_release_age_exclude "$D")"
    [ -z "$result" ]
}

@test "yarn_berry_get_release_age_exclude: missing key returns empty" {
    printf 'enableScripts: false\n' > "$D/.yarnrc.yml"
    result="$(yarn_berry_get_release_age_exclude "$D")"
    [ -z "$result" ]
}

@test "yarn_berry_get_release_age_exclude: returns empty when file does not exist" {
    result="$(yarn_berry_get_release_age_exclude "$D")"
    [ -z "$result" ]
}

# ── detect_pnpm_version ───────────────────────────────────────────────────────

@test "detect_pnpm_version: reads version from packageManager field" {
    printf '{"packageManager":"pnpm@10.4.0"}\n' > "$D/package.json"
    result="$(detect_pnpm_version "$D")"
    [ "$result" = "10.4.0" ]
}

@test "detect_pnpm_version: returns empty when packageManager is yarn" {
    printf '{"packageManager":"yarn@4.14.0"}\n' > "$D/package.json"
    result="$(detect_pnpm_version "$D")"
    [ -z "$result" ]
}

@test "detect_pnpm_version: reads version from .tool-versions" {
    printf '{"name":"foo"}\n' > "$D/package.json"
    printf 'pnpm 10.4.0\n' > "$D/.tool-versions"
    result="$(detect_pnpm_version "$D")"
    [ "$result" = "10.4.0" ]
}

@test "detect_pnpm_version: packageManager takes precedence over .tool-versions" {
    printf '{"packageManager":"pnpm@10.4.0"}\n' > "$D/package.json"
    printf 'pnpm 8.0.0\n' > "$D/.tool-versions"
    result="$(detect_pnpm_version "$D")"
    [ "$result" = "10.4.0" ]
}

@test "detect_pnpm_version: reads version from engines.pnpm field" {
    printf '{"engines":{"pnpm":">=10.4.0"}}\n' > "$D/package.json"
    result="$(detect_pnpm_version "$D")"
    [ "$result" = "10.4.0" ]
}

@test "detect_pnpm_version: returns empty when no version source exists" {
    printf '{"name":"foo"}\n' > "$D/package.json"
    result="$(detect_pnpm_version "$D")"
    [ -z "$result" ]
}

# ── detect_yarn_version ───────────────────────────────────────────────────────

@test "detect_yarn_version: reads version from packageManager field" {
    printf '{"packageManager":"yarn@4.14.0"}\n' > "$D/package.json"
    result="$(detect_yarn_version "$D")"
    [ "$result" = "4.14.0" ]
}

@test "detect_yarn_version: returns empty when packageManager is pnpm" {
    printf '{"packageManager":"pnpm@10.4.0"}\n' > "$D/package.json"
    result="$(detect_yarn_version "$D")"
    [ -z "$result" ]
}

@test "detect_yarn_version: returns empty when packageManager is absent" {
    printf '{"name":"foo"}\n' > "$D/package.json"
    result="$(detect_yarn_version "$D")"
    [ -z "$result" ]
}
