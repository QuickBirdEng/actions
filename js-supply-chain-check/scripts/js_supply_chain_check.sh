#!/usr/bin/env bash
set -euo pipefail

shopt -s globstar

# ── helpers ───────────────────────────────────────────────────────────────────

trim() { echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

normalize_csv() { echo "$1" | tr '\n' ',' | sed 's/,\+/,/g;s/^,//;s/,$//'; }

is_true() {
    local val; val="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    [[ "$val" == "true" || "$val" == "1" || "$val" == "yes" || "$val" == "y" ]]
}

# Split comma/newline list into a sorted, deduped, newline-separated list.
split_list() {
    echo "$1" | tr ',\n' '\n\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' | sort -u || true
}

# ── configuration ─────────────────────────────────────────────────────────────

SEARCH_DIR="${INPUT_SEARCH_DIRECTORY:-.}"
EXCLUDE_DEFAULTS=".git/**,node_modules/**,.idea/**,build/**,dist/**"
EXCLUDE_CSV="$(normalize_csv "${EXCLUDE_DEFAULTS}${INPUT_EXCLUDE:+,${INPUT_EXCLUDE}}")"
MIN_RELEASE_AGE_MINUTES="${INPUT_MINIMUM_RELEASE_AGE_MINUTES:-10080}"
ALLOW_BUILDS_RAW="${INPUT_ALLOW_BUILDS:-}"
REQUIRE_BLOCK_EXOTIC="${INPUT_REQUIRE_BLOCK_EXOTIC_SUBDEPS:-true}"
FAIL_ON_FOUND="${INPUT_FAIL_ON_FOUND:-true}"
# Opt-in escape hatch: when true, look up each lockfile entry's publish date
# against the npm registry. This is a PR-time-only band-aid (it doesn't
# protect a developer's machine that runs yarn install before opening a PR);
# the canonical fix is to migrate to pnpm 10+ where minimum-release-age is
# enforced natively at install time. Default off — yarn/npm projects with
# minimum-release-age set will hard-fail with a migration prompt unless this
# opt-in is enabled.
ENFORCE_RELEASE_AGE_VIA_REGISTRY="${INPUT_ENFORCE_RELEASE_AGE_VIA_REGISTRY:-false}"
# Minimum pnpm version where the recommended settings actually exist.
# minimumReleaseAge + blockExoticSubdeps require pnpm 10.0+; in older
# versions the settings parse but have no effect.
PNPM_MIN_VERSION="${INPUT_PNPM_MIN_VERSION:-10.0.0}"
# Minimum yarn (berry) version with native enforcement of all three policies.
# - npmMinimalAgeGate: introduced 4.10, full support 4.12+
# - approvedGitRepositories (blocks exotic git subdeps): introduced 4.14
# So 4.14+ is the first version that covers parity with pnpm 10.
YARN_MIN_VERSION="${INPUT_YARN_MIN_VERSION:-4.14.0}"

ALLOW_BUILDS_LIST="$(split_list "$ALLOW_BUILDS_RAW")"

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "ERROR: search-directory does not exist: $SEARCH_DIR" >&2
    exit 1
fi

# Optional dependency probes — used to pick parser strategy.
PYTHON_BIN="$(command -v python3 || command -v python || true)"
HAS_PYYAML=false
if [[ -n "$PYTHON_BIN" ]]; then
    if "$PYTHON_BIN" -c 'import yaml' 2>/dev/null; then
        HAS_PYYAML=true
    fi
fi

# ── exclude-glob handling (copied from detect-invisible-unicode) ─────────────

EXCLUDE_GLOBS=()

IFS=',' read -ra _globs <<< "$EXCLUDE_CSV"
for _glob in "${_globs[@]}"; do
    _glob="$(trim "$_glob")"
    [[ -z "$_glob" ]] && continue
    EXCLUDE_GLOBS+=("$_glob")
done

should_exclude() {
    local rel_path="$1" basename pattern dir
    basename="$(basename "$rel_path")"
    for pattern in "${EXCLUDE_GLOBS[@]}"; do
        if [[ "$pattern" == */** ]]; then
            dir="${pattern%/**}"
            [[ "$rel_path" == "$dir" || "$rel_path" == "$dir/"* ]] && return 0
        elif [[ "$pattern" != */* ]]; then
            # shellcheck disable=SC2254
            [[ "$basename" == $pattern ]] && return 0
        else
            # shellcheck disable=SC2254
            [[ "$rel_path" == $pattern ]] && return 0
        fi
    done
    return 1
}

# ── explanatory text (centralised so messages stay consistent) ───────────────

GAJUS_URL="https://gajus.com/blog/3-pnpm-settings-to-protect-yourself-from-supply-chain-attacks"
# QB-owned documentation explaining the policy these checks enforce. Settings
# and inputs are defined in the workflow and the underlying action.
QB_DOCS_URL="https://github.com/QuickBirdEng/workflows/blob/main/docs/qb-security/explanation.md"
QB_WORKFLOW_URL="https://github.com/QuickBirdEng/workflows/blob/main/.github/workflows/qb-security.yml"
QB_ACTION_URL="https://github.com/QuickBirdEng/actions/tree/main/js-supply-chain-check"

WHY_MIN_RELEASE_AGE=$'WHY THIS MATTERS:\n  When an attacker compromises a maintainer account (the most common npm supply-chain\n  attack vector — e.g. eslint-config-prettier, ua-parser-js, event-stream), the\n  malicious release is publicly installable within seconds. Most compromised\n  versions are detected and yanked within 24-72 hours.\n  Quarantining new package versions for a week neutralises that window: by the\n  time a tainted version reaches your CI, it has either been pulled from the\n  registry or flagged by security researchers.'

WHY_BLOCK_EXOTIC=$'WHY THIS MATTERS:\n  An "exotic" dependency is anything resolved from outside the npm registry —\n  a git URL, a tarball URL, a github: shortcut, a local file path. Any subdep\n  in your tree using one of these specifiers bypasses every registry-side check\n  (provenance, deprecation, yank, scoring). It is the cleanest way for an\n  attacker who controls a transitive dep to ship arbitrary code into your\n  build, because nothing audits what is on the other side of a git ref.\n  Block them at the package-manager layer (pnpm) AND/OR reject them in\n  lockfile review.'

WHY_ALLOW_BUILDS=$'WHY THIS MATTERS:\n  npm/pnpm/yarn run lifecycle scripts (preinstall, install, postinstall) of\n  dependencies by default. A compromised package can execute arbitrary code on\n  every developer machine and every CI runner that does `npm install` — before\n  any of your code runs, before any test gate. The 2024 ua-parser-js, 2018\n  event-stream, and 2025 nx attacks all relied on this.\n  Disable install scripts by default; explicitly whitelist the small set of\n  packages (e.g. esbuild, sharp, node-sass) that legitimately need to build\n  native binaries.'

FIX_MIN_RELEASE_AGE_PNPM=$'HOW TO FIX (pnpm):\n  Add to .npmrc at the project root:\n    minimum-release-age=10080\n    minimum-release-age-exclude=\n  OR add to pnpm-workspace.yaml:\n    minimumReleaseAge: 10080\n  See: https://pnpm.io/settings#minimumreleaseage'

FIX_MIN_RELEASE_AGE_OTHER=$'HOW TO FIX — migrate to a package manager that enforces this natively:\n\n  OPTION A — yarn 4.14+ (least disruptive for yarn projects):\n    Yarn 4.10 introduced `npmMinimalAgeGate` (full support 4.12+);\n    Yarn 4.14 added `approvedGitRepositories` (the block-exotic-subdeps\n    equivalent). Both run at install time.\n\n      corepack enable\n      yarn set version 4.14.0\n\n    Then add to .yarnrc.yml:\n      npmMinimalAgeGate: 10080         # 7 days, minutes\n      approvedGitRepositories: []      # empty = block all git deps\n      enableScripts: false             # disable install scripts\n\n  OPTION B — pnpm 10+ (full pnpm parity):\n    pnpm 10 enforces all three settings natively.\n\n      npx @pnpm/exe@latest import      # imports yarn.lock → pnpm-lock.yaml\n\n    Set in package.json:\n      "packageManager": "pnpm@10.x.y"\n      "pnpm": { "onlyBuiltDependencies": [] }\n\n    Add .npmrc:\n      minimum-release-age=10080\n      block-exotic-subdeps=true\n\n    Update CI to `pnpm install --frozen-lockfile`.'

FIX_BLOCK_EXOTIC_PNPM=$'HOW TO FIX (pnpm):\n  Add to .npmrc:\n    block-exotic-subdeps=true\n  OR add to pnpm-workspace.yaml:\n    blockExoticSubdeps: true\n  See: https://pnpm.io/settings#blockexoticsubdeps'

FIX_BLOCK_EXOTIC_LOCKFILE=$'HOW TO FIX (any manager — exotic dep found in lockfile):\n  Identify the offending package above. Replace the git/tarball/file specifier\n  with a registry version, or remove the dep entirely. If the dep MUST come\n  from a non-registry source, vendor it into the repo or publish it to your\n  own registry — never resolve at install time from an unaudited URL.'

FIX_ALLOW_BUILDS_PNPM=$'HOW TO FIX (pnpm):\n  Add to package.json:\n    "pnpm": {\n      "onlyBuiltDependencies": []\n    }\n  Whitelist specific packages by adding their names to the array, e.g.\n  ["esbuild", "sharp"]. To approve interactively, run: pnpm approve-builds.\n  See: https://pnpm.io/settings#onlybuiltdependencies'

FIX_ALLOW_BUILDS_NPM=$'HOW TO FIX (npm):\n  Add to .npmrc at the project root:\n    ignore-scripts=true\n  This disables lifecycle scripts for ALL dependencies on `npm install`.\n  If a specific package needs to build native code (e.g. node-sass), run\n  `npm rebuild <package>` explicitly after install.'

FIX_ALLOW_BUILDS_YARN_CLASSIC=$'HOW TO FIX (yarn 1.x classic):\n  Add to .yarnrc at the project root:\n    ignore-scripts true\n  Or run `yarn install --ignore-scripts` in CI.'

FIX_ALLOW_BUILDS_YARN_BERRY=$'HOW TO FIX (yarn berry / 2+):\n  Add to .yarnrc.yml:\n    enableScripts: false\n  See: https://yarnpkg.com/configuration/yarnrc#enableScripts'

FIX_MIN_RELEASE_AGE_YARN_BERRY=$'HOW TO FIX (yarn 4.10+, full support 4.12+):\n  Add to .yarnrc.yml:\n    npmMinimalAgeGate: 10080      # 7 days, in minutes\n    npmMinimumReleaseAgeExclude:  # optional whitelist for exemptions\n      []\n  See: https://yarnpkg.com/configuration/yarnrc#npmMinimalAgeGate'

FIX_BLOCK_EXOTIC_YARN_BERRY=$'HOW TO FIX (yarn 4.14+):\n  Add to .yarnrc.yml:\n    approvedGitRepositories: []\n  An empty list blocks ALL git/tarball deps. Whitelist specific hosts:\n    approvedGitRepositories:\n      - https://github.com/yourorg/*\n  See: https://yarnpkg.com/configuration/yarnrc#approvedGitRepositories'

# ── finding tracker ──────────────────────────────────────────────────────────

ERROR_COUNT=0
WARNING_COUNT=0
PROJECT_COUNT=0

# Per-project counters keyed by "<project>|<manager>".
declare -A PROJECT_ERRORS
declare -A PROJECT_WARNINGS

# Concrete edits required to clear the check, keyed by target file path.
# Value is a newline-separated list of "edits" to apply to that file.
declare -A FIXES_BY_FILE=()
# Ordering preserved separately so the footer is stable across runs.
declare -a FIX_FILE_ORDER=()

# add_fix FILE EDIT_DESCRIPTION
add_fix() {
    local file="$1" edit="$2"
    if [[ -v FIXES_BY_FILE["$file"] ]]; then
        if [[ "${FIXES_BY_FILE[$file]}" != *"$edit"* ]]; then
            FIXES_BY_FILE["$file"]+=$'\n'"$edit"
        fi
    else
        FIXES_BY_FILE["$file"]="$edit"
        FIX_FILE_ORDER+=("$file")
    fi
}

# report_finding LEVEL PROJECT MANAGER FILE LINE TITLE BODY [FIX_TARGET] [FIX_EDIT]
#   LEVEL    : error | warning | info
#   PROJECT  : project dir (relative to SEARCH_DIR)
#   MANAGER  : pnpm | yarn-classic | yarn-berry | npm
#   FILE     : file path for annotation (relative to repo root)
#   LINE     : line number, or empty for "1"
#   TITLE    : short one-line title shown inline in PR annotation
#   BODY     : multi-line block printed inside the details group
#   FIX_TARGET (optional) : file the fix applies to (aggregated in ACTION REQUIRED footer)
#   FIX_EDIT   (optional) : short single-line description of the edit
report_finding() {
    local level="$1" project="$2" manager="$3" file="$4" line="$5" title="$6" body="$7"
    local fix_target="${8:-}" fix_edit="${9:-}"
    local annotation_kind key
    line="${line:-1}"
    key="${project}|${manager}"

    case "$level" in
        error)   annotation_kind="error";   (( ERROR_COUNT++ )) || true;   PROJECT_ERRORS["$key"]=$(( ${PROJECT_ERRORS["$key"]:-0} + 1 )) ;;
        warning) annotation_kind="warning"; (( WARNING_COUNT++ )) || true; PROJECT_WARNINGS["$key"]=$(( ${PROJECT_WARNINGS["$key"]:-0} + 1 )) ;;
        info|*)  annotation_kind="notice" ;;
    esac

    # Inline GitHub annotation. Project path is in the message so the log line
    # is self-identifying without expanding the details group.
    echo "::${annotation_kind} file=${file},line=${line},title=js-supply-chain (${manager})::${project}: ${title}"

    # Foldable details group. NO [WARNING]/[ERROR] prefix — GitHub auto-colours
    # such prefixes and would render a duplicate "Warning:" line.
    echo "::group::  ↳ details for ${project}: ${title}"
    echo "File:    ${file}:${line}"
    echo ""
    echo "${body}"
    echo ""
    echo "Reference: ${GAJUS_URL}"
    echo "::endgroup::"

    if [[ -n "$fix_target" && -n "$fix_edit" ]]; then
        add_fix "$fix_target" "$fix_edit"
    fi
}

# ── parser helpers (best-effort, no jq dependency) ───────────────────────────

# Read a key from .npmrc-style key=value file. Echoes value or empty string.
npmrc_get() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null \
        | tail -1 | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//" \
        | sed 's/^"//;s/"$//' || true
}

# Line number of a key in an .npmrc-style file, or empty.
npmrc_line() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -nE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null \
        | tail -1 | cut -d: -f1 || true
}

# Read a top-level scalar key from a YAML file (handles both PyYAML and grep fallback).
# Echoes the value as a JSON-encoded string ("..." or true/false/123) so the caller
# can distinguish "missing" (empty output) from "set to false" ("false").
yaml_get_scalar() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    if "$HAS_PYYAML" 2>/dev/null || [[ "$HAS_PYYAML" == "true" ]]; then
        "$PYTHON_BIN" - "$file" "$key" <<'PY' 2>/dev/null || true
import json, sys, yaml
try:
    with open(sys.argv[1]) as fh:
        data = yaml.safe_load(fh) or {}
except Exception:
    sys.exit(0)
key = sys.argv[2]
if isinstance(data, dict) and key in data:
    print(json.dumps(data[key]))
PY
    else
        # Fallback: grep for `key: value` at top level (no indentation).
        local raw
        raw="$(grep -E "^${key}:" "$file" 2>/dev/null | head -1 | sed -E "s/^${key}:[[:space:]]*//;s/[[:space:]]+#.*$//;s/[[:space:]]*$//" || true)"
        [[ -z "$raw" ]] && return 0
        # Strip surrounding quotes.
        raw="${raw#\"}"; raw="${raw%\"}"
        raw="${raw#\'}"; raw="${raw%\'}"
        # JSON-encode.
        case "$raw" in
            true|false) echo "$raw" ;;
            ''|*[!0-9]*) printf '%s\n' "\"$raw\"" ;;
            *) echo "$raw" ;;
        esac
    fi
}

# Line number of a top-level key in a YAML file.
yaml_line() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -nE "^${key}:" "$file" 2>/dev/null | head -1 | cut -d: -f1 || true
}

# Extract pnpm.onlyBuiltDependencies from package.json.
# Always emits a status sentinel on the first line, then optional package names:
#   __NO_FILE__       package.json doesn't exist or can't be parsed
#   __NO_PNPM__       package.json has no top-level "pnpm" block
#   __ABSENT__        pnpm block exists but no onlyBuiltDependencies key
#   __EMPTY__         onlyBuiltDependencies is [] (compliant)
#   __ALLOW_ANY__     v9 form { allowAny: true } — equivalent to disabling the protection
#   __LIST__          followed by package names, one per line
pkg_json_get_only_built() {
    local file="$1"
    if [[ ! -f "$file" || -z "$PYTHON_BIN" ]]; then
        echo "__NO_FILE__"
        return 0
    fi
    "$PYTHON_BIN" - "$file" <<'PY' 2>/dev/null || echo "__NO_FILE__"
import json, sys
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    print("__NO_FILE__")
    sys.exit(0)
pnpm = data.get("pnpm") if isinstance(data, dict) else None
if not isinstance(pnpm, dict):
    print("__NO_PNPM__")
    sys.exit(0)
val = pnpm.get("onlyBuiltDependencies", "__SENTINEL_ABSENT__")
if val == "__SENTINEL_ABSENT__":
    print("__ABSENT__")
elif isinstance(val, list):
    if not val:
        print("__EMPTY__")
    else:
        print("__LIST__")
        for item in val:
            print(item)
elif isinstance(val, dict):
    if val.get("allowAny") is True:
        print("__ALLOW_ANY__")
    else:
        pkgs = val.get("packages") or []
        if isinstance(pkgs, list):
            if not pkgs:
                print("__EMPTY__")
            else:
                print("__LIST__")
                for item in pkgs:
                    print(item)
        else:
            print("__ABSENT__")
else:
    print("__ABSENT__")
PY
}

# Find exotic resolutions in pnpm-lock.yaml. Echoes "<pkg>\t<spec>" lines.
pnpm_lock_exotic() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    # pnpm-lock.yaml stores resolutions like:
    #   resolution: {tarball: 'https://...'}
    #   resolution: {repo: '...', commit: '...', type: git}
    grep -nE "resolution: \{(tarball|repo|directory):" "$file" 2>/dev/null \
        | head -50 || true
}

# Find exotic resolutions in yarn.lock (classic + berry). Echoes "<line>:<spec>".
# "Exotic" = anything resolved outside the npm registry convention. Registry
# tarballs follow `https://<host>/<pkg>/-/<pkg>-<ver>.tgz` and are NOT exotic.
yarn_lock_exotic() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    grep -nE '^[[:space:]]*resolved[[:space:]]+"(git\+|git://|ssh://|github:|file:|link:|portal:|npm:)' "$file" 2>/dev/null \
        | head -50 || true
}

# Find exotic resolutions in package-lock.json. Streams a Python parser.
npm_lock_exotic() {
    local file="$1"
    [[ -f "$file" && -n "$PYTHON_BIN" ]] || return 0
    "$PYTHON_BIN" - "$file" <<'PY' 2>/dev/null || true
import json, sys, re
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)
# Unambiguous exotic specifiers — these never appear in registry-resolved deps.
exotic_prefix_re = re.compile(r'^(git\+|git://|ssh://|github:|file:|link:|portal:)')
# Tarball URL that is NOT in the standard registry shape `<host>/<pkg>/-/<pkg>-<ver>.tgz`.
registry_tarball_re = re.compile(r'^https?://[^/]+/(@[^/]+/)?[^/]+/-/[^/]+-[^/]+\.tgz')
raw_tarball_re = re.compile(r'^https?://.*\.(tgz|tar\.gz)(\?|$)')
def is_exotic(spec):
    if not spec:
        return False
    if exotic_prefix_re.search(spec):
        return True
    if raw_tarball_re.search(spec) and not registry_tarball_re.search(spec):
        return True
    return False
def walk_v1(deps, prefix=""):
    if not isinstance(deps, dict):
        return
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        ver = meta.get("version", "")
        resolved = meta.get("resolved", "")
        if is_exotic(resolved) or is_exotic(ver):
            print(f"{prefix}{name}\t{resolved or ver}")
        walk_v1(meta.get("dependencies"), prefix + name + "/")
def walk_v2(packages):
    if not isinstance(packages, dict):
        return
    for path, meta in packages.items():
        if not isinstance(meta, dict) or not path:
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        resolved = meta.get("resolved", "")
        ver = meta.get("version", "")
        if is_exotic(resolved):
            print(f"{name}\t{resolved}")
        elif is_exotic(ver):
            print(f"{name}\t{ver}")
lock_version = data.get("lockfileVersion", 1)
if lock_version >= 2 and "packages" in data:
    walk_v2(data.get("packages"))
else:
    walk_v1(data.get("dependencies"))
PY
}

# Find packages in a lockfile with install scripts (best-effort).
# package-lock.json v2/v3 stores `hasInstallScript: true` on entries that have one.
npm_lock_install_scripts() {
    local file="$1"
    [[ -f "$file" && -n "$PYTHON_BIN" ]] || return 0
    "$PYTHON_BIN" - "$file" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)
packages = data.get("packages") or {}
for path, meta in packages.items():
    if not isinstance(meta, dict) or not path:
        continue
    if meta.get("hasInstallScript"):
        name = meta.get("name") or path.split("node_modules/")[-1]
        print(name)
PY
}

# ── version helpers ──────────────────────────────────────────────────────────

# Compare two semver-ish strings. Echoes -1 / 0 / 1 like cmp.
# Treats missing segments as 0; ignores pre-release tags.
version_cmp() {
    local a="$1" b="$2"
    a="${a#v}"; b="${b#v}"
    a="${a%%-*}"; b="${b%%-*}"
    local IFS=.
    local -a aa=($a) bb=($b)
    local i
    for ((i=0; i<3; i++)); do
        local av="${aa[$i]:-0}" bv="${bb[$i]:-0}"
        if (( av < bv )); then echo -1; return; fi
        if (( av > bv )); then echo 1; return; fi
    done
    echo 0
}

# Detect the pnpm version a project intends to use. Order of precedence:
#   1. packageManager field in package.json (e.g. "pnpm@10.4.0")
#   2. .tool-versions (asdf)  e.g. "pnpm 10.4.0"
#   3. .nvmrc / engines.pnpm in package.json
# Echoes the version string, or empty if none found.
detect_pnpm_version() {
    local project_dir="$1"
    local pkg_json="$project_dir/package.json"
    if [[ -f "$pkg_json" && -n "$PYTHON_BIN" ]]; then
        local v
        v="$("$PYTHON_BIN" - "$pkg_json" <<'PY' 2>/dev/null || true
import json, sys, re
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)
if not isinstance(data, dict):
    sys.exit(0)
pm = data.get("packageManager", "")
m = re.match(r'^pnpm@([0-9][^+\s]*)', pm or "")
if m:
    print(m.group(1)); sys.exit(0)
engines = data.get("engines") or {}
if isinstance(engines, dict):
    e = engines.get("pnpm", "")
    m = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', e or "")
    if m: print(m.group(1)); sys.exit(0)
PY
)"
        [[ -n "$v" ]] && { echo "$v"; return; }
    fi
    local tv="$project_dir/.tool-versions"
    if [[ -f "$tv" ]]; then
        local v
        v="$(grep -E '^pnpm[[:space:]]+' "$tv" 2>/dev/null | head -1 | awk '{print $2}' || true)"
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    return 0
}

# Detect yarn version (for berry vs. classic, plus version-specific warnings).
detect_yarn_version() {
    local project_dir="$1"
    local pkg_json="$project_dir/package.json"
    if [[ -f "$pkg_json" && -n "$PYTHON_BIN" ]]; then
        local v
        v="$("$PYTHON_BIN" - "$pkg_json" <<'PY' 2>/dev/null || true
import json, sys, re
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)
if not isinstance(data, dict):
    sys.exit(0)
pm = data.get("packageManager", "")
m = re.match(r'^yarn@([0-9][^+\s]*)', pm or "")
if m:
    print(m.group(1)); sys.exit(0)
PY
)"
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    return 0
}

# ── registry-scan enforcement (yarn/npm/pnpm — actually checks publish dates) ─

# Stream lockfile entries as "<name>\t<version>" lines.
# Works for pnpm-lock.yaml, yarn.lock, and package-lock.json.
lockfile_to_pkgversions() {
    local file="$1"
    [[ -f "$file" && -n "$PYTHON_BIN" ]] || return 0
    "$PYTHON_BIN" - "$file" <<'PY' 2>/dev/null || true
import json, re, sys
path = sys.argv[1]
seen = set()
def emit(name, version):
    if not name or not version or '/' in version or version.startswith(('git', 'http', 'file:', 'link:', 'portal:')):
        return
    key = (name, version)
    if key in seen: return
    seen.add(key)
    print(f"{name}\t{version}")

if path.endswith("package-lock.json"):
    try:
        with open(path) as fh: data = json.load(fh)
    except Exception:
        sys.exit(0)
    pkgs = data.get("packages") or {}
    if pkgs:
        for p, meta in pkgs.items():
            if not p or not isinstance(meta, dict): continue
            name = meta.get("name") or p.split("node_modules/")[-1]
            emit(name, meta.get("version", ""))
    else:
        def walk(deps):
            if not isinstance(deps, dict): return
            for n, m in deps.items():
                if isinstance(m, dict):
                    emit(n, m.get("version", ""))
                    walk(m.get("dependencies"))
        walk(data.get("dependencies"))

elif path.endswith("yarn.lock"):
    # Classic format: each block starts with "<name>@<range>:" and contains a `version "x.y.z"` line.
    name_re = re.compile(r'^([^@\s"][^@]*)@')
    ver_re = re.compile(r'^\s*version\s+"([^"]+)"')
    current_name = None
    with open(path) as fh:
        for line in fh:
            if line.startswith('#') or not line.strip():
                current_name = None
                continue
            if not line.startswith(' '):
                head = line.split(',')[0].strip().rstrip(':')
                if head.startswith('"'): head = head[1:-1] if head.endswith('"') else head[1:]
                m = name_re.match(head)
                if m: current_name = m.group(1)
                else: current_name = None
            else:
                m = ver_re.match(line)
                if m and current_name:
                    emit(current_name, m.group(1))
                    current_name = None

elif path.endswith("pnpm-lock.yaml"):
    # pnpm v9+: entries look like "  /<name>@<ver>:" or "  <name>@<ver>:" under "packages:" section
    entry_re = re.compile(r"^\s+/?(@?[^@/:\s]+(?:/[^@/:\s]+)?)@([^():\s]+)[:(]")
    with open(path) as fh:
        for line in fh:
            m = entry_re.match(line)
            if m:
                emit(m.group(1), m.group(2))
PY
}

# Look up publish dates for each "<name>\t<version>" line on stdin against the
# npm registry, in parallel. Echoes "<too-recent-name>\t<version>\t<age_min>" for
# any package version younger than MIN_RELEASE_AGE_MINUTES.
fetch_too_recent() {
    local min_minutes="$1"
    [[ -z "$PYTHON_BIN" ]] && return 0
    "$PYTHON_BIN" - "$min_minutes" <<'PY' 2>/dev/null || true
import sys, json, time
from concurrent.futures import ThreadPoolExecutor
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:
    sys.exit(0)

min_minutes = int(sys.argv[1])
threshold = time.time() - (min_minutes * 60)

def lookup(pair):
    name, version = pair
    url = f"https://registry.npmjs.org/{name}"
    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "qb-supply-chain-check"})
        with urlopen(req, timeout=10) as resp:
            data = json.load(resp)
    except (HTTPError, URLError, TimeoutError, Exception):
        return None
    times = data.get("time", {}) or {}
    t = times.get(version)
    if not t:
        return None
    # ISO 8601 → epoch
    try:
        # Python 3.7+: fromisoformat doesn't handle "Z" suffix
        import datetime
        published = datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None
    if published > threshold:
        age_min = int((time.time() - published) // 60)
        return (name, version, age_min)
    return None

pairs = []
for raw in sys.stdin:
    raw = raw.rstrip("\n")
    if "\t" not in raw: continue
    name, version = raw.split("\t", 1)
    pairs.append((name, version))

if not pairs:
    sys.exit(0)

with ThreadPoolExecutor(max_workers=12) as pool:
    for result in pool.map(lookup, pairs):
        if result:
            print(f"{result[0]}\t{result[1]}\t{result[2]}")
PY
}

# Run the registry scan on a single lockfile and emit findings.
registry_scan_lockfile() {
    local project_label="$1" manager="$2" lockfile="$3" lockfile_rel="$4"
    [[ -f "$lockfile" ]] || return 0
    [[ -z "$PYTHON_BIN" ]] && return 0
    local hits
    hits="$(lockfile_to_pkgversions "$lockfile" | fetch_too_recent "$MIN_RELEASE_AGE_MINUTES")"
    [[ -z "$hits" ]] && return 0
    local count
    count="$(echo "$hits" | wc -l | tr -d ' ')"
    local sample
    sample="$(echo "$hits" | head -10 | awk -F'\t' '{printf "    - %s@%s  (published %d min ago)\n", $1, $2, $3}')"
    report_finding error "$project_label" "$manager" \
        "$lockfile_rel" "1" \
        "${count} dependency version(s) younger than minimum-release-age (${MIN_RELEASE_AGE_MINUTES} min)" \
        "FOUND: A registry-scan of ${lockfile_rel} found ${count} package version(s) that were published less than ${MIN_RELEASE_AGE_MINUTES} minutes ago. Examples:
${sample}

${WHY_MIN_RELEASE_AGE}

HOW TO FIX:
  Either (a) pin these deps to older registry versions that are at least
  ${MIN_RELEASE_AGE_MINUTES} min old, or (b) wait until they age past the
  threshold and re-run the check, or (c) add an exemption by raising
  js-minimum-release-age-minutes for this repo." \
        "$lockfile_rel" \
        "pin ${count} dependency version(s) to older releases (see details)"
}

# ── manager detection ────────────────────────────────────────────────────────

detect_yarn_flavour() {
    local project_dir="$1"
    if [[ -f "$project_dir/.yarnrc.yml" ]]; then
        echo "yarn-berry"; return
    fi
    if [[ -f "$project_dir/package.json" && -n "$PYTHON_BIN" ]]; then
        local pm
        pm="$("$PYTHON_BIN" - "$project_dir/package.json" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)
pm = data.get("packageManager", "") if isinstance(data, dict) else ""
print(pm)
PY
)"
        case "$pm" in
            yarn@1.*|yarn@1) echo "yarn-classic"; return ;;
            yarn@*) echo "yarn-berry"; return ;;
        esac
    fi
    # Default: yarn.lock without .yarnrc.yml = classic
    echo "yarn-classic"
}

# ── per-project checks ───────────────────────────────────────────────────────

# pnpm: project_dir, project_label
check_pnpm_project() {
    local project_dir="$1" project_label="$2"
    local npmrc="$project_dir/.npmrc"
    local workspace_yaml="$project_dir/pnpm-workspace.yaml"
    local pkg_json="$project_dir/package.json"
    local lockfile="$project_dir/pnpm-lock.yaml"

    # 0. Version check — the recommended settings only take effect on pnpm ≥ 10.
    local pnpm_version cmp_result
    pnpm_version="$(detect_pnpm_version "$project_dir")"
    if [[ -n "$pnpm_version" ]]; then
        cmp_result="$(version_cmp "$pnpm_version" "$PNPM_MIN_VERSION")"
        if [[ "$cmp_result" == "-1" ]]; then
            report_finding error "$project_label" "pnpm" \
                "${project_label}/package.json" "1" \
                "pnpm ${pnpm_version} is too old — settings won't be enforced (need ≥ ${PNPM_MIN_VERSION})" \
                "FOUND: ${project_label} pins pnpm@${pnpm_version} via package.json/packageManager (or .tool-versions). The recommended supply-chain settings — minimumReleaseAge, blockExoticSubdeps — were introduced in pnpm ${PNPM_MIN_VERSION}. Older pnpm versions silently ignore these keys, so even if .npmrc / pnpm-workspace.yaml looks correct the protection is NOT active at install time.

WHY THIS MATTERS:
  A misconfigured setting that is silently ignored is worse than a missing
  one: PRs look green, audits look green, but the runtime install behaviour
  hasn't changed. A version pin that contradicts the security policy makes
  the whole policy a no-op.

HOW TO FIX:
  Bump pnpm in package.json:
      \"packageManager\": \"pnpm@${PNPM_MIN_VERSION}\"
  And in any .tool-versions / CI workflow that pins pnpm.
  Then re-run pnpm install to refresh the lockfile under the new version." \
                "${project_label}/package.json" \
                "bump packageManager to pnpm@${PNPM_MIN_VERSION} or newer"
        fi
    fi

    # 1. minimumReleaseAge
    if [[ "$MIN_RELEASE_AGE_MINUTES" != "0" ]]; then
        local age_npmrc age_yaml age_val=""
        age_npmrc="$(npmrc_get "$npmrc" "minimum-release-age")"
        age_yaml="$(yaml_get_scalar "$workspace_yaml" "minimumReleaseAge")"
        # yaml_get_scalar returns JSON; strip for numeric.
        age_yaml="${age_yaml%\"}"; age_yaml="${age_yaml#\"}"

        if [[ -n "$age_npmrc" ]]; then
            age_val="$age_npmrc"
        elif [[ -n "$age_yaml" ]]; then
            age_val="$age_yaml"
        fi

        if [[ -z "$age_val" ]]; then
            report_finding error "$project_label" "pnpm" \
                "${project_label}/.npmrc" "1" \
                "Missing minimumReleaseAge (need ≥ ${MIN_RELEASE_AGE_MINUTES} min = $((MIN_RELEASE_AGE_MINUTES/1440)) days)" \
                "FOUND: Neither .npmrc nor pnpm-workspace.yaml sets minimumReleaseAge in ${project_label}.

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_PNPM}" \
                "${project_label}/.npmrc" \
                "add line: minimum-release-age=${MIN_RELEASE_AGE_MINUTES}"
        elif [[ "$age_val" =~ ^[0-9]+$ ]] && (( age_val < MIN_RELEASE_AGE_MINUTES )); then
            local line file
            if [[ -n "$age_npmrc" ]]; then
                line="$(npmrc_line "$npmrc" "minimum-release-age")"; file="${project_label}/.npmrc"
            else
                line="$(yaml_line "$workspace_yaml" "minimumReleaseAge")"; file="${project_label}/pnpm-workspace.yaml"
            fi
            report_finding error "$project_label" "pnpm" \
                "$file" "${line:-1}" \
                "minimumReleaseAge=${age_val} is below required ${MIN_RELEASE_AGE_MINUTES} min" \
                "FOUND: ${file} sets minimumReleaseAge to ${age_val} minutes. Required minimum is ${MIN_RELEASE_AGE_MINUTES} minutes ($((MIN_RELEASE_AGE_MINUTES/1440)) days).

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_PNPM}" \
                "$file" \
                "raise minimumReleaseAge to at least ${MIN_RELEASE_AGE_MINUTES}"
        fi
    fi

    # 2. blockExoticSubdeps
    if is_true "$REQUIRE_BLOCK_EXOTIC"; then
        local block_npmrc block_yaml block_val=""
        block_npmrc="$(npmrc_get "$npmrc" "block-exotic-subdeps")"
        block_yaml="$(yaml_get_scalar "$workspace_yaml" "blockExoticSubdeps")"

        if [[ -n "$block_npmrc" ]]; then
            block_val="$block_npmrc"
        elif [[ "$block_yaml" == "true" || "$block_yaml" == "false" ]]; then
            block_val="$block_yaml"
        fi

        if [[ -z "$block_val" ]]; then
            report_finding warning "$project_label" "pnpm" \
                "${project_label}/.npmrc" "1" \
                "blockExoticSubdeps not set" \
                "FOUND: Neither .npmrc nor pnpm-workspace.yaml in ${project_label} enables blockExoticSubdeps. (Warning only — finding becomes an error if a non-registry resolution is detected in pnpm-lock.yaml below.)

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_PNPM}" \
                "${project_label}/.npmrc" \
                "add line: block-exotic-subdeps=true"
        elif ! is_true "$block_val"; then
            local line file
            if [[ -n "$block_npmrc" ]]; then
                line="$(npmrc_line "$npmrc" "block-exotic-subdeps")"; file="${project_label}/.npmrc"
            else
                line="$(yaml_line "$workspace_yaml" "blockExoticSubdeps")"; file="${project_label}/pnpm-workspace.yaml"
            fi
            report_finding warning "$project_label" "pnpm" \
                "$file" "${line:-1}" \
                "blockExoticSubdeps explicitly disabled" \
                "FOUND: ${file} sets blockExoticSubdeps to false. This explicit opt-out is a warning, not an error — but every lockfile entry will still be scanned for non-registry resolutions below.

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_PNPM}" \
                "$file" \
                "change blockExoticSubdeps / block-exotic-subdeps to true"
        fi

        # Lockfile scan
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local lock_line lock_spec
            lock_line="${match%%:*}"
            lock_spec="${match#*:}"
            report_finding error "$project_label" "pnpm" \
                "${project_label}/pnpm-lock.yaml" "$lock_line" \
                "Exotic resolution in pnpm-lock.yaml" \
                "FOUND: pnpm-lock.yaml line ${lock_line} contains a non-registry resolution:
    ${lock_spec}

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_LOCKFILE}" \
                "${project_label}/pnpm-lock.yaml" \
                "remove or replace exotic dep at line ${lock_line}: ${lock_spec}"
        done < <(pnpm_lock_exotic "$lockfile")
    fi

    # 3. allowBuilds (pnpm.onlyBuiltDependencies)
    local only_built status
    only_built="$(pkg_json_get_only_built "$pkg_json")"
    status="$(echo "$only_built" | head -1)"
    case "$status" in
        __NO_FILE__|__NO_PNPM__|__ABSENT__)
            report_finding error "$project_label" "pnpm" \
                "${project_label}/package.json" "1" \
                "Missing pnpm.onlyBuiltDependencies whitelist" \
                "FOUND: ${project_label}/package.json does not declare pnpm.onlyBuiltDependencies. By default pnpm runs install scripts for every package — this whitelist must be present (even if empty) to opt out.

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_PNPM}" \
                "${project_label}/package.json" \
                'add "pnpm": { "onlyBuiltDependencies": [] }'
            ;;
        __ALLOW_ANY__)
            report_finding error "$project_label" "pnpm" \
                "${project_label}/package.json" "1" \
                "pnpm.onlyBuiltDependencies.allowAny is true" \
                "FOUND: ${project_label}/package.json sets pnpm.onlyBuiltDependencies.allowAny to true, which whitelists every package — equivalent to disabling the protection.

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_PNPM}" \
                "${project_label}/package.json" \
                'replace pnpm.onlyBuiltDependencies.allowAny with an explicit array of allowed packages'
            ;;
        __EMPTY__)
            : # compliant — explicit empty list
            ;;
        __LIST__)
            while IFS= read -r pkg; do
                [[ -z "$pkg" ]] && continue
                if ! grep -qxF "$pkg" <<< "$ALLOW_BUILDS_LIST"; then
                    report_finding error "$project_label" "pnpm" \
                        "${project_label}/package.json" "1" \
                        "Package '${pkg}' allowed to run install scripts but not in workflow allow-builds" \
                        "FOUND: ${project_label}/package.json whitelists '${pkg}' in pnpm.onlyBuiltDependencies, but '${pkg}' is not in the workflow's allow-builds input (currently: $(echo "$ALLOW_BUILDS_LIST" | paste -sd ',' - || echo '<empty>')).

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_PNPM}

If '${pkg}' is intentionally allowed, add it to the workflow input:
    js-allow-builds: |
      ${pkg}" \
                        "${project_label}/package.json" \
                        "remove '${pkg}' from pnpm.onlyBuiltDependencies OR add '${pkg}' to the workflow's js-allow-builds input"
                fi
            done < <(echo "$only_built" | tail -n +2)
            ;;
    esac
}

# yarn classic + berry shared
check_yarn_project() {
    local project_dir="$1" project_label="$2" flavour="$3"
    local yarnrc_classic="$project_dir/.yarnrc"
    local yarnrc_yml="$project_dir/.yarnrc.yml"
    local lockfile="$project_dir/yarn.lock"

    # 0. Version probe — determines whether native enforcement is available.
    local yarn_version yarn_supports_native=false
    yarn_version="$(detect_yarn_version "$project_dir")"
    if [[ "$flavour" == "yarn-berry" && -n "$yarn_version" ]]; then
        if [[ "$(version_cmp "$yarn_version" "$YARN_MIN_VERSION")" != "-1" ]]; then
            yarn_supports_native=true
        fi
    fi

    # 1. minimumReleaseAge
    if [[ "$MIN_RELEASE_AGE_MINUTES" != "0" ]]; then
        if "$yarn_supports_native"; then
            # yarn-berry ≥ YARN_MIN_VERSION: check npmMinimalAgeGate natively.
            local age_yaml
            age_yaml="$(yaml_get_scalar "$yarnrc_yml" "npmMinimalAgeGate")"
            age_yaml="${age_yaml%\"}"; age_yaml="${age_yaml#\"}"
            if [[ -z "$age_yaml" ]]; then
                report_finding error "$project_label" "$flavour" \
                    "${project_label}/.yarnrc.yml" "1" \
                    "Missing npmMinimalAgeGate (need ≥ ${MIN_RELEASE_AGE_MINUTES} min = $((MIN_RELEASE_AGE_MINUTES/1440)) days)" \
                    "FOUND: ${project_label}/.yarnrc.yml does not set npmMinimalAgeGate. Without it, yarn will install too-recent versions at install time.

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_YARN_BERRY}" \
                    "${project_label}/.yarnrc.yml" \
                    "add line: npmMinimalAgeGate: ${MIN_RELEASE_AGE_MINUTES}"
            elif [[ "$age_yaml" =~ ^[0-9]+$ ]] && (( age_yaml < MIN_RELEASE_AGE_MINUTES )); then
                local line
                line="$(yaml_line "$yarnrc_yml" "npmMinimalAgeGate")"
                report_finding error "$project_label" "$flavour" \
                    "${project_label}/.yarnrc.yml" "${line:-1}" \
                    "npmMinimalAgeGate=${age_yaml} is below required ${MIN_RELEASE_AGE_MINUTES} min" \
                    "FOUND: ${project_label}/.yarnrc.yml sets npmMinimalAgeGate to ${age_yaml} minutes. Required minimum is ${MIN_RELEASE_AGE_MINUTES}.

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_YARN_BERRY}" \
                    "${project_label}/.yarnrc.yml" \
                    "raise npmMinimalAgeGate to at least ${MIN_RELEASE_AGE_MINUTES}"
            fi
        elif ! is_true "$ENFORCE_RELEASE_AGE_VIA_REGISTRY"; then
            # yarn-classic OR yarn-berry < YARN_MIN_VERSION → hard-fail with
            # migration options (yarn 4.14+ or pnpm 10+).
            local title body fix_edit
            if [[ "$flavour" == "yarn-classic" ]]; then
                title="yarn 1.x cannot enforce minimumReleaseAge — migrate to yarn 4.14+ or pnpm 10+"
                body="FOUND: ${project_label} uses yarn 1.x (classic). yarn 1.x has NO setting for minimum-release-age. Anyone who clones this repo and runs yarn install can pick up a freshly-published (and possibly compromised) version of any dep. The quarantine policy of ${MIN_RELEASE_AGE_MINUTES} min is unenforceable here."
                fix_edit="migrate to yarn 4.14+ (npmMinimalAgeGate) OR pnpm 10+ (minimumReleaseAge)"
            else
                title="yarn ${yarn_version:-<unknown>} is too old for npmMinimalAgeGate — need ≥ ${YARN_MIN_VERSION}"
                body="FOUND: ${project_label} pins yarn@${yarn_version:-<unknown>} via packageManager. npmMinimalAgeGate was introduced in yarn 4.10 and approvedGitRepositories in 4.14. Below ${YARN_MIN_VERSION} the recommended settings are silently ignored, so the protection is NOT active at install time."
                fix_edit="bump packageManager to yarn@${YARN_MIN_VERSION} or newer (corepack enable && yarn set version ${YARN_MIN_VERSION})"
            fi
            report_finding error "$project_label" "$flavour" \
                "${project_label}/package.json" "1" \
                "$title" \
                "${body}

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_OTHER}" \
                "${project_label}/package.json" \
                "$fix_edit"
        fi
    fi

    # 2. blockExoticSubdeps — yarn-berry ≥ 4.14 has approvedGitRepositories natively;
    #    otherwise rely on the lockfile scan below.
    if is_true "$REQUIRE_BLOCK_EXOTIC"; then
        if "$yarn_supports_native"; then
            # Setting is present if approvedGitRepositories appears in .yarnrc.yml
            # (any value — empty list blocks all; whitelist blocks anything not listed).
            local approved_line
            approved_line="$(yaml_line "$yarnrc_yml" "approvedGitRepositories")"
            if [[ -z "$approved_line" ]]; then
                report_finding warning "$project_label" "$flavour" \
                    "${project_label}/.yarnrc.yml" "1" \
                    "approvedGitRepositories not set (yarn 4.14+ block-exotic-subdeps equivalent)" \
                    "FOUND: ${project_label}/.yarnrc.yml does not declare approvedGitRepositories. Without it, yarn will allow git/tarball deps from any source. (Warning only — additional errors are emitted per match if exotic resolutions exist in yarn.lock.)

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_YARN_BERRY}" \
                    "${project_label}/.yarnrc.yml" \
                    "add: approvedGitRepositories: []  (empty list = block all)"
            fi
        fi

        # Lockfile scan — applies to every yarn project regardless of version.
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local lock_line lock_spec
            lock_line="${match%%:*}"
            lock_spec="$(echo "${match#*:}" | sed 's/^[[:space:]]*//')"
            report_finding error "$project_label" "$flavour" \
                "${project_label}/yarn.lock" "$lock_line" \
                "Exotic resolution in yarn.lock" \
                "FOUND: yarn.lock line ${lock_line} contains a non-registry resolution:
    ${lock_spec}

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_LOCKFILE}" \
                "${project_label}/yarn.lock" \
                "remove or replace exotic dep at line ${lock_line}: ${lock_spec}"
        done < <(yarn_lock_exotic "$lockfile")
    fi

    # 3. allowBuilds — enableScripts: false (berry) or ignore-scripts true (classic).
    if [[ "$flavour" == "yarn-berry" ]]; then
        local enable_scripts
        enable_scripts="$(yaml_get_scalar "$yarnrc_yml" "enableScripts")"
        if [[ "$enable_scripts" == "false" ]]; then
            : # protected
        else
            local line file
            line="$(yaml_line "$yarnrc_yml" "enableScripts")"
            file="${project_label}/.yarnrc.yml"
            [[ -f "$yarnrc_yml" ]] || { file="${project_label}/.yarnrc.yml (missing)"; line="1"; }
            report_finding error "$project_label" "$flavour" \
                "$file" "${line:-1}" \
                "yarn berry: enableScripts must be false" \
                "FOUND: ${project_label} (yarn berry) does not set enableScripts: false in .yarnrc.yml — install scripts run by default.

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_YARN_BERRY}" \
                "${project_label}/.yarnrc.yml" \
                "add line: enableScripts: false"
        fi
    else
        local ignore_scripts file line
        ignore_scripts="$(grep -E '^[[:space:]]*ignore-scripts[[:space:]]+(true|false)' "$yarnrc_classic" 2>/dev/null | tail -1 | awk '{print $2}' || true)"
        if [[ "$ignore_scripts" == "true" ]]; then
            : # protected
        else
            if [[ -f "$yarnrc_classic" ]]; then
                file="${project_label}/.yarnrc"
                line="$(grep -nE '^[[:space:]]*ignore-scripts' "$yarnrc_classic" 2>/dev/null | tail -1 | cut -d: -f1 || true)"
            else
                file="${project_label}/.yarnrc (missing)"
                line="1"
            fi
            report_finding error "$project_label" "$flavour" \
                "$file" "${line:-1}" \
                "yarn classic: ignore-scripts must be true" \
                "FOUND: ${project_label} (yarn 1.x) does not set 'ignore-scripts true' in .yarnrc — install scripts run by default.

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_YARN_CLASSIC}" \
                "${project_label}/.yarnrc" \
                "add line: ignore-scripts true"
        fi
    fi
}

# npm
check_npm_project() {
    local project_dir="$1" project_label="$2"
    local npmrc="$project_dir/.npmrc"
    local lockfile="$project_dir/package-lock.json"

    # 1. minimumReleaseAge — npm has no widely-supported install-time setting.
    #    Hard-fail by default: migrate to pnpm 10+ for actual enforcement.
    if [[ "$MIN_RELEASE_AGE_MINUTES" != "0" ]] && ! is_true "$ENFORCE_RELEASE_AGE_VIA_REGISTRY"; then
        report_finding error "$project_label" "npm" \
            "${project_label}/package.json" "1" \
            "npm cannot enforce minimumReleaseAge — migrate to yarn 4.14+ or pnpm 10+" \
            "FOUND: ${project_label} uses npm. npm < 11.10 has no setting that refuses install of too-recent dependency versions. Anyone who clones this repo and runs npm install can pick up a freshly-published (and possibly compromised) dependency version. The quarantine policy of ${MIN_RELEASE_AGE_MINUTES} min is unenforceable here.

${WHY_MIN_RELEASE_AGE}

${FIX_MIN_RELEASE_AGE_OTHER}" \
            "${project_label}/package.json" \
            "migrate to yarn 4.14+ (npmMinimalAgeGate) OR pnpm 10+ (minimumReleaseAge)"
    fi

    # 2. blockExoticSubdeps — lockfile scan
    if is_true "$REQUIRE_BLOCK_EXOTIC"; then
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local pkg spec
            pkg="${match%%	*}"
            spec="${match#*	}"
            report_finding error "$project_label" "npm" \
                "${project_label}/package-lock.json" "1" \
                "Exotic dep '${pkg}' in package-lock.json" \
                "FOUND: package-lock.json resolves '${pkg}' to a non-registry source:
    ${spec}

${WHY_BLOCK_EXOTIC}

${FIX_BLOCK_EXOTIC_LOCKFILE}" \
                "${project_label}/package-lock.json" \
                "remove or replace exotic dep '${pkg}' (${spec})"
        done < <(npm_lock_exotic "$lockfile")
    fi

    # 3. allowBuilds — require ignore-scripts=true in .npmrc, unless allow-builds covers every hasInstallScript entry
    local ignore_scripts
    ignore_scripts="$(npmrc_get "$npmrc" "ignore-scripts")"
    if is_true "$ignore_scripts"; then
        : # protected
    else
        # Check lockfile install-script packages against allow-builds
        local script_pkgs unapproved=()
        script_pkgs="$(npm_lock_install_scripts "$lockfile" | sort -u || true)"
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            if ! grep -qxF "$pkg" <<< "$ALLOW_BUILDS_LIST"; then
                unapproved+=("$pkg")
            fi
        done <<< "$script_pkgs"

        local file line
        if [[ -f "$npmrc" ]]; then
            file="${project_label}/.npmrc"
            line="$(npmrc_line "$npmrc" "ignore-scripts")"
        else
            file="${project_label}/.npmrc (missing)"
            line="1"
        fi

        if (( ${#unapproved[@]} > 0 )); then
            report_finding error "$project_label" "npm" \
                "$file" "${line:-1}" \
                "npm: ignore-scripts must be true (or allow-builds must cover all install-script deps)" \
                "FOUND: ${project_label} (npm) does not set ignore-scripts=true in .npmrc, AND the lockfile contains $(echo "${unapproved[@]}" | wc -w | tr -d ' ') package(s) with install scripts that are not in the workflow's allow-builds whitelist:
    $(printf '    %s\n' "${unapproved[@]}" | sed 's/^    //' | paste -sd ',' - || echo '(none)')

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_NPM}

Or, if these are legitimate, add them to the workflow input:
    js-allow-builds: |
$(printf '      %s\n' "${unapproved[@]}")" \
                "${project_label}/.npmrc" \
                "add line: ignore-scripts=true (or add these to workflow js-allow-builds: $(printf '%s, ' "${unapproved[@]}" | sed 's/, $//'))"
        else
            report_finding error "$project_label" "npm" \
                "$file" "${line:-1}" \
                "npm: ignore-scripts must be true" \
                "FOUND: ${project_label} (npm) does not set ignore-scripts=true in .npmrc. No packages with install scripts are currently in the lockfile, but the lockfile is not pinned against future install-script additions.

${WHY_ALLOW_BUILDS}

${FIX_ALLOW_BUILDS_NPM}" \
                "${project_label}/.npmrc" \
                "add line: ignore-scripts=true"
        fi
    fi
}

# ── scan ─────────────────────────────────────────────────────────────────────

echo "============================================================"
echo "JS Supply-Chain Check"
echo "============================================================"
echo "Search dir:                       $(realpath "$SEARCH_DIR")"
echo "Excluding:                        $EXCLUDE_CSV"
echo "minimum-release-age-minutes:      $MIN_RELEASE_AGE_MINUTES"
echo "allow-builds:                     $(echo "$ALLOW_BUILDS_LIST" | paste -sd ',' - || echo '<empty>')"
echo "require-block-exotic-subdeps:     $REQUIRE_BLOCK_EXOTIC"
echo "enforce-release-age-via-registry: $ENFORCE_RELEASE_AGE_VIA_REGISTRY"
echo "pnpm-min-version:                 $PNPM_MIN_VERSION"
echo "yarn-min-version:                 $YARN_MIN_VERSION"
echo "fail-on-found:                    $FAIL_ON_FOUND"
if is_true "$ENFORCE_RELEASE_AGE_VIA_REGISTRY" && [[ "$MIN_RELEASE_AGE_MINUTES" != "0" ]]; then
    echo ""
    echo "Registry-scan enforcement is ON: every lockfile entry will be looked up"
    echo "against registry.npmjs.org and the PR will fail on any package version"
    echo "younger than ${MIN_RELEASE_AGE_MINUTES} minutes ($((MIN_RELEASE_AGE_MINUTES/1440)) days)."
fi
if [[ -z "$PYTHON_BIN" ]]; then
    echo "::warning::python3 not available — package.json/package-lock.json parsing will be skipped."
elif ! $HAS_PYYAML; then
    echo "Note: PyYAML not installed; falling back to regex parser for YAML files."
fi
echo ""

# Discover lockfiles. -not -path "*/node_modules/*" is a fast pruning shortcut;
# should_exclude() does the authoritative filtering below.
LOCKFILES=()
while IFS= read -r -d '' file; do
    LOCKFILES+=("$file")
done < <(find "$SEARCH_DIR" \
    \( -name pnpm-lock.yaml -o -name yarn.lock -o -name package-lock.json \) \
    -not -path "*/node_modules/*" \
    -print0 2>/dev/null || true)

if (( ${#LOCKFILES[@]} == 0 )); then
    echo "No JS lockfiles found under $SEARCH_DIR."
    echo "============================================================"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        {
            echo "findings=0"
            echo "warnings=0"
            echo "projects-scanned=0"
        } >> "$GITHUB_OUTPUT"
    fi
    exit 0
fi

# Group lockfiles by project directory.
# Use space-delimited tokens with surrounding spaces so substring tests like
# *' npm '* don't accidentally match 'pnpm'.
declare -A PROJECT_LOCKS  # dir -> " pnpm  yarn  npm "
for lock in "${LOCKFILES[@]}"; do
    rel_lock="${lock#"$SEARCH_DIR"/}"
    rel_dir="$(dirname "$rel_lock")"
    [[ "$rel_dir" == "." ]] && rel_dir=""
    should_exclude "${rel_dir:-.}" && continue
    should_exclude "$rel_lock" && continue

    project_dir="$(dirname "$lock")"
    # Initialise to a single space so the leading-space invariant holds.
    [[ -z "${PROJECT_LOCKS[$project_dir]:-}" ]] && PROJECT_LOCKS["$project_dir"]=" "
    case "$(basename "$lock")" in
        pnpm-lock.yaml)     PROJECT_LOCKS["$project_dir"]+="pnpm " ;;
        yarn.lock)          PROJECT_LOCKS["$project_dir"]+="yarn " ;;
        package-lock.json)  PROJECT_LOCKS["$project_dir"]+="npm "  ;;
    esac
done

for project_dir in "${!PROJECT_LOCKS[@]}"; do
    managers="${PROJECT_LOCKS[$project_dir]}"
    rel_project="${project_dir#"$SEARCH_DIR"/}"
    [[ "$rel_project" == "$project_dir" ]] && rel_project="."  # SEARCH_DIR itself
    project_label="$rel_project"

    # Count this as one project for the stat, even if multiple lockfiles coexist.
    (( PROJECT_COUNT++ )) || true

    # Detect ambiguous (multiple managers in same dir).
    manager_count=$(echo "$managers" | wc -w | tr -d ' ')
    if (( manager_count > 1 )); then
        report_finding warning "$project_label" "ambiguous" \
            "${project_label}/package.json" "1" \
            "Multiple lockfiles in same directory:$managers" \
            "FOUND: ${project_label} contains lockfiles for multiple package managers ($managers). Pick one manager, delete the other lockfiles, and commit. Mixing managers causes nondeterministic installs — different developers and CI runners can end up with different dependency trees."
    fi

    # Space-delimited match — 'pnpm' must not trigger the 'npm' branch.
    [[ "$managers" == *" pnpm "* ]] && check_pnpm_project "$project_dir" "$project_label"
    if [[ "$managers" == *" yarn "* ]]; then
        flavour="$(detect_yarn_flavour "$project_dir")"
        check_yarn_project "$project_dir" "$project_label" "$flavour"
    fi
    [[ "$managers" == *" npm "* ]] && check_npm_project "$project_dir" "$project_label"

    # Registry-scan: explicitly enforce minimum-release-age by checking each
    # lockfile entry's npm-registry publish date. Opt-in (default off) because
    # it hits the network and is O(deps) requests.
    if is_true "$ENFORCE_RELEASE_AGE_VIA_REGISTRY" && [[ "$MIN_RELEASE_AGE_MINUTES" != "0" ]]; then
        [[ "$managers" == *" pnpm "* ]] && registry_scan_lockfile \
            "$project_label" "pnpm" "$project_dir/pnpm-lock.yaml" "${project_label}/pnpm-lock.yaml"
        if [[ "$managers" == *" yarn "* ]]; then
            local _flavour
            _flavour="$(detect_yarn_flavour "$project_dir")"
            registry_scan_lockfile "$project_label" "$_flavour" "$project_dir/yarn.lock" "${project_label}/yarn.lock"
        fi
        [[ "$managers" == *" npm "* ]] && registry_scan_lockfile \
            "$project_label" "npm" "$project_dir/package-lock.json" "${project_label}/package-lock.json"
    fi
done

# ── ACTION REQUIRED footer ──────────────────────────────────────────────────
# Aggregates every concrete edit needed across all projects, grouped by file.
# Printed OUTSIDE any ::group:: so a developer who jumps to the bottom of the
# log sees exactly what to do without expanding individual findings.

if (( ${#FIX_FILE_ORDER[@]} > 0 )); then
    echo ""
    echo "############################################################"
    echo "# ACTION REQUIRED — apply these edits to clear the check   #"
    echo "############################################################"
    fix_index=1
    for fix_file in "${FIX_FILE_ORDER[@]}"; do
        echo ""
        echo "[${fix_index}] ${fix_file}"
        while IFS= read -r edit; do
            [[ -z "$edit" ]] && continue
            echo "      → ${edit}"
        done <<< "${FIXES_BY_FILE[$fix_file]}"
        ((fix_index++))
    done
    echo ""
    echo "Policy and inputs are defined and documented here:"
    echo "  ${QB_DOCS_URL}"
    echo "  ${QB_WORKFLOW_URL}"
    echo "  ${QB_ACTION_URL}"
fi

# ── final summary ────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "Summary"
echo "============================================================"
echo "Projects scanned: $PROJECT_COUNT"
echo "Errors:           $ERROR_COUNT"
echo "Warnings:         $WARNING_COUNT"
echo ""

if (( PROJECT_COUNT > 0 )); then
    echo "Per-project breakdown:"
    for key in $(printf '%s\n' "${!PROJECT_ERRORS[@]}" "${!PROJECT_WARNINGS[@]}" | sort -u); do
        e="${PROJECT_ERRORS[$key]:-0}"
        w="${PROJECT_WARNINGS[$key]:-0}"
        printf "  %-50s errors=%-3s warnings=%-3s\n" "$key" "$e" "$w"
    done
fi
echo "============================================================"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "findings=${ERROR_COUNT}"
        echo "warnings=${WARNING_COUNT}"
        echo "projects-scanned=${PROJECT_COUNT}"
    } >> "$GITHUB_OUTPUT"
fi

if (( ERROR_COUNT > 0 )) && is_true "$FAIL_ON_FOUND"; then
    exit 1
fi
exit 0
