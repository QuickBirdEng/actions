#!/usr/bin/env bash
# Dependency discovery across every ecosystem in a repo.
#
# Emits an exhaustive list of *candidates* — things that could contribute components
# to the SBOM — with, for each, the scan source that would represent what actually
# ships. It does not decide scope. That is resolve-scope.sh, deliberately separate:
# discovery must be exhaustive to be trustworthy, and scope must be a recorded
# decision rather than a side effect of a grep.
#
# Output: candidates.json

set -uo pipefail

REPO_ROOT="${1:-.}"
OUTPUT="${DISCOVER_OUTPUT:-candidates.json}"

cd "$REPO_ROOT" || { echo "::error::cannot enter $REPO_ROOT" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }

# Track files via git so generated output, vendored trees and build dirs are excluded
# by construction rather than by an ever-growing --exclude list.
if git rev-parse --git-dir >/dev/null 2>&1; then
  list_files() { git ls-files; }
else
  echo "::warning::not a git repo — falling back to find, results may include build output" >&2
  list_files() { find . -type f -not -path '*/.git/*' | sed 's|^\./||'; }
fi

FILES=$(list_files)
CANDIDATES="[]"

add() {
  # add <id> <ecosystem> <scan_source> <marker> <ships> <note> [resolvable]
  # Candidates are keyed by id. The same image referenced from five manifests is one
  # candidate with five markers, not five candidates — otherwise ids collide and a scope
  # rule matches an arbitrary one of them.
  CANDIDATES=$(jq -c \
    --arg id "$1" --arg eco "$2" --arg src "$3" --arg marker "$4" \
    --arg ships "$5" --arg note "$6" --arg resolvable "${7:-true}" \
    '
    (map(.id) | index($id)) as $i
    | if $i == null then
        . + [{id:$id, ecosystem:$eco, scan_source:$src, markers:[$marker],
              ships:($ships=="true"), resolvable:($resolvable=="true"), note:$note}]
      else
        .[$i].markers |= (. + [$marker] | unique)
      end
    ' <<<"$CANDIDATES")
}

# ---------------------------------------------------------------------------
# Go — prefer the linked binary over go.sum
# ---------------------------------------------------------------------------
# go.sum lists every module in the module graph including test-only ones; the linked
# binary carries only those actually reachable. Scanning the binary is both smaller
# and truthful. The binary is a build product, so the manifest records how to get it.
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  add "$(basename "$dir")" "go" "binary:$dir" "$f" "true" \
      "scan the linked binary, not go.sum — go.sum includes test-only modules that do not ship"
done <<<"$(grep -E '(^|/)go\.mod$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# JVM — prefer the resolved runtime closure over declared dependencies
# ---------------------------------------------------------------------------
# This is the defect DEV-195 exists for. Parsing build.gradle gives declared
# dependencies only: transitives are invisible and BOM/platform-managed versions come
# back empty. installDist output (or the lockfile, where locking is on) is the resolved
# set and is exactly what the runtime image copies.
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")

  # A Flutter/Android app's build.gradle is not a JVM service. It has no installDist
  # task, and its dependency closure belongs to the mobile artifact, which is
  # represented by the Flutter build, not by a server-side runtime directory. Running
  # the JVM strategy here would simply fail. Detected by an `android/` path segment or
  # a pubspec.yaml above it.
  is_mobile=false
  [[ "/$f" == */android/* ]] && is_mobile=true
  probe="$dir"
  while [[ "$probe" != "." && "$probe" != "/" && -n "$probe" ]]; do
    [[ -f "$probe/pubspec.yaml" ]] && is_mobile=true && break
    probe=$(dirname "$probe")
  done

  if $is_mobile; then
    # An Android build is one candidate, not one per build.gradle. A Flutter app has at
    # least android/build.gradle and android/app/build.gradle; both describe the same
    # shipped artifact. Key on the directory containing android/ so they collapse.
    app_root="${f%%/android/*}"
    [[ "$app_root" == "$f" ]] && app_root=$(dirname "$dir")
    [[ -z "$app_root" || "$app_root" == "." ]] && app_root="app"
    add "$(tr '/' '-' <<<"$app_root")-android" "android-gradle" "apk:$app_root/android" "$f" "true" \
        "Android build of a mobile app — no installDist; the shipped closure comes from the built APK/AAB, and the Dart side from pubspec.lock"
    continue
  fi

  if [[ -f "$dir/gradle.lockfile" ]]; then
    src="file:$dir/gradle.lockfile"; note="dependency locking enabled — lockfile is the resolved set"
  else
    src="installDist:$dir"
    note="no gradle.lockfile — scan installDist output for the resolved runtime closure; declared deps alone would omit transitives and leave BOM-managed versions empty"
  fi
  add "$(basename "$dir")" "jvm-gradle" "$src" "$f" "true" "$note"
done <<<"$(grep -E '(^|/)build\.gradle(\.kts)?$' <<<"$FILES" || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  add "$(basename "$dir")" "jvm-maven" "mvn:$dir" "$f" "true" \
      "package first, then scan target/ — the pom lists declared dependencies only, the packaged output is the resolved set"
done <<<"$(grep -E '(^|/)pom\.xml$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Node / Dart — the lockfile is already the resolved set
# ---------------------------------------------------------------------------
# Workspace members must be resolved against the workspace root, not on their own. In a
# yarn/npm/pnpm workspace only the root carries a lockfile, so treating each member as its
# own candidate reports "NO LOCKFILE — not reproducible" for packages that are perfectly
# well resolved. Seen on osteocoach: web/packages/common and web/packages/rest are covered
# by web/yarn.lock. A member is folded into the root candidate as an extra marker, so scope
# rules by path still reach it and nothing disappears silently.
# A monorepo root is not only "package.json has a workspaces field". osteocoach uses Nx
# (web/nx.json) with no workspaces key at all, and its web/yarn.lock resolves every
# package under web/packages/. Checking only for `workspaces` reported two perfectly
# resolved packages as unreproducible.
npm_monorepo_root() {
  local probe
  probe=$(dirname "$1")
  while [[ "$probe" != "." && "$probe" != "/" && -n "$probe" ]]; do
    for marker in pnpm-workspace.yaml nx.json lerna.json turbo.json rush.json; do
      [[ -f "$probe/$marker" ]] && { printf '%s' "$probe"; return 0; }
    done
    if [[ -f "$probe/package.json" ]] \
       && jq -e '.workspaces != null' "$probe/package.json" >/dev/null 2>&1; then
      printf '%s' "$probe"; return 0
    fi
    probe=$(dirname "$probe")
  done
  return 1
}

npm_lock_in() {
  local d="$1" l
  for l in package-lock.json yarn.lock pnpm-lock.yaml; do
    [[ -f "$d/$l" ]] && { printf '%s' "$d/$l"; return 0; }
  done
  return 1
}

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")

  # Own lockfile wins: a package that resolves independently is its own resolved set even
  # inside a monorepo. Only fall back to the root when the package has none of its own.
  if lock=$(npm_lock_in "$dir"); then
    add "$(basename "$dir")" "npm" "file:$lock" "$f" "true" "lockfile present — resolved set"
    continue
  fi

  if root=$(npm_monorepo_root "$dir") && rootlock=$(npm_lock_in "$root"); then
    add "$(basename "$root")" "npm" "file:$rootlock" "$f" "true" \
        "monorepo root lockfile covers this and every member package — resolved set"
    continue
  fi

  add "$(basename "$dir")" "npm" "dir:$dir" "$f" "true" \
      "NO LOCKFILE — versions are ranges, not a resolved set; the component list is not reproducible"
done <<<"$(grep -E '(^|/)package\.json$' <<<"$FILES" | grep -v 'node_modules' || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  if [[ -f "$dir/pubspec.lock" ]]; then
    add "$(basename "$dir")" "pub" "file:$dir/pubspec.lock" "$f" "true" "lockfile present — resolved set"
  else
    add "$(basename "$dir")" "pub" "dir:$dir" "$f" "true" "NO pubspec.lock — not a resolved set"
  fi
done <<<"$(grep -E '(^|/)pubspec\.yaml$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  pinned="unpinned"
  grep -qE '==[0-9]' "$f" 2>/dev/null && pinned="pinned"
  add "${dir//\//-}" "python" "file:$f" "$f" "true" \
      "requirements are $pinned; unpinned requirements do not identify a version"
done <<<"$(grep -E '(^|/)requirements[^/]*\.txt$' <<<"$FILES" || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  add "${dir//\//-}" "python" "file:$f" "$f" "true" "pyproject — prefer a lock file (uv.lock/poetry.lock) if present"
done <<<"$(grep -E '(^|/)pyproject\.toml$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Terraform — the lockfile is the pinned provider set
# ---------------------------------------------------------------------------
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  add "${dir//\//-}" "terraform" "file:$f" "$f" "true" \
      "pinned provider versions; a flat set by nature — no dependency graph exists"
done <<<"$(grep -E '(^|/)\.terraform\.lock\.hcl$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Container images — only the final stage ships
# ---------------------------------------------------------------------------
# A multi-stage Dockerfile names build images that never reach production. Emitting
# every FROM would inflate the BOM with toolchain that does not ship. Only the last
# FROM is a runtime base; earlier ones are recorded as build-only.
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  froms=$(grep -nE '^[[:space:]]*FROM[[:space:]]' "$f" 2>/dev/null || true)
  [[ -z "$froms" ]] && continue
  last_line=$(tail -1 <<<"$froms" | cut -d: -f1)
  while IFS= read -r fl; do
    ln=$(cut -d: -f1 <<<"$fl")
    # Strip the line number, the FROM keyword, any build flags, and the AS alias.
    # --platform=linux/amd64 is common in multi-arch builds and was silently ending up
    # inside the image reference ("registry:--platform=linux/amd64 nginx:mainline-alpine"),
    # which made the scan fail and the candidate land in the gap list for the wrong reason.
    img=$(sed -E 's/^[0-9]+:[[:space:]]*FROM[[:space:]]+//; s/[[:space:]]+AS[[:space:]]+.*$//I' <<<"$fl")
    while [[ "$img" == --* ]]; do
      img="${img#* }"
      img="${img#"${img%%[![:space:]]*}"}"
    done
    if [[ "$ln" == "$last_line" ]]; then ships=true; else ships=false; fi
    if [[ "$img" == *"@sha256:"* ]]; then
      note="digest-pinned"
    else
      note="NOT digest-pinned — the scanned contents cannot be tied to a specific image build"
    fi
    $ships || note="build stage only, does not ship; $note"
    add "$(dirname "$f" | tr '/' '-')-image-$ln" "container" "registry:$img" "$f:$ln" "$ships" "$note"
  done <<<"$froms"
done <<<"$(grep -E '(^|/)Dockerfile[^/]*$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Helm / k8s image references — images we deploy but do not build
# ---------------------------------------------------------------------------
while IFS= read -r ref; do
  [[ -z "$ref" ]] && continue
  # Normalise the leading ./ that grep -r emits. Without this, markers from this block
  # do not match the git-relative paths used everywhere else, and `path:` scope rules
  # silently fail to match — the exact class of silent failure this pipeline exists to
  # prevent. Caught by the scope gate on the first real repo.
  file=$(cut -d: -f1 <<<"$ref" | sed 's|^\./||')
  img=$(sed -E 's/.*image:[[:space:]]*["'\'']?([^"'\''[:space:]]+).*/\1/' <<<"$ref")
  [[ -z "$img" ]] && continue

  # `image:` is not a container-only key. Flutter's flutter_native_splash.yaml, theme
  # files and countless other configs use it for asset paths — mindnet yielded
  # "assets/logo/logo.png" as a container image. Reject anything with an image-file
  # extension before anything else.
  [[ "$img" =~ \.(png|jpe?g|svg|gif|webp|ico|bmp|tiff?)$ ]] && continue

  # A templated tag is a real deployed image whose concrete version is substituted at
  # deploy time. It cannot be scanned from the repo — which is precisely the DEV-196
  # problem, so record it as unresolvable rather than dropping it or pretending it scans.
  resolvable=true
  note="referenced in a deployment manifest — built elsewhere, so its contents are out of our control but in our CVE scope"
  if [[ "$img" == *'{{'* || "$img" == *'<'*'>'* || "$img" == *'${'* || "$img" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    resolvable=false
    note="TEMPLATED REFERENCE — the concrete version is substituted at deploy time and is not knowable from the repo. Its components cannot be enumerated here; resolving it needs the deploy record (DEV-196)."
  fi

  # Must still look like an image reference: a repo path, optionally with tag/digest.
  if $resolvable && ! [[ "$img" =~ ^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]+)?$ ]]; then
    continue
  fi

  # id from the image's last path segment, so it is readable:
  # nvcr.io/nvidia/k8s-device-plugin:v0.17.1 -> deployed-k8s-device-plugin-v0.17.1
  slug=$(sed -E 's|.*/||; s|[:@]|-|g; s|[^A-Za-z0-9._-]|-|g; s|-+|-|g; s|^-||; s|-$||' <<<"$img")
  # A fully templated ref ({{ .Values.image }}) strips to nothing. Falling back to the
  # manifest filename keeps the candidate addressable by a scope rule instead of
  # collapsing every such ref onto one unusable id.
  if [[ -z "$slug" || "$slug" =~ ^[-._]*$ ]]; then
    slug="templated-$(basename "$file" | sed -E 's/\.(ya?ml)$//')"
  fi
  add "deployed-$slug" "container" "registry:$img" "$file" "true" "$note" "$resolvable"
done <<<"$(grep -rnE '^[[:space:]]*(- )?image:[[:space:]]*\S+' --include='*.yaml' --include='*.yml' . 2>/dev/null \
           | grep -vE 'imagePullPolicy|imagePullSecrets' || true)"

# ---------------------------------------------------------------------------
jq -n --argjson c "$CANDIDATES" '{
  schema: "quickbird.soup-discovery/v1",
  candidate_count: ($c | length),
  ecosystems: ($c | map(.ecosystem) | unique),
  unresolvable: ($c | map(select(.resolvable == false)) | map({id, markers, note})),
  warnings: ($c | map(select(.note | test("NOT digest-pinned|NO LOCKFILE|NO pubspec|unpinned|TEMPLATED")))
              | map({id, ecosystem, markers, note})),
  candidates: ($c | sort_by(.ecosystem, .id))
}' > "$OUTPUT"

jq -r '"discovered \(.candidate_count) candidates across \(.ecosystems | length) ecosystems: \(.ecosystems | join(", "))"' "$OUTPUT" >&2
jq -r 'if (.warnings | length) > 0 then "\(.warnings | length) reproducibility warnings — see .warnings" else "no reproducibility warnings" end' "$OUTPUT" >&2
echo "wrote $OUTPUT" >&2
