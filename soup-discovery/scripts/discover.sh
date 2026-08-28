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
      elif .[$i].scan_source != $src and ($src | startswith("registry:")) then
        if ($id | startswith("compose-")) then
          # A local docker-compose stack is never the authority on what ships, so two of them
          # disagreeing about a tag is drift between dev conveniences, not the case the
          # conflict below exists for. Worth a warning, not a stopped run. Keeps the first
          # tag seen; the note carries the disagreement forward instead of hiding it.
          .[$i].note = "COMPOSE FILES DISAGREE — " + .[$i].note + " (also seen: " + $src + ")"
          | .[$i].markers |= (. + [$marker] | unique)
        else
          # Two image references under one id. Merging keeps the first and drops the second
          # without a word, which is how a shipped image disappears from an inventory that
          # still calls itself complete. Recorded as a conflict; the run stops on it below.
          #
          # Only for images, because for them the reference is the thing. For a file the path
          # is only where it is kept, and one artefact is legitimately in two places: Xcode
          # keeps the same Package.resolved under the project and under the workspace, and
          # collapsing those two into one candidate is the intended behaviour.
          .[$i].conflict = ((.[$i].conflict // [.[$i].scan_source]) + [$src] | unique)
          | .[$i].markers |= (. + [$marker] | unique)
        end
      else
        .[$i].markers |= (. + [$marker] | unique)
      end
    ' <<<"$CANDIDATES")
}

# Stable id from a path: the full path with / -> -, so equal basenames in different trees
# stay distinct. A top-level directory keeps its short name unchanged.
id_slug() { printf '%s' "${1//\//-}"; }

# ---------------------------------------------------------------------------
# Go — prefer the linked binary over go.sum
# ---------------------------------------------------------------------------
# go.sum lists every module in the module graph including test-only ones; the linked
# binary carries only those actually reachable. Scanning the binary is both smaller
# and truthful. The binary is a build product, so the manifest records how to get it.
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  # Path-based id, not basename: two go.mod in services/a/server and services/b/server both
  # slugged to "server", the `add` dedupe merged them, and the second scan source was
  # silently dropped while its marker claimed coverage. Same convention as python/terraform.
  add "$(id_slug "$dir")" "go" "binary:$dir" "$f" "true" \
      "scan the linked binary, not go.sum — go.sum includes test-only modules that do not ship"
done <<<"$(grep -E '(^|/)go\.mod$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# JVM — prefer the resolved runtime closure over declared dependencies
# ---------------------------------------------------------------------------
# This is the defect this discovery step exists for. Parsing build.gradle gives declared
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
    # Gradle dependency locking wins over the built artifact. syft reads ZERO
    # components out of an AAB — dex bytecode carries no package metadata — so scanning the
    # bundle would close the gap by claiming an empty inventory, which is worse than the gap.
    # The lockfile is the resolved android closure. Enabling it is a build-config decision,
    # not a one-liner: locking must be activated for the runtime configurations first
    # (dependencyLocking { } in the app module), THEN --write-locks persists the file.
    # Once android/app/gradle.lockfile is committed, this branch picks it up automatically.
    android_lock=""
    for cand in "$app_root/android/app/gradle.lockfile" "$app_root/android/gradle.lockfile"; do
      [[ -f "$cand" ]] && { android_lock="$cand"; break; }
    done
    if [[ -n "$android_lock" ]]; then
      add "$(tr '/' '-' <<<"$app_root")-android" "android-gradle" "file:$android_lock" "$f" "true" \
          "gradle dependency locking is on — the lockfile is the resolved android closure; the Dart side comes from pubspec.lock"
    else
      add "$(tr '/' '-' <<<"$app_root")-android" "android-gradle" "apk:$app_root/android" "$f" "true" \
          "Android build of a mobile app — no installDist. The resolved closure needs gradle dependency locking: activate dependencyLocking for the runtime configurations in the app module, run ./gradlew :app:dependencies --write-locks, commit the lockfile — discovery then switches to it automatically. The Dart side is covered by pubspec.lock."
    fi
    continue
  fi

  if [[ -f "$dir/gradle.lockfile" ]]; then
    # lockAllConfigurations() tags every configuration onto one shared line, so the lockfile
    # cannot be scanned as-is: a component locked only for testRuntimeClasspath would be
    # counted as shipped. run-pipeline.sh filters it to runtimeClasspath first.
    src="gradle-lockfile:$dir/gradle.lockfile"
    note="dependency locking enabled — lockfile filtered to runtimeClasspath and used as the resolved set"
  else
    src="installDist:$dir"
    note="no gradle.lockfile — scan installDist output for the resolved runtime closure; declared deps alone would omit transitives and leave BOM-managed versions empty"
  fi
  add "$(id_slug "$dir")" "jvm-gradle" "$src" "$f" "true" "$note"
done <<<"$(grep -E '(^|/)build\.gradle(\.kts)?$' <<<"$FILES" || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  add "$(id_slug "$dir")" "jvm-maven" "mvn:$dir" "$f" "true" \
      "package first, then scan target/ — the pom lists declared dependencies only, the packaged output is the resolved set"
done <<<"$(grep -E '(^|/)pom\.xml$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# iOS — CocoaPods and Swift Package Manager
# ---------------------------------------------------------------------------
# Both files are resolved sets, so neither needs a build and neither can be a gap for want of
# one. Before this, the iOS half of a mobile product was in no inventory and was not reported
# as missing either: the Android build is a candidate and can be recorded as a gap, while iOS
# was absent from the candidate list, so a document could say complete with a whole platform
# never looked at.
#
# Keyed on the app root rather than the file's directory, the same as the Android candidate:
# Package.resolved sits several levels down inside Runner.xcworkspace, and an id built from
# that path would say nothing about which app it belongs to.
ios_root() {  # <file> -> the directory holding ios/, or the file's own directory
  local r="${1%%/ios/*}"
  [[ "$r" == "$1" ]] && r=$(dirname "$1")
  [[ -z "$r" || "$r" == "." ]] && r="app"
  printf '%s' "$r"
}

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  add "$(tr '/' '-' <<<"$(ios_root "$f")")-ios-pods" "cocoapods" "file:$f" "$f" "true" \
      "Podfile.lock is the resolved CocoaPods set of the iOS build"
done <<<"$(grep -E '(^|/)Podfile\.lock$' <<<"$FILES" || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  add "$(tr '/' '-' <<<"$(ios_root "$f")")-ios-spm" "swift" "file:$f" "$f" "true" \
      "Package.resolved is the resolved Swift Package Manager set of the iOS build"
done <<<"$(grep -E '(^|/)Package\.resolved$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Node / Dart — the lockfile is already the resolved set
# ---------------------------------------------------------------------------
# Workspace members must be resolved against the workspace root, not on their own. In a
# yarn/npm/pnpm workspace only the root carries a lockfile, so treating each member as its
# own candidate reports "NO LOCKFILE — not reproducible" for packages that are perfectly
# well resolved. Seen in practice: web/packages/common and web/packages/rest are covered
# by web/yarn.lock. A member is folded into the root candidate as an extra marker, so scope
# rules by path still reach it and nothing disappears silently.
# A monorepo root is not only "package.json has a workspaces field". One product uses Nx
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
    add "$(id_slug "$dir")" "npm" "file:$lock" "$f" "true" "lockfile present — resolved set"
    continue
  fi

  if root=$(npm_monorepo_root "$dir") && rootlock=$(npm_lock_in "$root"); then
    add "$(id_slug "$root")" "npm" "file:$rootlock" "$f" "true" \
        "monorepo root lockfile covers this and every member package — resolved set"
    continue
  fi

  add "$(id_slug "$dir")" "npm" "dir:$dir" "$f" "true" \
      "NO LOCKFILE — versions are ranges, not a resolved set; the component list is not reproducible"
done <<<"$(grep -E '(^|/)package\.json$' <<<"$FILES" | grep -v 'node_modules' || true)"

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  if [[ -f "$dir/pubspec.lock" ]]; then
    add "$(id_slug "$dir")" "pub" "file:$dir/pubspec.lock" "$f" "true" "lockfile present — resolved set"
  else
    add "$(id_slug "$dir")" "pub" "dir:$dir" "$f" "true" "NO pubspec.lock — not a resolved set"
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
  # The id names the file and the stage, not the line. A line number changes whenever
  # anything above it is added or removed, and the scope declaration then no longer
  # matches a candidate that did not itself change: the run fails after a release and
  # needs a second one. The file has to be part of it, because two Dockerfiles in one
  # directory both have a `builder` and both have a final stage, and a directory-keyed
  # id would collapse two different shipped images onto one candidate.
  file_slug=$(tr '/' '-' <<<"$f")
  stage_idx=0
  while IFS= read -r fl; do
    ln=$(cut -d: -f1 <<<"$fl")
    stage_idx=$((stage_idx + 1))
    stage_alias=$(sed -nE 's/^[0-9]+:.*[[:space:]]AS[[:space:]]+([A-Za-z0-9._-]+).*$/\1/Ip' <<<"$fl")
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
    if [[ "$ln" == "$last_line" ]]; then
      stage="${stage_alias:-final}"
    else
      stage="${stage_alias:-stage-$stage_idx}"
    fi
    add "$file_slug-$stage" "container" "registry:$img" "$f:$ln" "$ships" "$note"
  done <<<"$froms"
done <<<"$(grep -E '(^|/)Dockerfile[^/]*$' <<<"$FILES" || true)"

# ---------------------------------------------------------------------------
# Helm / k8s image references — images we deploy but do not build
# ---------------------------------------------------------------------------

# A Helm template never carries the image version; the chart's values.yaml does. So for a
# manifest under <chart>/templates/ the concrete image *is* knowable from the repo — just
# not from the line the reference appears on. Resolving it is what separates the two very
# different cases that both look templated:
#
#   redis:7-alpine, vendor-rest-service:v1.2.4, wireguard:1.0.20210914
#       third-party images pinned in values.yaml. Nothing else in the repo covers them,
#       so reporting them as unresolvable forces a scope file to exclude them, and the
#       images whose CVEs nobody else is watching are the ones that fall out of scope.
#
#   <our-registry>/<product>-rest:<appVersion>
#       our own image at the release version. Genuinely not knowable from the repository, but
#       naming the repository is what lets a scope rule say which build candidate covers it.
resolve_helm_ref() {
  local img="$1" file="$2" chart values expr key val out rest
  case "$file" in */templates/*) ;; *) printf '%s' "$img"; return ;; esac
  chart="${file%%/templates/*}"
  values="$chart/values.yaml"
  [[ -f "$chart/Chart.yaml" && -f "$values" ]] || { printf '%s' "$img"; return; }

  out=""; rest="$img"
  while [[ "$rest" == *'{{'* ]]; do
    out+="${rest%%\{\{*}"
    rest="${rest#*\{\{}"
    expr="${rest%%\}\}*}"
    rest="${rest#*\}\}}"
    # The first .Values reference in the expression is the one that supplies the value;
    # anything after it is a `| default` fallback. `.*\.Values\.` would be greedy and pick
    # the LAST one — which resolved every image to the chart's default `version: 1.0.0`
    # via `| default .Values.version`, silently replacing the vendor image's real v1.2.4.
    key=$(grep -oE '\.Values\.[A-Za-z0-9_.]+' <<<"$expr" | head -1 | sed -E 's/^\.Values\.//; s/\.$//')
    if [[ -z "$key" ]]; then out+="@unresolved"; continue; fi
    val=$(yq -r ".${key}" "$values" 2>/dev/null)
    if [[ -z "$val" || "$val" == "null" ]]; then
      # An empty `tag:` that falls back to the chart appVersion or --set version is our
      # own image at the release version. Distinguish it from a value we simply cannot find.
      if [[ "$expr" == *AppVersion* || "$expr" == *".Values.version"* ]]; then
        out+="@appVersion"
      else
        out+="@unresolved"
      fi
    else
      out+="$val"
    fi
  done
  printf '%s' "$out$rest"
}

# A docker-compose file is a local developer convenience, never the deployment mechanism, in
# every product this pipeline has seen — the chart or the raw k8s manifest is. Naming its
# candidates "compose-" rather than "deployed-" keeps that convention from being an accident of
# which file a grep happened to find first: a compose image can never collide with, and so never
# silently outvote, the real deployed reference for the same image (see add() above).
is_compose_ref() {
  case "$(basename "$1")" in
    docker-compose*.yml|docker-compose*.yaml|compose.yml|compose.yaml) return 0 ;;
    *) return 1 ;;
  esac
}

while IFS= read -r ref; do
  [[ -z "$ref" ]] && continue
  # Normalise the leading ./ that grep -r emits. Without this, markers from this block
  # do not match the git-relative paths used everywhere else, and `path:` scope rules
  # silently fail to match — the exact class of silent failure this pipeline exists to
  # prevent. Caught by the scope gate on the first real repo.
  file=$(cut -d: -f1 <<<"$ref" | sed 's|^\./||')

  # A templated reference contains spaces inside {{ }}, so taking the first whitespace-
  # delimited token truncates it to "{{" — which is why every chart image collapsed onto
  # a filename-derived id. Take the whole quoted value when it is quoted.
  img=$(sed -E 's/.*image:[[:space:]]*//' <<<"$ref")
  case "$img" in
    \"*) img="${img#\"}"; img="${img%%\"*}" ;;
    \'*) img="${img#\'}"; img="${img%%\'*}" ;;
    *)   img="${img%%[[:space:]]*}"; img="${img%%#*}" ;;
  esac
  [[ -z "$img" ]] && continue

  [[ "$img" == *'{{'* ]] && img=$(resolve_helm_ref "$img" "$file")

  # `image:` is not a container-only key. Flutter's flutter_native_splash.yaml, theme
  # files and countless other configs use it for asset paths — one product yielded
  # "assets/logo/logo.png" as a container image. Reject anything with an image-file
  # extension before anything else.
  [[ "$img" =~ \.(png|jpe?g|svg|gif|webp|ico|bmp|tiff?)$ ]] && continue

  # A templated tag is a real deployed image whose concrete version is substituted at
  # deploy time. It cannot be scanned from the repo — which is precisely the deployed-version
  # problem, so record it as unresolvable rather than dropping it or pretending it scans.
  resolvable=true
  note="referenced in a deployment manifest — built elsewhere, so its contents are out of our control but in our CVE scope"
  if [[ "$img" == *'@appVersion'* ]]; then
    # The repository resolved, only the tag comes from the release. Naming the repository
    # is the difference between a scope rule that can say what covers this and one that
    # can only say "some templated thing in this file".
    resolvable=false
    note="OUR OWN IMAGE, RELEASE-VERSIONED — repository resolved from the chart values as ${img%%:*}, but the tag is the chart appVersion / --set version, so the concrete version comes from the deploy record. The Dockerfile candidate that builds it covers its contents only where that candidate declares built_image; without one it scans the base image from its FROM line."
  elif [[ "$img" == *'@unresolved'* || "$img" == *'{{'* || "$img" == *'<'*'>'* || "$img" == *'${'* || "$img" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    resolvable=false
    note="TEMPLATED REFERENCE — the concrete version is substituted at deploy time and is not knowable from the repo. Its components cannot be enumerated here; resolving it needs the deploy record."
  fi

  # Must still look like an image reference: a repo path, optionally with tag/digest.
  if $resolvable && ! [[ "$img" =~ ^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]+)?$ ]]; then
    continue
  fi

  # id from the image's last path segment, so it is readable:
  # nvcr.io/nvidia/k8s-device-plugin:v0.17.1 -> deployed-k8s-device-plugin-v0.17.1
  # @appVersion / @unresolved are our own markers, not part of the reference. They are spelled
  # out here so a slug built from them reads as words; the tag is then dropped from the id
  # anyway, and what marks the candidate as templated is `resolvable` and the note.
  slug_src=$(sed -E 's|@appVersion|appversion|g; s|@unresolved|templated|g' <<<"$img")

  # A ref that is still templated has no version to name it by, and slugging the raw
  # Jinja gives ids like `superset.postgres.image_name-superset.postgres.image_tag`. Name
  # it after whatever *is* concrete: the literal prefix if the repository is spelled out
  # (`<our-registry>/<product>-rest:{{ image.TAG }}`), otherwise the variable path that stands in
  # for it, minus its uninformative leaf.
  if [[ "$slug_src" == *'{{'* ]]; then
    literal="${slug_src%%\{\{*}"
    literal="${literal%:}"
    if [[ -n "${literal//[:\/ ]/}" ]]; then
      slug_src="$literal-templated"
    else
      var=$(grep -oE '\{\{[^}]*\}\}' <<<"$slug_src" | head -1 \
            | sed -E 's/[{}]//g; s/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]*\|.*//' \
            | sed -E 's/\.(image_name|image_tag|repository|image|name|tag)$//')
      slug_src="${var:-unknown}-templated"
    fi
    # A version like 1.37 needs its dot, a variable path does not.
    slug_src="${slug_src//./-}"
  fi

  # The tag is deliberately not part of the id. Bumping a pinned image is the most
  # common change there is and the one this process asks for, and an id carrying the
  # tag turns every bump into a scope declaration that no longer matches. The id names
  # the image; the version it runs at is in the scan source and in the document.
  slug=$(sed -E 's|.*/||; s|@sha256:.*$||; s|:.*$||; s|[@]|-|g; s|[^A-Za-z0-9._-]|-|g; s|-+|-|g; s|^-||; s|-$||' <<<"$slug_src")
  # A fully templated ref ({{ .Values.image }}) strips to nothing. Falling back to the
  # manifest filename keeps the candidate addressable by a scope rule instead of
  # collapsing every such ref onto one unusable id.
  if [[ -z "$slug" || "$slug" =~ ^[-._]*$ ]]; then
    slug="templated-$(basename "$file" | sed -E 's/\.(ya?ml)$//')"
  fi
  prefix="deployed"
  is_compose_ref "$file" && prefix="compose"
  add "$prefix-$slug" "container" "registry:$img" "$file" "true" "$note" "$resolvable"
done <<<"$(grep -rnE '^[[:space:]]*(- )?image:[[:space:]]*\S+' --include='*.yaml' --include='*.yml' . 2>/dev/null \
           | grep -vE 'imagePullPolicy|imagePullSecrets' || true)"

# ---------------------------------------------------------------------------
jq -n --argjson c "$CANDIDATES" '{
  schema: "quickbird.soup-discovery/v1",
  candidate_count: ($c | length),
  ecosystems: ($c | map(.ecosystem) | unique),
  unresolvable: ($c | map(select(.resolvable == false)) | map({id, markers, note})),
  warnings: ($c | map(select(.note | test("NOT digest-pinned|NO LOCKFILE|NO pubspec|unpinned|TEMPLATED|COMPOSE FILES DISAGREE")))
              | map({id, ecosystem, markers, note})),
  candidates: ($c | sort_by(.ecosystem, .id))
}' > "$OUTPUT"

jq -r '"discovered \(.candidate_count) candidates across \(.ecosystems | length) ecosystems: \(.ecosystems | join(", "))"' "$OUTPUT" >&2
jq -r 'if (.warnings | length) > 0 then "\(.warnings | length) reproducibility warnings — see .warnings" else "no reproducibility warnings" end' "$OUTPUT" >&2
echo "wrote $OUTPUT" >&2

# An id that names two different things is not a scope question, it is a defect in the id
# scheme, and the scope declaration cannot express a decision about it either way. Stopping
# here is the only honest answer: continuing would publish a document that omits one of them
# and still reports itself complete.
if [[ "$(jq '[.candidates[] | select(has("conflict"))] | length' "$OUTPUT")" != "0" ]]; then
  echo "::error::two different artefacts share one candidate id — the id scheme cannot tell them apart" >&2
  jq -r '.candidates[] | select(has("conflict")) | "::error::  \(.id): \(.conflict | join(" vs "))"' "$OUTPUT" >&2
  exit 1
fi
