#!/usr/bin/env bash
# Run the whole pipeline over a repo: discover -> scope -> scan -> normalise -> verify
# -> consolidate. One command, no global setup: syft is fetched pinned if absent.
#
# Usage: run-pipeline.sh <product-name> <product-version> [repo-root]
#
# Exits non-zero if any candidate lacks a scope decision, if any produced BOM fails the
# gate, or if consolidation loses a component. Targets that need a build step this script
# cannot perform are recorded as gaps in quickbird:sbom:missing rather than skipped
# silently — an incomplete SBOM must say so.

set -uo pipefail

PRODUCT="${1:?usage: run-pipeline.sh <product> <version> [repo-root]}"
VERSION="${2:?missing version}"
REPO="${3:-.}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SBOM_OUT_DIR:-$REPO/sbom}"
SYFT_VERSION="${SYFT_VERSION:-1.20.0}"
SYFT_BIN="${SYFT_BIN:-}"

log() { printf '%s\n' "$*" >&2; }
die() { printf '::error::%s\n' "$*" >&2; exit 1; }

for tool in jq yq curl; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

# --- syft, pinned -----------------------------------------------------------
# Pinned rather than @latest: the component list must not change because a scanner
# auto-updated between two runs of the same commit.
ensure_syft() {
  [[ -n "$SYFT_BIN" && -x "$SYFT_BIN" ]] && return 0
  if command -v syft >/dev/null 2>&1; then
    local have; have=$(syft --version 2>/dev/null | awk '{print $2}')
    if [[ "$have" == "$SYFT_VERSION" ]]; then SYFT_BIN=$(command -v syft); return 0; fi
    log "warning: syft $have on PATH, pipeline pins $SYFT_VERSION — fetching the pinned build"
  fi
  local cache="${SYFT_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/qb-syft}/$SYFT_VERSION"
  mkdir -p "$cache"
  if [[ ! -x "$cache/syft" ]]; then
    local os arch
    case "$(uname -s)" in Darwin) os=darwin;; Linux) os=linux;; *) die "unsupported OS";; esac
    case "$(uname -m)" in arm64|aarch64) arch=arm64;; x86_64) arch=amd64;; *) die "unsupported arch";; esac
    log "fetching syft ${SYFT_VERSION} (${os}/${arch})"
    curl -sSL --fail --max-time 300 \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${os}_${arch}.tar.gz" \
      -o "$cache/syft.tgz" || die "could not download syft $SYFT_VERSION"
    tar -xzf "$cache/syft.tgz" -C "$cache" syft || die "could not unpack syft"
  fi
  SYFT_BIN="$cache/syft"
}
ensure_syft
log "syft: $("$SYFT_BIN" --version)"

mkdir -p "$OUT_DIR/bom"
CAND="$OUT_DIR/candidates.json"
PLAN="$OUT_DIR/scan-plan.json"

# --- 1. discover ------------------------------------------------------------
DISCOVER_OUTPUT="$CAND" bash "$HERE/discover.sh" "$REPO" || die "discovery failed"

# --- 2. scope ---------------------------------------------------------------
SCOPE_FILE="${SOUP_SCOPE_FILE:-$REPO/.soup-scope.yml}"
SCOPE_OUTPUT="$PLAN" bash "$HERE/resolve-scope.sh" "$CAND" "$SCOPE_FILE" \
  || die "scope resolution failed — every candidate needs a recorded decision before a BOM can be trusted"

# --- 3. scan each in-scope target ------------------------------------------
BOMS=()
GAPS=()

while IFS=$'\t' read -r id source resolvable; do
  [[ -z "$id" ]] && continue
  raw="$OUT_DIR/bom/$id.raw.json"
  final="$OUT_DIR/bom/$id.cdx.json"
  kind="${source%%:*}"
  arg="${source#*:}"

  if [[ "$resolvable" != "true" ]]; then
    log "  gap  $id — reference is templated, concrete version not knowable from the repo"
    GAPS+=("$id"); continue
  fi

  case "$kind" in
    file|dir|registry)
      target="$kind:$arg"
      [[ "$kind" != "registry" ]] && target="$kind:$REPO/$arg"
      ;;
    installDist)
      # The resolved runtime closure. Declared dependencies alone omit transitives and
      # leave BOM-managed versions empty, which is the defect this pipeline exists for.
      gdir="$REPO/$arg"
      if [[ ! -x "$gdir/gradlew" ]]; then
        log "  gap  $id — no gradlew in $arg, cannot produce the resolved closure"
        GAPS+=("$id"); continue
      fi
      log "  build $id (gradlew installDist)"
      ( cd "$gdir" && ./gradlew installDist --no-daemon -q ) >&2 || {
        log "  gap  $id — installDist failed"; GAPS+=("$id"); continue; }
      libdir=$(find "$gdir/build/install" -maxdepth 2 -type d -name lib 2>/dev/null | head -1)
      [[ -d "$libdir" ]] || { log "  gap  $id — no install output"; GAPS+=("$id"); continue; }
      target="dir:$libdir"
      ;;
    mvn)
      # Same reasoning as installDist: the packaged output is the resolved set, while the
      # pom lists declared dependencies only. mindnet's three Keycloak provider extensions
      # went to the gap list purely because target/ had never been built.
      mdir="$REPO/$arg"
      if [[ ! -f "$mdir/pom.xml" ]]; then
        log "  gap  $id — no pom.xml in $arg"; GAPS+=("$id"); continue
      fi
      if ! command -v mvn >/dev/null 2>&1; then
        log "  gap  $id — maven not available on this runner"; GAPS+=("$id"); continue
      fi
      # package alone is not enough. Without a shade/assembly plugin, target/ holds only
      # the artifact jar — scanning it found 2 components for an extension that has 8
      # runtime dependencies including protobuf-java and five netty jars, exactly the kind
      # of library that carries CVEs. copy-dependencies materialises the resolved runtime
      # closure, which is the Maven analogue of Gradle's installDist.
      #
      # includeScope=runtime deliberately drops `provided` dependencies: the Keycloak SPI
      # jars are supplied by the Keycloak runtime, so they ship in the Keycloak image's BOM
      # rather than in the extension's. Counting them here would double-count them.
      log "  build $id (mvn package + copy-dependencies)"
      ( cd "$mdir" && mvn -q -B package -DskipTests \
          dependency:copy-dependencies -DincludeScope=runtime \
          -DoutputDirectory=target/sbom-deps ) >&2 || {
        log "  gap  $id — mvn build failed"; GAPS+=("$id"); continue; }
      [[ -d "$mdir/target" ]] || { log "  gap  $id — no target/ after build"; GAPS+=("$id"); continue; }
      NDEPS=$(find "$mdir/target/sbom-deps" -name '*.jar' 2>/dev/null | wc -l | tr -d ' ')
      log "       $NDEPS runtime dependency jar(s) materialised"
      target="dir:$mdir/target"
      ;;
    binary|apk)
      # These need a project-specific build (a linked Go binary, a signed APK). Rather
      # than guess a build command, record the gap so the consolidated BOM declares it.
      log "  gap  $id — needs a prebuilt artifact ($kind); provide one via SBOM_ARTIFACT_$id"
      var="SBOM_ARTIFACT_${id//[^A-Za-z0-9]/_}"
      if [[ -n "${!var:-}" && -e "${!var}" ]]; then
        target="file:${!var}"; log "       using ${!var}"
      else
        GAPS+=("$id"); continue
      fi
      ;;
    *)
      log "  gap  $id — unknown scan source kind: $kind"; GAPS+=("$id"); continue ;;
  esac

  log "  scan $id  <- $target"
  # Two output formats from one scan. syft's CycloneDX output records only the image name and
  # tag — no digest at all — while its native output carries repoDigests, manifestDigest and
  # imageID. That digest is what makes the document say which bytes were actually examined:
  #
  #   redis:8.8.1-alpine  ->  index.docker.io/library/redis@sha256:8096655e4377...
  #
  # It matters most for a floating tag. `curlimages/curl:latest` names nothing, so without the
  # digest the SBOM cannot say what it looked at, and the scope files were excluding such images
  # as "not reproducible" — which rewarded leaving them unpinned. With the digest recorded, the
  # document is exact regardless of what the tag does later, and the image can simply be in scope.
  # It also makes tag mutation visible on a pinned image: same tag, different digest between runs.
  native="${raw%.json}.syft.json"
  if ! "$SYFT_BIN" scan "$target" -o cyclonedx-json="$raw" -o syft-json="$native" -q 2>/dev/null; then
    log "  gap  $id — syft failed"; GAPS+=("$id"); continue
  fi
  BOM_SUBJECT="$id" SCAN_TARGET="$target" SYFT_NATIVE="$native" \
    bash "$HERE/normalize-bom.sh" "$raw" "$final" >/dev/null \
    || { log "  gap  $id — normalisation failed"; GAPS+=("$id"); continue; }
  bash "$HERE/verify-bom.sh" "$final" >/dev/null 2>&1 \
    || { bash "$HERE/verify-bom.sh" "$final" >&2; die "$id failed the BOM gate"; }
  rm -f "$raw" "$native"
  BOMS+=("$final")
done < <(jq -r '.scan[] | "\(.id)\t\(.scan_source)\t\(.resolvable)"' "$PLAN")

[[ ${#BOMS[@]} -gt 0 ]] || die "no target produced a BOM"

# --- 4. consolidate ---------------------------------------------------------
SOLUTION="$OUT_DIR/bom/solution.cdx.json"
SBOM_MISSING="$(IFS=,; echo "${GAPS[*]:-}")" \
  SBOM_TIER="${SBOM_TIER:-branch}" \
  bash "$HERE/consolidate.sh" "$PRODUCT" "$VERSION" "$SOLUTION" "${BOMS[@]}" \
  || die "consolidation failed"

bash "$HERE/verify-bom.sh" "$SOLUTION" >&2 || die "consolidated BOM failed the gate"

# --- 5. assess: vulnerabilities, enrichment, VEX, classification -------------
# The release bundle is evidence, and a component list without its assessment is only half
# of it. Guarded by a policy: without one there is nothing to classify against, and
# inventing defaults here would produce deadlines nobody agreed to.
if [[ -n "${SOUP_POLICY_FILE:-}" && -f "${SOUP_POLICY_FILE}" ]]; then
  if EFF=$(bash "$HERE/validate-policy.sh" "$SOUP_POLICY_FILE" 2>/dev/null); then
    printf '%s' "$EFF" > "$OUT_DIR/policy.effective.json"
    ASSESS_ARGS=("$SOLUTION" "$OUT_DIR/policy.effective.json" --out-dir "$OUT_DIR/bom")
    [[ -d "$REPO/.soups" ]] && ASSESS_ARGS+=(--soups "$REPO/.soups")
    bash "$HERE/assess-bom.sh" "${ASSESS_ARGS[@]}" || die "assessment failed"
    SOLUTION="$OUT_DIR/bom/solution.assessed.cdx.json"
  else
    die "$SOUP_POLICY_FILE failed validation — refusing to classify against a policy that does not hold"
  fi
else
  log "::warning::no policy file — the bundle carries components but no vulnerability assessment"
fi

# --- 6. human-readable PDF (optional) --------------------------------------
# Guarded rather than required: the pipeline's value is the machine-readable bundle, and
# a missing python dependency should not fail a run that already produced it.
if [[ "${RENDER_PDF:-false}" == "true" ]]; then
  PDF="${SOLUTION%.json}.pdf"
  if python3 -c 'import reportlab' 2>/dev/null; then
    python3 "$HERE/render-bundle-pdf.py" "$SOLUTION" "$PDF" || log "::warning::PDF rendering failed; the bundle itself is unaffected"
  else
    log "::warning::reportlab not installed — skipping the PDF. pip install reportlab"
  fi
fi

log ""
log "done: $SOLUTION"
log "  ${#BOMS[@]} target(s) scanned, ${#GAPS[@]} gap(s) recorded"
if [[ ${#GAPS[@]} -gt 0 ]]; then
  log "  quickbird:sbom:complete=false — gaps: ${GAPS[*]}"
fi
