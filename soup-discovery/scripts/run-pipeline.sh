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
  if ! "$SYFT_BIN" scan "$target" -o cyclonedx-json="$raw" -q 2>/dev/null; then
    log "  gap  $id — syft failed"; GAPS+=("$id"); continue
  fi
  BOM_SUBJECT="$id" bash "$HERE/normalize-bom.sh" "$raw" "$final" >/dev/null \
    || { log "  gap  $id — normalisation failed"; GAPS+=("$id"); continue; }
  bash "$HERE/verify-bom.sh" "$final" >/dev/null 2>&1 \
    || { bash "$HERE/verify-bom.sh" "$final" >&2; die "$id failed the BOM gate"; }
  rm -f "$raw"
  BOMS+=("$final")
done < <(jq -r '.scan[] | "\(.id)\t\(.scan_source)\t\(.resolvable)"' "$PLAN")

[[ ${#BOMS[@]} -gt 0 ]] || die "no target produced a BOM"

# --- 4. consolidate ---------------------------------------------------------
SOLUTION="$OUT_DIR/bom/solution.cdx.json"
SBOM_MISSING="$(IFS=,; echo "${GAPS[*]:-}")" \
  bash "$HERE/consolidate.sh" "$PRODUCT" "$VERSION" "$SOLUTION" "${BOMS[@]}" \
  || die "consolidation failed"

bash "$HERE/verify-bom.sh" "$SOLUTION" >&2 || die "consolidated BOM failed the gate"

log ""
log "done: $SOLUTION"
log "  ${#BOMS[@]} target(s) scanned, ${#GAPS[@]} gap(s) recorded"
if [[ ${#GAPS[@]} -gt 0 ]]; then
  log "  quickbird:sbom:complete=false — gaps: ${GAPS[*]}"
fi
