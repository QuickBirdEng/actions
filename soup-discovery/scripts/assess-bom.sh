#!/usr/bin/env bash
# Turn a component list into an assessed one: what is in it, what is known about that, what
# was decided about it, and what we have to do.
#
#   scan-vulns        CVEs for the components, joined on purl
#   enrich            KEV membership and EPSS, with feed provenance
#   merge-enrichment  both onto the vulnerabilities, provenance into metadata
#   merge-assessment  SOUP requirements, approval annotations, VEX analysis
#   classify          track and two dated deadlines per finding
#
# This exists because the five steps were written as separate scripts and then only ever run
# by hand. Two of them — merge-enrichment and classify — were called by nothing at all, so
# in CI the enrichment would never have reached the BOM and no finding would ever have been
# given a deadline. Both consumers now go through here rather than each chaining their own
# subset.
#
# Usage: assess-bom.sh <bom.cdx.json> <effective-policy.json> [options]
#   --soups <dir>     SOUP records, for VEX suppression and approval evidence
#   --state <file>    previous classified findings, for latching and clock starts
#   --out-dir <dir>   where intermediates and results go (default: alongside the BOM)
#   --skip-scan       the BOM already carries vulnerabilities[]

set -uo pipefail

BOM="${1:?usage: assess-bom.sh <bom.cdx.json> <policy.json> [options]}"
POLICY="${2:?missing effective policy json}"
shift 2

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOUPS=""; STATE=""; OUT_DIR=""; SKIP_SCAN=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --soups)    SOUPS="$2"; shift 2 ;;
    --state)    STATE="$2"; shift 2 ;;
    --out-dir)  OUT_DIR="$2"; shift 2 ;;
    --skip-scan) SKIP_SCAN=true; shift ;;
    *) echo "::error::unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ -f "$BOM" ]]    || { echo "::error::BOM not found: $BOM" >&2; exit 1; }
[[ -f "$POLICY" ]] || { echo "::error::policy not found: $POLICY" >&2; exit 1; }
OUT_DIR="${OUT_DIR:-$(dirname "$BOM")}"
mkdir -p "$OUT_DIR"

BASE=$(basename "${BOM%.cdx.json}"); BASE="${BASE%.json}"
log() { printf '%s\n' "$*" >&2; }

VULNS="$OUT_DIR/$BASE.vulns.cdx.json"
ENRICH="$OUT_DIR/$BASE.enrichment.json"
ASSESSED="$OUT_DIR/$BASE.assessed.cdx.json"
FINDINGS="$OUT_DIR/$BASE.findings.json"

# --- 1. vulnerabilities ------------------------------------------------------
if $SKIP_SCAN; then
  cp "$BOM" "$VULNS"
  log "1/5 scan       skipped, BOM already carries $(jq '[.vulnerabilities[]?]|length' "$VULNS") vulnerabilities"
else
  bash "$HERE/scan-vulns.sh" "$BOM" "$VULNS" >/dev/null 2>&1 \
    || { echo "::error::vulnerability scan failed" >&2; exit 1; }
  log "1/5 scan       $(jq '[.vulnerabilities[]?]|length' "$VULNS") vulnerabilities"
fi

# --- 2. enrichment -----------------------------------------------------------
# A failure here is not "no KEV findings" — it means membership was never established, and
# the classifier treats an unknown as Immediate rather than folding it into clear. So the
# run continues, but the tri-state has to survive intact.
ENRICH_SCRIPT="$HERE/../../kev-epss-enrichment/scripts/enrich.sh"
[[ -f "$ENRICH_SCRIPT" ]] || ENRICH_SCRIPT="$HERE/enrich.sh"
if QB_ENRICH_CVE_FILE="$VULNS" QB_ENRICH_OUTPUT="$ENRICH" bash "$ENRICH_SCRIPT" >/dev/null 2>&1; then
  log "2/5 enrich     KEV $(jq -r '.feeds.kev.catalog_version // "unavailable"' "$ENRICH") · EPSS $(jq -r '.feeds.epss.model_version // "unavailable"' "$ENRICH")$( [[ "$(jq -r .stale "$ENRICH")" == "true" ]] && echo ' · STALE' )"
else
  log "::warning::enrichment failed — KEV membership is unestablished for every finding"
  jq -n '{schema:"quickbird.cve-enrichment/v1", stale:true,
          feeds:{kev:{available:false,catalog_version:null},
                 epss:{available:false,model_version:null,score_date:null}},
          cves:{}}' > "$ENRICH"
fi

# --- 3. enrichment onto the BOM ----------------------------------------------
bash "$HERE/merge-enrichment.sh" "$VULNS" "$ENRICH" "$OUT_DIR/$BASE.enriched.cdx.json" >/dev/null 2>&1 \
  || { echo "::error::could not merge the enrichment" >&2; exit 1; }
log "3/5 merge-enr   $(jq '[.vulnerabilities[]? | select(.properties[]? | .name=="quickbird:vuln:kev" and .value=="true")]|length' "$OUT_DIR/$BASE.enriched.cdx.json") in KEV"

# --- 4. SOUP assessment ------------------------------------------------------
if [[ -n "$SOUPS" && -d "$SOUPS" ]]; then
  bash "$HERE/merge-assessment.sh" "$OUT_DIR/$BASE.enriched.cdx.json" "$SOUPS" "$ASSESSED" >/dev/null 2>&1 \
    || { echo "::error::could not merge the SOUP assessment" >&2; exit 1; }
  log "4/5 assess     $(jq -r '[.metadata.properties[]?|select(.name=="quickbird:soup:records-matched")][0].value // 0' "$ASSESSED") SOUP records matched, $(jq '[.vulnerabilities[]?|select(.analysis)]|length' "$ASSESSED") VEX statements applied"
else
  cp "$OUT_DIR/$BASE.enriched.cdx.json" "$ASSESSED"
  log "4/5 assess     no SOUP records given — no VEX suppression, no approval evidence"
fi

# --- 5. classify -------------------------------------------------------------
# Maintenance windows (§3.4) are what give Track 3/4 a remediation date at all. Without them
# the classifier says so explicitly rather than leaving an empty field that reads as "no
# deadline yet" — 210 of Kontina's 521 findings used to sit in exactly that state.
WINDOWS=""
if [[ -n "${MAINTENANCE_LAST_RELEASE:-}" ]]; then
  WINDOWS="$OUT_DIR/maintenance-windows.json"
  MW_ARGS=(--last-release "$MAINTENANCE_LAST_RELEASE"
           --interval "$(jq -r '.maintenance_interval // "90d"' "$POLICY" 2>/dev/null || echo 90d)"
           --out "$WINDOWS")
  ONB=$(jq -r '.onboarded // ""' "$POLICY" 2>/dev/null)
  [[ -n "$ONB" && "$ONB" != "null" ]] && MW_ARGS+=(--onboarded "$ONB")
  python3 "$HERE/maintenance-windows.py" "${MW_ARGS[@]}" >/dev/null 2>&1 || WINDOWS=""
fi

CLS_ARGS=("$ASSESSED" "$POLICY" --out "$FINDINGS")
[[ -n "$WINDOWS" && -f "$WINDOWS" ]] && CLS_ARGS+=(--windows "$WINDOWS")
[[ -n "$STATE" && -f "$STATE" ]] && CLS_ARGS+=(--state "$STATE")
python3 "$HERE/classify-findings.py" "${CLS_ARGS[@]}" 2>&1 | sed 's/^/5\/5 classify   /' >&2 \
  || { echo "::error::classification failed" >&2; exit 1; }

rm -f "$VULNS" "$OUT_DIR/$BASE.enriched.cdx.json"

log ""
log "assessed BOM: $ASSESSED"
log "findings:     $FINDINGS"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "assessed-bom=$ASSESSED"
    echo "findings=$FINDINGS"
    echo "immediate=$(jq -r '.summary.by_track.immediate' "$FINDINGS")"
    echo "alerting=$(jq -r '.summary.alerting' "$FINDINGS")"
    echo "overdue=$(jq -r '.summary.overdue' "$FINDINGS")"
  } >> "$GITHUB_OUTPUT"
fi
