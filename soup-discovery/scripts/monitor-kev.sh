#!/usr/bin/env bash
# CRA minimal monitoring path (DEV-197): does anything we currently run contain a
# vulnerability that is known to be actively exploited?
#
# One question, because from 11 September 2026 that is the one with a 24-hour clock on it.
# Severity grading, deadline tracking and the finding lifecycle are DEV-191 and are
# deliberately absent here — a KEV finding is unconditionally Track 1 in the classification,
# so acting on one needs no severity logic at all.
#
# Pipeline: resolve deployed version -> fetch its SBOM -> scan -> enrich with KEV ->
# suppress VEX not_affected -> emit a dated run record and, if anything is left, an alert.
#
# The run record is written on every run, including clean ones. An "all clear" record is
# not noise: it is the evidence that the product was monitored on that date, and it is the
# only thing that distinguishes "we checked and found nothing" from "nobody looked".
#
# Usage: monitor-kev.sh <owner/repo> <product-name> [out-dir]

set -uo pipefail

REPO="${1:?usage: monitor-kev.sh <owner/repo> <product> [out-dir]}"
PRODUCT="${2:?missing product name}"
OUT_DIR="${3:-monitor-out}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DATE="${RUN_DATE:-$(date -u +%Y-%m-%d)}"
RUN_TS="${RUN_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
CRA_SCOPE="${CRA_SCOPE:-unknown}"     # true | false | unknown

for t in gh jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
mkdir -p "$OUT_DIR"

log() { printf '%s\n' "$*" >&2; }

# --- 1. what is live, and can we scan it? -----------------------------------
# MONITOR_LOCAL_SBOM exists so the alerting path can be exercised before any release
# carries an SBOM asset, and so a project can be dry-run during onboarding. It bypasses the
# deployed-version resolution, so every record produced with it is stamped synthetic:true —
# a test run must never be mistakable for evidence that a product was monitored.
SYNTHETIC=false
if [[ -n "${MONITOR_LOCAL_SBOM:-}" ]]; then
  [[ -f "$MONITOR_LOCAL_SBOM" ]] || { echo "::error::MONITOR_LOCAL_SBOM not found: $MONITOR_LOCAL_SBOM" >&2; exit 1; }
  SYNTHETIC=true
  log "::warning::MONITOR_LOCAL_SBOM set — this run is synthetic and is not monitoring evidence"
fi

DEPLOYED="$OUT_DIR/deployed.json"
if $SYNTHETIC; then
  jq -n --arg s "file://$MONITOR_LOCAL_SBOM" \
    '{mobile:null, environments:[{environment:"synthetic-production", ref:"local", sbom:$s, sbom_status:"local file"}], unresolvable:[]}' \
    > "$DEPLOYED"
else
  bash "$HERE/resolve-deployed.sh" "$REPO" > "$DEPLOYED" 2>/dev/null \
    || { echo "::error::could not resolve the deployed version for $REPO" >&2; exit 1; }
fi

# One target per live thing. mindnet has two — the app and the backend — and they can be on
# different versions, so this is a list rather than a field.
TARGETS=$(jq -c '
  [ (if .mobile != null and .mobile.sbom != null
     then {name:"mobile", version:.mobile.live_version, sbom:.mobile.sbom} else empty end),
    ( .environments[]? | select(.sbom != null and (.environment | test("prod"; "i")))
      | {name:.environment, version:.ref, sbom:.sbom} ) ]' "$DEPLOYED")

UNSCANNABLE=$(jq -c '[ .unresolvable[]? | {name:.environment, version:.ref, why:.why} ]' "$DEPLOYED")

N_TARGETS=$(jq 'length' <<<"$TARGETS")
N_UNSCANNABLE=$(jq 'length' <<<"$UNSCANNABLE")
log "$PRODUCT: $N_TARGETS scannable target(s), $N_UNSCANNABLE unscannable"

FINDINGS='[]'; SUPPRESSED='[]'; UNKNOWN='[]'; SCANNED='[]'
FEEDS='{}'

# --- 2. per target: scan, enrich, filter -------------------------------------
while IFS=$'\t' read -r name version sbom_url; do
  [[ -z "$name" ]] && continue
  log "  $name @ $version"
  bom="$OUT_DIR/$name.cdx.json"
  if [[ "$sbom_url" == file://* ]]; then
    cp "${sbom_url#file://}" "$bom" 2>/dev/null || true
  else
    curl -sSL --fail --max-time 180 "$sbom_url" -o "$bom" 2>/dev/null || true
  fi
  if [[ ! -s "$bom" ]]; then
    UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
      '. + [{name:$n, version:$v, why:"SBOM asset could not be downloaded"}]' <<<"$UNSCANNABLE")
    continue
  fi

  vulns="$OUT_DIR/$name.vulns.json"
  if ! bash "$HERE/scan-vulns.sh" "$bom" "$vulns" >/dev/null 2>&1; then
    UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
      '. + [{name:$n, version:$v, why:"vulnerability scan failed"}]' <<<"$UNSCANNABLE")
    continue
  fi

  enr="$OUT_DIR/$name.enrich.json"
  if ! QB_ENRICH_CVE_FILE="$vulns" QB_ENRICH_OUTPUT="$enr" \
       bash "$HERE/../../kev-epss-enrichment/scripts/enrich.sh" >/dev/null 2>&1 \
    && ! QB_ENRICH_CVE_FILE="$vulns" QB_ENRICH_OUTPUT="$enr" \
       bash "$HERE/enrich.sh" >/dev/null 2>&1; then
    # Enrichment failing means KEV membership is unestablished for the whole target. That
    # is emphatically not "no KEV findings" — mark the target unscannable instead.
    UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
      '. + [{name:$n, version:$v, why:"KEV enrichment failed — membership could not be established"}]' <<<"$UNSCANNABLE")
    continue
  fi

  FEEDS=$(jq -c --slurpfile e "$enr" '$e[0].feeds' <<<"$FEEDS")

  # VEX suppression, where the repo carries SOUP records with vex blocks.
  final="$vulns"
  if [[ -d "$OUT_DIR/soups" ]]; then
    bash "$HERE/merge-assessment.sh" "$vulns" "$OUT_DIR/soups" "$OUT_DIR/$name.assessed.json" >/dev/null 2>&1 \
      && final="$OUT_DIR/$name.assessed.json"
  fi

  # kev is tri-state. true -> alert. false -> clear. null -> unknown, and unknown must not
  # be silently folded into clear, which is the whole reason DEV-192 distinguishes them.
  hits=$(jq -c --slurpfile e "$enr" --arg n "$name" --arg v "$version" '
    ($e[0].cves) as $c
    | [ .vulnerabilities[]?
        | . as $vuln
        | ($c[$vuln.id] // null) as $k
        | select($k != null and $k.kev == true)
        | { cve: $vuln.id, target: $n, version: $v,
            kev_date_added: $k.kev_date_added,
            ransomware: ($k.kev_ransomware == "Known"),
            epss: $k.epss,
            components: [ $vuln.affects[]?.ref ],
            vex_state: ($vuln.analysis.state // null) } ]' "$final")

  sup=$(jq -c '[ .[] | select(.vex_state == "not_affected") ]' <<<"$hits")
  act=$(jq -c '[ .[] | select(.vex_state != "not_affected") ]' <<<"$hits")
  unk=$(jq -c --slurpfile e "$enr" --arg n "$name" '
    ($e[0].cves) as $c
    | [ .vulnerabilities[]? | select(($c[.id] // {kev:null}).kev == null)
        | {cve: .id, target: $n} ]' "$final")

  FINDINGS=$(jq -c --argjson a "$act" '. + $a' <<<"$FINDINGS")
  SUPPRESSED=$(jq -c --argjson s "$sup" '. + $s' <<<"$SUPPRESSED")
  UNKNOWN=$(jq -c --argjson u "$unk" '. + $u' <<<"$UNKNOWN")
  SCANNED=$(jq -c --arg n "$name" --arg v "$version" \
    --argjson t "$(jq '[.vulnerabilities[]?] | length' "$final")" \
    '. + [{name:$n, version:$v, vulnerabilities:$t}]' <<<"$SCANNED")
done < <(jq -r '.[] | "\(.name)\t\(.version)\t\(.sbom)"' <<<"$TARGETS")

# --- 3. the run record ------------------------------------------------------
# all_clear requires that we actually established the answer: no KEV findings AND nothing
# unscannable AND no CVE whose KEV membership is unknown. Anything else is "not clear",
# not "clear".
RECORD="$OUT_DIR/${RUN_DATE}-${PRODUCT}.json"
jq -n \
  --arg product "$PRODUCT" --arg repo "$REPO" --arg at "$RUN_TS" --arg cra "$CRA_SCOPE" \
  --argjson scanned "$SCANNED" --argjson unscannable "$UNSCANNABLE" \
  --argjson findings "$FINDINGS" --argjson suppressed "$SUPPRESSED" \
  --argjson unknown "$UNKNOWN" --argjson feeds "$FEEDS" --argjson synthetic "$SYNTHETIC" \
  '{
     schema: "quickbird.kev-monitor-run/v1",
     product: $product, repo: $repo, run_at: $at, cra_scope: $cra,
     synthetic: $synthetic,
     feeds: $feeds,
     scanned: $scanned,
     not_scanned: $unscannable,
     kev_findings: $findings,
     kev_suppressed_by_vex: $suppressed,
     kev_membership_unknown: $unknown,
     all_clear: (($findings | length) == 0
                 and ($unscannable | length) == 0
                 and ($unknown | length) == 0),
     verdict: (if ($findings | length) > 0 then "kev-findings"
               elif ($unscannable | length) > 0 or ($unknown | length) > 0 then "incomplete"
               else "all-clear" end)
   }' > "$RECORD"

jq -r '"  verdict: \(.verdict)  (kev=\(.kev_findings|length), suppressed=\(.kev_suppressed_by_vex|length), unknown=\(.kev_membership_unknown|length), not scanned=\(.not_scanned|length))"' "$RECORD" >&2
log "  record: $RECORD"

# --- 4. the alert -----------------------------------------------------------
# Written to a file rather than posted here: posting is the workflow's job, and separating
# them means the message can be inspected in a dry run.
ALERT="$OUT_DIR/alert.txt"
: > "$ALERT"
VERDICT=$(jq -r '.verdict' "$RECORD")

if [[ "$VERDICT" == "kev-findings" ]]; then
  {
    echo ":rotating_light: *$PRODUCT — actively exploited vulnerability in the running version*"
    echo ""
    jq -r '.kev_findings[] |
      "• *\(.cve)*  in `\(.target)` @ \(.version)\n" +
      "   in CISA KEV since \(.kev_date_added // "?")" +
      (if .ransomware then "  · known ransomware use" else "" end) +
      (if .epss then "  · EPSS \(.epss)" else "" end) +
      "\n   component: \((.components // []) | join(", ") | .[0:120])"' "$RECORD"
    echo ""
    if [[ "$CRA_SCOPE" == "true" ]]; then
      echo ":warning: This product is in CRA scope. An actively exploited vulnerability is reportable *within 24 hours*."
    elif [[ "$CRA_SCOPE" == "false" ]]; then
      echo "_Not in CRA scope — no 24-hour reporting obligation. Still Track 1 under the classification: act immediately._"
    else
      echo ":question: *CRA scope for this product is not recorded.* Determine it before assuming the 24-hour clock does not apply."
    fi
    echo ""
    echo "Classification: KEV is Track 1 unconditionally — mitigation 72 h, remediation 21 d, and the remediation clock stops only on deploy."
  } >> "$ALERT"

elif [[ "$VERDICT" == "incomplete" ]]; then
  {
    echo ":warning: *$PRODUCT — the KEV check could not be completed*"
    echo ""
    echo "This is not an all-clear. Something could not be established:"
    jq -r '.not_scanned[]? | "• `\(.name // "?")` @ \(.version // "?") — \(.why)"' "$RECORD"
    U=$(jq -r '.kev_membership_unknown | length' "$RECORD")
    [[ "$U" != "0" ]] && echo "• KEV membership unknown for $U vulnerability/ies — the catalog could not be read"
    echo ""
    echo "_Absence of a KEV finding here is not evidence that none exists._"
  } >> "$ALERT"
fi

if [[ -s "$ALERT" ]]; then
  log "  alert written to $ALERT"
  echo "alert=true"
else
  log "  no alert — all clear, record kept as evidence of monitoring"
  echo "alert=false"
fi
