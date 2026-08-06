#!/usr/bin/env bash
# CRA minimal monitoring path: does anything we currently run contain a
# vulnerability that is known to be actively exploited?
#
# One question, because from 11 September 2026 that is the one with a 24-hour clock on it.
# Severity grading, deadline tracking and the finding lifecycle are separate concerns and are
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
CRA_SCOPE="${CRA_SCOPE:-}"            # true | false | unknown; normally from the policy
POLICY_FILE="${SOUP_POLICY_FILE:-.soup-policy.yml}"

for t in gh jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
mkdir -p "$OUT_DIR"

log() { printf '%s\n' "$*" >&2; }

# --- policy -----------------------------------------------------------------
# The per-product policy is the machine-readable side of the classification process: it is
# where cra_scope, the alert threshold and the deadlines live. Reading it here rather than
# taking them as arguments means the values are versioned in the repo and validated against
# the process defaults, instead of being retyped into a workflow call.
POLICY_JSON=""
if [[ -f "$POLICY_FILE" ]]; then
  if POLICY_JSON=$(bash "$HERE/validate-policy.sh" "$POLICY_FILE" 2>/dev/null); then
    [[ -z "$CRA_SCOPE" ]] && CRA_SCOPE=$(jq -r '.cra_scope | tostring' <<<"$POLICY_JSON")
    log "policy: $(jq -r '"\(.product) · tier \(.tier) · CRA \(.cra_scope)"' <<<"$POLICY_JSON")"
  else
    # An invalid policy is not a reason to fall back to defaults quietly — the defaults
    # might be exactly what the project meant to override.
    echo "::error::$POLICY_FILE failed validation; run validate-policy.sh to see why" >&2
    exit 1
  fi
else
  log "::warning::no $POLICY_FILE — falling back to arguments and process defaults"
fi
CRA_SCOPE="${CRA_SCOPE:-unknown}"

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

# One target per live thing. A product may have two — the app and the backend — and they can be on
# different versions, so this is a list rather than a field.
TARGETS=$(jq -c '
  [ (if .mobile != null and .mobile.sbom != null
     then {name:"mobile", version:.mobile.live_version, sbom:.mobile.sbom,
           # When the live version reached users. This is the origin of the maintenance-window
           # grid (WI §6.2): the last maintenance event, not a nominal release date.
           live_since:(.mobile.published // null)} else empty end),
    # prod|study, the same rule as the backstop: on these products a Study environment is
    # production. Matching only /prod/ dropped a Study-only product from the targets AND from
    # the unscannable list — the record then said all_clear with nothing scanned at all.
    ( .environments[]? | select(.sbom != null and (.environment | test("prod|study"; "i")))
      | {name:.environment, version:.ref, sbom:.sbom,
         live_since:(.deployed_at // null)} ) ]' "$DEPLOYED")

# The same production filter as the targets. Without it, a Development or QA environment
# with no SBOM keeps every record at `incomplete` forever, and an alert that always fires
# carries no information. `mobile` and the `*` wildcard entry are production by definition.
UNSCANNABLE=$(jq -c '[ .unresolvable[]?
  | select((.environment | test("prod|study|mobile"; "i")) or .environment == "*")
  | {name:.environment, version:.ref, why:.why} ]' "$DEPLOYED")

N_TARGETS=$(jq 'length' <<<"$TARGETS")
N_UNSCANNABLE=$(jq 'length' <<<"$UNSCANNABLE")
log "$PRODUCT: $N_TARGETS scannable target(s), $N_UNSCANNABLE unscannable"

FINDINGS='[]'; SUPPRESSED='[]'; UNKNOWN='[]'; SCANNED='[]'; CLASSIFIED='[]'
LIFECYCLES='[]'; ESCALATIONS='[]'
FEEDS='{}'
# Per target, not per product. One state file for a product with two live things (the app
# and the backend) handed target B target A's clock starts, so B's clocks restarted on
# every run and its latching never held.
STATE_DIR="${MONITOR_STATE_DIR:-$OUT_DIR}"
LIFECYCLE_STATE_DIR="${MONITOR_LIFECYCLE_STATE_DIR:-$OUT_DIR}"
DECISIONS_FILE="${SOUP_DECISIONS_FILE:-.soup-decisions.yml}"

# --- 2. per target: scan, enrich, filter -------------------------------------
while IFS=$'\t' read -r name version sbom_url live_since; do
  [[ -z "$name" ]] && continue
  log "  $name @ $version"
  bom="$OUT_DIR/$name.cdx.json"
  if [[ "$sbom_url" == file://* ]]; then
    cp "${sbom_url#file://}" "$bom" 2>/dev/null || true
  else
    curl -sSL --fail --max-time 180 "$sbom_url" -o "$bom" 2>/dev/null || true
  fi
  # What matters is that the document describes the version that is actually deployed, and
  # resolve-deployed.sh already established which version that is — so the version identity
  # is the guarantee, not the tier.
  #
  # Requiring a particular tier would be wrong here. A `candidate` document is a build of a
  # release-shaped tag and a `staging` document a build of a QA tag; either can be the version the
  # deployment record shows in production, and that record is the guarantee. A `branch` bundle is
  # different — it carries no version identity, so nothing can tie it to a deployment.
  #
  # The tier is recorded either way, so the evidence says which kind of document was scanned.
  BOM_TIER=unmarked
  if [[ -s "$bom" ]]; then
    BOM_TIER=$(jq -r '[.metadata.properties[]? | select(.name=="quickbird:sbom:tier")][0].value // "unmarked"' "$bom" 2>/dev/null)
    if [[ "$BOM_TIER" == "branch" ]]; then
      log "::error::$name: the SBOM at that location is a branch build with no version identity"
      UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
        '. + [{name:$n, version:$v, why:"the SBOM found for this version is a branch build — it carries no version identity, so it cannot be shown to describe what is deployed"}]' <<<"$UNSCANNABLE")
      continue
    fi
  fi

  if [[ ! -s "$bom" ]]; then
    UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
      '. + [{name:$n, version:$v, why:"SBOM asset could not be downloaded"}]' <<<"$UNSCANNABLE")
    continue
  fi

  # One path for both consumers. The monitor used to chain scan -> enrich -> merge itself
  # and skip classification entirely, which is how merge-enrichment and the classifier ended
  # up called by nothing: two subsets of the same pipeline, neither of them complete.
  POL_EFF="$OUT_DIR/policy.effective.json"
  if [[ ! -f "$POL_EFF" ]]; then
    if [[ -n "$POLICY_JSON" ]]; then printf '%s' "$POLICY_JSON" > "$POL_EFF"
    else bash "$HERE/validate-policy.sh" "$HERE/../policy-defaults.yml" >"$POL_EFF" 2>/dev/null || true; fi
  fi

  # The live version's publish date is the grid origin for the maintenance windows that give
  # Track 3/4 their remediation deadline.
  export MAINTENANCE_LAST_RELEASE="${live_since:-}"
  ASSESS=("$bom" "$POL_EFF" --out-dir "$OUT_DIR")
  [[ -d "$OUT_DIR/soups" ]] && ASSESS+=(--soups "$OUT_DIR/soups")
  [[ -f "$STATE_DIR/state-$name.json" ]] && ASSESS+=(--state "$STATE_DIR/state-$name.json")
  if ! bash "$HERE/assess-bom.sh" "${ASSESS[@]}" >&2; then
    UNSCANNABLE=$(jq -c --arg n "$name" --arg v "$version" \
      '. + [{name:$n, version:$v, why:"assessment failed"}]' <<<"$UNSCANNABLE")
    continue
  fi
  final="$OUT_DIR/$name.assessed.cdx.json"
  cls="$OUT_DIR/$name.findings.json"
  FEEDS=$(jq -c --slurpfile e "$OUT_DIR/$name.enrichment.json" '$e[0].feeds' <<<"$FEEDS")

  # KEV findings, from the classified output: the classifier already applied VEX
  # suppression and the tri-state KEV rule, so re-deriving them here would be a second
  # implementation of the same decision.
  hits=$(jq -c --arg n "$name" --arg v "$version" '
    [ .findings[]
      | select(.kev == "true" or .kev == "unknown")
      | { cve: .id, target: $n, version: $v, track: .track,
          kev_uncertain: (.kev == "unknown"),
          kev_date_added: (.kev_date_added // null),
          ransomware: (.kev_ransomware // false),
          epss: .epss,
          mitigation_due: .mitigation_due, remediation_due: .remediation_due,
          overdue: ((.mitigation_overdue // false) or (.remediation_overdue // false)),
          components: .affects, vex_state: .vex_state } ]' "$cls")

  sup=$(jq -c '[ .suppressed[] | {cve:.id, why:.why} ]' "$cls")
  act="$hits"
  unk=$(jq -c --arg n "$name" '[ .findings[] | select(.kev == "unknown") | {cve:.id, target:$n} ]' "$cls")
  CLASSIFIED=$(jq -c --slurpfile c "$cls" --arg n "$name" '. + [{target:$n, summary:$c[0].summary}]' <<<"$CLASSIFIED")

  FINDINGS=$(jq -c --argjson a "$act" '. + $a' <<<"$FINDINGS")
  SUPPRESSED=$(jq -c --argjson s "$sup" '. + $s' <<<"$SUPPRESSED")
  UNKNOWN=$(jq -c --argjson u "$unk" '. + $u' <<<"$UNKNOWN")
  SCANNED=$(jq -c --arg n "$name" --arg v "$version" --arg tier "$BOM_TIER" \
    --argjson t "$(jq '[.vulnerabilities[]?] | length' "$final")" \
    '. + [{name:$n, version:$v, vulnerabilities:$t,
           # Which kind of document this scan rests on. A staging-tier bundle is the right
           # document when a pre-release tag is what got deployed, but the record has to say
           # so rather than leaving a reader to assume it was the release bundle.
           sbom_tier:$tier}]' <<<"$SCANNED")

  # --- lifecycle and escalation, per target ----------------------------------
  # These used to run once after the loop, on whichever findings file `ls -1t` surfaced
  # first — with two targets, one of them was simply never lifecycle-tracked.
  lc="$OUT_DIR/$name.lifecycle.json"
  LC_ARGS=(--deployed "$cls" --out "$lc")
  [[ -n "${MONITOR_MAIN_BOM:-}" && -f "${MONITOR_MAIN_BOM}" ]] && LC_ARGS+=(--main "$MONITOR_MAIN_BOM")
  [[ -f "$LIFECYCLE_STATE_DIR/lifecycle-state-$name.json" ]] \
    && LC_ARGS+=(--state "$LIFECYCLE_STATE_DIR/lifecycle-state-$name.json")
  [[ -f "$POL_EFF" ]] && LC_ARGS+=(--policy "$POL_EFF")
  if python3 "$HERE/track-lifecycle.py" "${LC_ARGS[@]}" >&2; then
    LIFECYCLES=$(jq -c --arg n "$name" --slurpfile l "$lc" '. + [{target:$n} + $l[0]]' <<<"$LIFECYCLES")
  fi

  esc="$OUT_DIR/$name.escalation.json"
  if [[ -f "$lc" ]]; then
    ESC_ARGS=("$lc" --out "$esc")
    [[ -f "$POL_EFF" ]] && ESC_ARGS+=(--policy "$POL_EFF")
    units="$OUT_DIR/$(basename "${cls%.findings.json}").remediation-units.json"
    [[ -f "$units" ]] && ESC_ARGS+=(--units "$units")
    [[ -f "$DECISIONS_FILE" ]] && ESC_ARGS+=(--decisions "$DECISIONS_FILE")
    if python3 "$HERE/escalate-breaches.py" "${ESC_ARGS[@]}" >&2; then
      ESCALATIONS=$(jq -c --arg n "$name" --slurpfile e "$esc" '. + [{target:$n} + $e[0]]' <<<"$ESCALATIONS")
    fi
  fi
done < <(jq -r '.[] | "\(.name)\t\(.version)\t\(.sbom)\t\(.live_since // "")"' <<<"$TARGETS")

# Merge the per-target results into one product view for the record and the alert. Sums and
# concatenations only — nothing is re-decided here.
LIFECYCLE=""
if [[ "$(jq 'length' <<<"$LIFECYCLES")" != "0" ]]; then
  LIFECYCLE="$OUT_DIR/lifecycle.json"
  jq -c '{
    schema: "quickbird.finding-lifecycle/v1",
    targets: [.[].target],
    summary: {
      total: ([.[].summary.total] | add),
      by_state: (map(.summary.by_state | to_entries) | add | group_by(.key)
                 | map({key: .[0].key, value: (map(.value) | add)}) | from_entries),
      release_required: ([.[].summary.release_required] | add),
      transitions: ([.[].summary.transitions] | add),
      resolved_this_run: ([.[].summary.resolved_this_run] | add)
    },
    release_required: (map(. as $t | .release_required[] | . + {target: $t.target})),
    transitions: (map(. as $t | .transitions[] | . + {target: $t.target}))
  }' <<<"$LIFECYCLES" > "$LIFECYCLE"
fi
ESCALATION=""
if [[ "$(jq 'length' <<<"$ESCALATIONS")" != "0" ]]; then
  ESCALATION="$OUT_DIR/escalation.json"
  jq -c '{
    schema: "quickbird.deadline-escalation/v1",
    targets: [.[].target],
    summary: {
      total: ([.[].summary.total] | add),
      by_level: (map(.summary.by_level | to_entries) | add | group_by(.key)
                 | map({key: .[0].key, value: (map(.value) | add)}) | from_entries)
    },
    escalations: (map(. as $t | .escalations[] | . + {target: $t.target}))
  }' <<<"$ESCALATIONS" > "$ESCALATION"
fi

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
  --arg cadence "$(jq -r '.release_cadence // ""' <<<"${POLICY_JSON:-{\}}" 2>/dev/null)" \
  --arg interval "$(jq -r '.maintenance_interval // ""' <<<"${POLICY_JSON:-{\}}" 2>/dev/null)" \
  --arg onboarded "$(jq -r '.onboarded // ""' <<<"${POLICY_JSON:-{\}}" 2>/dev/null)" \
  --arg tier "$(jq -r '.tier // ""' <<<"${POLICY_JSON:-{\}}" 2>/dev/null)" \
  --argjson prodrel "$(jq -c '.production_release // null' <<<"${POLICY_JSON:-{\}}" 2>/dev/null || echo null)" \
  --argjson classified "$CLASSIFIED" \
  --argjson lifecycle "$( [[ -n "$LIFECYCLE" && -f "$LIFECYCLE" ]] && jq -c '{summary, release_required, transitions}' "$LIFECYCLE" || echo null )" \
  --argjson escalation "$( [[ -n "$ESCALATION" && -f "$ESCALATION" ]] && jq -c '{summary, escalations}' "$ESCALATION" || echo null )" \
  '# `select()` inside an object constructor does not omit the field — it makes the whole
   # construction produce `empty`, and jq then writes nothing at all. That is how a run came to
   # report success and leave a 0-byte evidence record: the policy had `onboarded: ""`. Map blank
   # to null instead; the same mistake was already fixed once elsewhere in this pipeline.
   def blank_to_null: if . == "" then null else . end;
   {
     schema: "quickbird.kev-monitor-run/v1",
     product: $product, repo: $repo, run_at: $at, cra_scope: $cra,
     # Carried so the backstop can check the declared cadence against the actual release
     # history (WI §6.2) without needing the policy file of every project.
     release_cadence: ($cadence | blank_to_null),
     # WI §6.2: the maintenance commitment. The backstop checks the windows against it, and the
     # classifier lands every Track 3/4 finding on the next one.
     maintenance_interval: ($interval | blank_to_null),
     onboarded: ($onboarded | blank_to_null),
     tier: ($tier | blank_to_null),
     # Which releases this product counts as production. Three signals answer that and they
     # disagree on most of the portfolio, so the backstop must not pick one on its own —
     # cadence, and every Track 3/4 deadline derived from it, depends on the answer.
     policy: (if $prodrel == null then null else {production_release: $prodrel} end),
     synthetic: $synthetic,
     feeds: $feeds,
     scanned: $scanned,
     not_scanned: $unscannable,
     kev_findings: $findings,
     kev_suppressed_by_vex: $suppressed,
     kev_membership_unknown: $unknown,
     classification: $classified,
     lifecycle: $lifecycle,
     escalation: $escalation,
     # An all-clear additionally requires that something was actually scanned. A target
     # filter that drops every environment produces empty lists on both sides, and an empty
     # record must read as "nothing was looked at", never as "nothing was found".
     all_clear: (($scanned | length) > 0
                 and ($findings | length) == 0
                 and ($unscannable | length) == 0
                 and ($unknown | length) == 0),
     verdict: (if ($findings | length) > 0 then "kev-findings"
               elif ($scanned | length) == 0 then "incomplete"
               elif ($unscannable | length) > 0 or ($unknown | length) > 0 then "incomplete"
               else "all-clear" end)
   }' > "$RECORD"

# An empty record is the worst outcome available: the run reports success and leaves no evidence
# that the product was looked at, which is exactly what the backstop is supposed to catch and
# cannot if the file exists but is blank.
if [[ ! -s "$RECORD" ]] || ! jq -e . "$RECORD" >/dev/null 2>&1; then
  echo "::error::the run record at $RECORD is empty or not valid JSON — this run produced no" >&2
  echo "::error::  evidence that $PRODUCT was monitored, so it must not be treated as a clean run" >&2
  exit 1
fi

# Carry the classified findings forward, one state file per target. Without this every run
# restarts every clock and latching never happens — the deadlines would look correct and
# mean nothing.
for f in "$OUT_DIR"/*.findings.json; do
  [[ -e "$f" ]] || continue
  n=$(basename "${f%.findings.json}")
  cp "$f" "$STATE_DIR/state-$n.json"
done
for f in "$OUT_DIR"/*.lifecycle.json; do
  [[ -e "$f" ]] || continue
  n=$(basename "${f%.lifecycle.json}")
  cp "$f" "$LIFECYCLE_STATE_DIR/lifecycle-state-$n.json"
done

jq -r '"  verdict: \(.verdict)  (kev=\(.kev_findings|length), suppressed=\(.kev_suppressed_by_vex|length), unknown=\(.kev_membership_unknown|length), not scanned=\(.not_scanned|length))"' "$RECORD" >&2
log "  record: $RECORD"

# --- 4. the alert -----------------------------------------------------------
# Written to a file rather than posted here: posting is the workflow's job, and separating
# them means the message can be inspected in a dry run.
ALERT="$OUT_DIR/alert.txt"

ALERT_ARGS=("$RECORD" "$ALERT")
ALERT_ARGS+=("${ESCALATION:-}" "${LIFECYCLE:-}")
PRODUCT="$PRODUCT" CRA_SCOPE="$CRA_SCOPE" bash "$HERE/compose-alert.sh" "${ALERT_ARGS[@]}"

if [[ -s "$ALERT" ]]; then
  log "  alert written to $ALERT"
  echo "alert=true"
else
  log "  no alert — all clear, record kept as evidence of monitoring"
  echo "alert=false"
fi
