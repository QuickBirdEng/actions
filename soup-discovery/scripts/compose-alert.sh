#!/usr/bin/env bash
# Compose the Slack alert text for a monitoring run.
#
# Four independent blocks, not one nested tree. Deadlines and the release-required signal
# used to be written only inside the KEV branch, so a breached Track 2 deadline on a finding
# that happened not to be in KEV produced no notification at all — it reached the run record
# and the workflow log and stopped there. WI-006-09: Decide says a breach is escalated in the
# project's Slack channel, so that was the process step silently not happening.
#
# A breach is also not subject to the alert threshold. The threshold decides which *new*
# findings are worth interrupting someone for; a deadline that has already been missed is
# past that question.
#
# Separate from monitor-kev.sh so it can be tested against constructed records. It is the
# kind of branching where a mistake is invisible — the run still succeeds and simply says
# nothing.
#
# Usage: compose-alert.sh <record.json> <alert-out> [escalation.json] [lifecycle.json]
# Env:   PRODUCT, CRA_SCOPE
#        ALERT_SCOPE       new (default) | full — see below
#        ALERT_PREV_STATE  previous alert-state.json, for the item ledger
#        ALERT_ITEMS       where to write this run's ledger (default <alert-out>.items.json)

set -uo pipefail

RECORD="${1:?record.json required}"
ALERT="${2:?output path required}"
ESCALATION="${3:-}"
LIFECYCLE="${4:-}"
PRODUCT="${PRODUCT:-?}"
CRA_SCOPE="${CRA_SCOPE:-unknown}"
SCOPE="${ALERT_SCOPE:-new}"
ITEMS="${ALERT_ITEMS:-$ALERT.items.json}"

: > "$ALERT"
VERDICT=$(jq -r '.verdict' "$RECORD")

# --- what has changed since the last posted message --------------------------
# The daily message carries the delta; the full list rides with the weekly overview
# (ALERT_SCOPE=full). decide-alert.sh cannot do this on its own: each line embeds a live
# countdown ("due in 167h"), so its digest differs every night and its weekly-repeat rule is
# unreachable for any product with an open deadline.
#
# Keyed per target: the same unit in mobile and in Production are two clocks, and collapsing
# them would hide the second one going overdue.
PREV_ITEMS='{}'; SINCE=""
if [[ -n "${ALERT_PREV_STATE:-}" && -f "${ALERT_PREV_STATE:-}" ]]; then
  PREV_ITEMS=$(jq -c '.items // {}' "$ALERT_PREV_STATE" 2>/dev/null) || PREV_ITEMS='{}'
  [[ -n "$PREV_ITEMS" && "$PREV_ITEMS" != "null" ]] || PREV_ITEMS='{}'
  SINCE=$(jq -r '.posted_at // "" | .[0:10]' "$ALERT_PREV_STATE" 2>/dev/null) || SINCE=""
fi

ESC_KEY='"esc:" + (.id|tostring) + "@" + (.target // "-")'
REL_KEY='"rel:" + (.id|tostring) + "@" + (.target // "-")'

esc_open() {
  [[ -n "$ESCALATION" && -f "$ESCALATION" ]] || { echo '[]'; return; }
  jq -c "[ .escalations[] | select(.level==\"undecided\" or .level==\"breached\")
           | . + {key: ($ESC_KEY)} ]" "$ESCALATION" 2>/dev/null || echo '[]'
}
rel_open() {
  [[ -n "$LIFECYCLE" && -f "$LIFECYCLE" ]] || { echo '[]'; return; }
  jq -c "[ .release_required[]? | . + {key: ($REL_KEY)} ]" "$LIFECYCLE" 2>/dev/null || echo '[]'
}

ESC_ALL=$(esc_open)
REL_ALL=$(rel_open)

# Written every run; decide-alert.sh copies it into the state only when the message goes out.
jq -c -n --argjson e "$ESC_ALL" --argjson r "$REL_ALL" '
  ([ $e[] | {key: .key, value: .level} ] + [ $r[] | {key: .key, value: "release-required"} ])
  | from_entries' > "$ITEMS"

# A level change counts as new: undecided -> breached is the transition someone has to see.
select_new() {
  jq -c --argjson prev "$PREV_ITEMS" --arg scope "$SCOPE" --arg fixed "${2:-}" '
    if $scope == "full" then .
    else map(select($prev[.key] != (if $fixed == "" then .level else $fixed end))) end' <<<"$1"
}

if [[ "$VERDICT" == "kev-findings" ]]; then
  {
    echo ":rotating_light: *$PRODUCT: actively exploited vulnerability in the running version*"
    echo ""
    jq -r '.kev_findings[] |
      "• *\(.cve)*  in `\(.target)` @ \(.version)\n" +
      "   in CISA KEV since \(.kev_date_added // "unknown date")" +
      (if .kev_uncertain then " (membership could not be established, treated as KEV)" else "" end) +
      (if .ransomware then "  · known ransomware use" else "" end) +
      (if .epss then "  · EPSS \(.epss)" else "" end) +
      "\n   component: \((.components // []) | join(", ") | .[0:120])"' "$RECORD"
    echo ""
    if [[ "$CRA_SCOPE" == "true" ]]; then
      echo ":warning: This product is in CRA scope. An actively exploited vulnerability is reportable *within 24 hours*."
    elif [[ "$CRA_SCOPE" == "false" ]]; then
      # Deliberately not "no reporting obligation". CRA Art. 2(2) exempts MDR/IVDR devices, but
      # MDR Art. 87 vigilance still applies on its own terms. Telling someone at 3am that nothing
      # is reportable would be the one wrong answer with a legal consequence.
      echo "_Not in CRA scope, so no CRA reporting deadline. That is *not* the same as nothing being reportable: MDR Art. 87 vigilance applies on its own terms. Check the product's reporting obligations rather than assuming there are none. Still Track 1: act immediately._"
    else
      echo ":question: *CRA scope for this product is not recorded.* Determine it before assuming the 24-hour clock does not apply."
    fi
    echo ""
    # No hardcoded durations here: the 72h/21d that used to be in this sentence had already
    # drifted from the revised policy (30d). The dated deadlines per finding are in the lines
    # above, straight from the record.
    echo "Classification: KEV is Track 1 unconditionally. The dated deadlines above come from the policy, and the remediation clock stops only on deploy."
  } >> "$ALERT"
fi

# --- breached deadlines, whatever the verdict --------------------------------
ESC_SHOW=$(select_new "$ESC_ALL")
if [[ "$(jq 'length' <<<"$ESC_SHOW")" != "0" ]]; then
  BR=$(jq '[.[] | select(.level=="breached")] | length' <<<"$ESC_SHOW")
  UD=$(jq '[.[] | select(.level=="undecided")] | length' <<<"$ESC_SHOW")
  OPEN=$(jq 'length' <<<"$ESC_ALL")
  {
    [[ -s "$ALERT" ]] && echo ""
    if [[ "$SCOPE" == "full" ]]; then
      [[ ! -s "$ALERT" ]] && echo ":alarm_clock: *$PRODUCT: missed remediation deadlines*" && echo ""
      echo ":alarm_clock: *Deadlines*: $BR breached, $UD past the decision period with nothing on record:"
    else
      [[ ! -s "$ALERT" ]] && echo ":alarm_clock: *$PRODUCT: deadlines that changed${SINCE:+ since $SINCE}*" && echo ""
      echo ":alarm_clock: *Deadlines, new or escalated*: $BR breached, $UD past the decision period:"
    fi
    jq -r '.[] | "   • \(.id)\(if .target then " (" + .target + ")" else "" end) [\(.level)] \(.detail[-1])"' <<<"$ESC_SHOW"
    # Without this a three-line delta reads as "three problems open".
    [[ "$SCOPE" != "full" ]] && echo "_$OPEN open in total. The full list goes out with the weekly overview._"
    [[ "$UD" != "0" ]] && echo "_The work instruction requires a recorded decision in .soup-decisions.yml: a revised date, or a risk acceptance._"
  } >> "$ALERT"
fi

# --- release-required (WI-006-09: Notification), whatever the verdict ---------------------------
REL_SHOW=$(select_new "$REL_ALL" "release-required")
if [[ "$(jq 'length' <<<"$REL_SHOW")" != "0" ]]; then
  RR=$(jq 'length' <<<"$REL_SHOW")
  OPEN_RR=$(jq 'length' <<<"$REL_ALL")
  {
    [[ -s "$ALERT" ]] && echo ""
    [[ ! -s "$ALERT" ]] && echo ":package: *$PRODUCT: an out-of-band release is required*" && echo ""
    echo ":package: *Release required*: $RR finding(s) are fixed in a later build but not yet live:"
    # Same CVE in two environments is two entries; without the target they render identically.
    jq -r '.[] | "   • \(.id)\(if .target then " (" + .target + ")" else "" end): \(.why)"' <<<"$REL_SHOW"
    [[ "$SCOPE" != "full" ]] && echo "_$OPEN_RR awaiting release in total._"
    AGAINST=$( [[ -n "$LIFECYCLE" && -f "$LIFECYCLE" ]] && jq -r '.compared_against // ""' "$LIFECYCLE" )
    [[ -n "$AGAINST" ]] && echo "_Compared against \`$AGAINST\`, which is a snapshot at that tag: anything merged after it is not counted here._"
    echo "_A merged fix does not stop the remediation clock. Only a deploy does._"
  } >> "$ALERT"
fi

# --- the standing overview ---------------------------------------------------
# Appended last, so the blocks above keep the top of the message: those are interruptions,
# this is the worklist. Optional — a monitoring run with no OVERVIEW passed behaves exactly
# as before, which keeps the daily KEV path unchanged while the weekly message carries the
# table.
#
# It also posts on its own. A run where nothing is exploited, nothing is overdue and no
# release is required produces no alert blocks at all, and before this that meant silence:
# the standing state was only ever visible in the report nobody opens between releases.
if [[ -n "${OVERVIEW:-}" && -s "${OVERVIEW:-}" ]]; then
  {
    [[ -s "$ALERT" ]] && echo ""
    echo ":bar_chart: *$PRODUCT: where the work stands*"
    echo ""
    cat "$OVERVIEW"
    echo ""
    echo "_act: a bump in an artifact we build · decide: no fix published, needs a VEX statement or a recorded acceptance · external: built elsewhere, the lever is a vendor request · parked: a disposition is already on record._"
  } >> "$ALERT"
fi

if [[ "$VERDICT" == "incomplete" ]]; then
  {
    [[ -s "$ALERT" ]] && echo ""
    echo ":warning: *$PRODUCT: the KEV check could not be completed*"
    echo ""
    echo "This is not an all-clear. Something could not be established:"
    jq -r '.not_scanned[]? | "• `\(.name // "?")` @ \(.version // "?"): \(.why)"' "$RECORD"
    U=$(jq -r '.kev_membership_unknown | length' "$RECORD")
    [[ "$U" != "0" ]] && echo "• KEV membership unknown for $U vulnerability/ies, the catalog could not be read"
    echo ""
    echo "_Absence of a KEV finding here is not evidence that none exists._"
  } >> "$ALERT"
fi

