#!/usr/bin/env bash
# Compose the Slack alert text for a monitoring run.
#
# Four independent blocks, not one nested tree. Deadlines and the release-required signal
# used to be written only inside the KEV branch, so a breached Track 2 deadline on a finding
# that happened not to be in KEV produced no notification at all — it reached the run record
# and the workflow log and stopped there. §3.3 step 1 says a breach is escalated in the
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

set -uo pipefail

RECORD="${1:?record.json required}"
ALERT="${2:?output path required}"
ESCALATION="${3:-}"
LIFECYCLE="${4:-}"
PRODUCT="${PRODUCT:-?}"
CRA_SCOPE="${CRA_SCOPE:-unknown}"

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
      # Deliberately not "no reporting obligation". CRA Art. 2(2) exempts MDR/IVDR devices, but
      # the Commission proposal of 2025-12-16 would put the same actively-exploited-vulnerability
      # reporting duty into MDR/IVDR Annex I instead — reaching the device through the MDR rather
      # than through the CRA. Telling someone at 3am that nothing is reportable would be the one
      # wrong answer with a legal consequence.
      echo "_Not in CRA scope, so no CRA reporting deadline. That is *not* the same as nothing being reportable: MDR Art. 87 vigilance applies on its own terms, and the MDR/IVDR proposal of 2025-12-16 would add the same actively-exploited-vulnerability reporting via MDR Annex I. Check the product's reporting obligations rather than assuming there are none. Still Track 1: act immediately._"
    else
      echo ":question: *CRA scope for this product is not recorded.* Determine it before assuming the 24-hour clock does not apply."
    fi
    echo ""
    echo "Classification: KEV is Track 1 unconditionally — mitigation 72 h, remediation 21 d, and the remediation clock stops only on deploy."
  } >> "$ALERT"
fi

# --- breached deadlines, whatever the verdict --------------------------------
if [[ -n "$ESCALATION" && -f "$ESCALATION" ]]; then
  UD=$(jq -r '.summary.by_level.undecided // 0' "$ESCALATION")
  BR=$(jq -r '.summary.by_level.breached // 0' "$ESCALATION")
  if [[ "$UD" != "0" || "$BR" != "0" ]]; then
    {
      [[ -s "$ALERT" ]] && echo ""
      [[ ! -s "$ALERT" ]] && echo ":alarm_clock: *$PRODUCT — missed remediation deadlines*" && echo ""
      echo ":alarm_clock: *Deadlines* — $BR breached, $UD breached with no valid decision on record:"
      jq -r '.escalations[] | select(.level=="undecided" or .level=="breached")
             | "   • \(.id) [\(.level)] \(.detail[-1])"' "$ESCALATION"
      [[ "$UD" != "0" ]] && echo "_§3.3 requires a recorded decision — a revised date or a risk acceptance — in .soup-decisions.yml._"
    } >> "$ALERT"
  fi
fi

# --- release-required (§3.2), whatever the verdict ---------------------------
if [[ -n "$LIFECYCLE" && -f "$LIFECYCLE" ]]; then
  RR=$(jq -r '.summary.release_required' "$LIFECYCLE")
  if [[ "$RR" != "0" && -n "$RR" && "$RR" != "null" ]]; then
    {
      [[ -s "$ALERT" ]] && echo ""
      [[ ! -s "$ALERT" ]] && echo ":package: *$PRODUCT — an out-of-band release is required*" && echo ""
      echo ":package: *Release required* — $RR finding(s) are fixed in main but not yet live:"
      jq -r '.release_required[] | "   • \(.id) — \(.why)"' "$LIFECYCLE"
      echo "_A merged fix does not stop the remediation clock. Only a deploy does._"
    } >> "$ALERT"
  fi
fi

if [[ "$VERDICT" == "incomplete" ]]; then
  {
    [[ -s "$ALERT" ]] && echo ""
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

