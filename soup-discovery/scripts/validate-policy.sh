#!/usr/bin/env bash
# Validate a project's .soup-policy.yml against the process defaults and emit the effective
# policy as JSON for the consumers to read.
#
# Two properties make this more than a config loader:
#
#   1. Fields with no safe default are required. cra_scope and release_cadence cannot be
#      guessed: assuming "not in CRA scope" is the one wrong answer with a legal
#      consequence, and a missing cadence would produce a Track 3 deadline that only looks
#      like one. Missing means the run fails, not that a default appears.
#
#   2. A loosened value needs a stated reason. Overriding a deadline to be *longer* than the
#      process default, or an EPSS threshold to be *higher* (so fewer findings escalate), is
#      allowed — projects differ — but only with a `reason`. Without that rule
#      "configurable per project" is just another way of saying the process is advisory.
#      Tightening never needs a reason.
#
# Usage: validate-policy.sh <.soup-policy.yml> [policy-defaults.yml]
# Writes the effective policy to stdout; diagnostics to stderr; exit 1 on any violation.

set -uo pipefail

POLICY="${1:?usage: validate-policy.sh <.soup-policy.yml> [defaults.yml]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULTS="${2:-$HERE/../policy-defaults.yml}"

for t in yq jq; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
[[ -f "$POLICY" ]]   || { echo "::error::no policy file at $POLICY — every product needs one" >&2; exit 1; }
[[ -f "$DEFAULTS" ]] || { echo "::error::defaults not found at $DEFAULTS" >&2; exit 1; }

# Every script here uses mikefarah yq v4 syntax (-o=json). The python yq is a different
# tool with the same name; its failure mode is a confusing parse error deep in a run, so
# the variant is checked once, here, where every consumer already passes through.
yq --version 2>&1 | grep -q "mikefarah" \
  || { echo "::error::yq on this runner is not mikefarah yq v4 — install it; the python yq is a different tool with the same name" >&2; exit 1; }

P=$(yq -o=json '.' "$POLICY")   || { echo "::error::$POLICY is not valid YAML" >&2; exit 1; }
D=$(yq -o=json '.' "$DEFAULTS") || { echo "::error::$DEFAULTS is not valid YAML" >&2; exit 1; }

STATUS=0
err() { echo "::error::$*" >&2; STATUS=1; }
warn() { echo "::warning::$*" >&2; }

# --- unknown keys ---------------------------------------------------------------
# A typo in an override is worse than a missing one: `mitigaton:` simply does nothing, the
# operator believes a stricter value applies, and no error ever says otherwise. Everything
# a project may set is named here; anything else fails.
KNOWN_TOP='["process_version","product","cra_scope","regulatory_scope","maintenance_interval","reconciliation_interval","onboarded","baseline_clocks_start","epss","tracks","breach","production_release","dependency_currency","alerts","release_cadence"]'
UNKNOWN=$(jq -r --argjson known "$KNOWN_TOP" 'keys - $known | join(", ")' <<<"$P")
[[ -n "$UNKNOWN" ]] && err "$POLICY: unknown key(s): $UNKNOWN — a misspelled override silently does nothing, so unknown keys are refused"
for spec in \
  'tracks:.tracks // {} | [.[] | keys[]] | unique:["mitigation","remediation","reason"]' \
  'epss:.epss // {} | keys:["elevated","high","reason"]' \
  'dependency_currency:.dependency_currency // {} | keys:["max_behind","stale_after","stale_exempt_publishers","obsolescence_may_be_accepted","reason"]' \
  'dependency_currency.max_behind:.dependency_currency.max_behind // {} | keys:["major","minor","patch"]' \
  'alerts:.alerts // {} | keys:["threshold","slack_channel"]' \
  'breach:.breach // {} | keys:["decision_within","risk_acceptance_approvers"]' \
  'production_release:.production_release // {} | keys:["tag_pattern"]'; do
  name="${spec%%:*}"; rest="${spec#*:}"; expr="${rest%:*}"; allowed="${rest##*:}"
  U=$(jq -r --argjson a "$allowed" "[$expr] | flatten - \$a | join(\", \")" <<<"$P" 2>/dev/null)
  [[ -n "$U" ]] && err "$POLICY: unknown key(s) under $name: $U"
done
# tracks may only name the five tracks
U=$(jq -r '.tracks // {} | keys - ["kev","immediate","expedited","planned","monitor"] | join(", ")' <<<"$P")
[[ -n "$U" ]] && err "$POLICY: unknown track(s): $U — the tracks are kev, immediate, expedited, planned, monitor"

# --- required fields ---------------------------------------------------------
for f in product cra_scope maintenance_interval; do
  # `has` and an explicit null test, not `// ""`. jq's alternative operator treats `false`
  # as absent, so `cra_scope: false` — the value most products will set — would have been
  # reported as missing.
  jq -e --arg f "$f" 'has($f) and .[$f] != null and .[$f] != ""' <<<"$P" >/dev/null 2>&1 \
    || err "$POLICY: '$f' is required and has no safe default"
done

# cra_scope, maintenance_interval and reconciliation_interval are agreed with the customer in
# the SLA and written here. They are not determined by this process. Deliberately NOT accompanied by a reference
# field: a pointer to a contract version in a YAML file goes stale the first time the SLA is
# amended, and then it asserts a provenance that no longer holds, which is worse than none. The
# controls that actually work here are the CODEOWNERS review on this file and the backstop
# reporting any of the three changing between runs.

CRA=$(jq -r '.cra_scope // ""' <<<"$P")
case "$CRA" in
  true|false|unknown|"") ;;
  *) err "$POLICY: cra_scope must be true, false or unknown — got '$CRA'" ;;
esac
[[ "$CRA" == "unknown" ]] && warn "$POLICY: cra_scope is 'unknown'. Alerts will say so rather than assume. Determine it before 2026-09-11."

# --- the two SLA intervals must be durations ---------------------------------
# No upper bound is enforced. What a product commits to is the SLA's business, and a value that
# is too loose is caught by the CODEOWNERS review on this file rather than by a rule here.
to_days() {
  case "$1" in
    ""|null) echo "-1" ;;
    *d)      echo "${1%d}" ;;
    *m)      echo $(( ${1%m} * 30 )) ;;
    *y)      echo $(( ${1%y} * 365 )) ;;
    *[!0-9]*) echo "-99" ;;
    *)       echo "$1" ;;
  esac
}
for f in maintenance_interval reconciliation_interval; do
  V=$(jq -r --arg f "$f" '.[$f] // ""' <<<"$P")
  [[ -z "$V" ]] && continue
  V_D=$(to_days "$V")
  if [[ "$V_D" == "-99" || "$V_D" -le 0 ]]; then
    err "$POLICY: $f '$V' is not a duration (e.g. 90d, 3m)"
  fi
done

# release_cadence was the previous, observation-based field. It set a deadline from a rhythm
# that had already lapsed on most products, so it is replaced rather than kept alongside:
# two fields that approximately mean the same thing eventually disagree.
if jq -e 'has("release_cadence")' <<<"$P" >/dev/null 2>&1; then
  RC=$(jq -r '.release_cadence' <<<"$P")
  if [[ "$RC" == "continuous" ]]; then
    warn "$POLICY: release_cadence: continuous is retained for products that deploy every merge; the maintenance window still applies and is measured against deploys."
  else
    warn "$POLICY: release_cadence ('$RC') is superseded by maintenance_interval (WI-006-09-01: The maintenance window) and is ignored for deadlines. Remove it once the interval is agreed."
  fi
fi

# --- regulatory scope tightens the currency policy ---------------------------
# TR-03161 O.TrdP_2 requires the newest version or the one preceding it. The process default
# tolerates unlimited patch drift, which does not meet that, so a product in TR-03161 scope must
# state a patch limit. Enforced rather than documented: a requirement that only appears in prose is
# a requirement nobody applies.
SCOPE=$(jq -r '[.regulatory_scope // [] | .[]] | join(",")' <<<"$P" 2>/dev/null)
for entry in $(tr ',' ' ' <<<"$SCOPE"); do
  case "$entry" in
    tr-03161-1|tr-03161-2|tr-03161-3|cra|mdr) ;;
    *) err "$POLICY: regulatory_scope entry '$entry' is not one of tr-03161-1, tr-03161-2, tr-03161-3, cra, mdr" ;;
  esac
done
if [[ "$SCOPE" == *tr-03161* ]]; then
  # The project value if it sets one, otherwise the process default.
  PATCH=$(jq -r '.dependency_currency.max_behind.patch // ""' <<<"$P")
  [[ -z "$PATCH" || "$PATCH" == "null" ]] && PATCH=$(jq -r '.dependency_currency.max_behind.patch // ""' <<<"$D")
  if [[ "$PATCH" == "unlimited" || -z "$PATCH" ]]; then
    err "$POLICY: regulatory_scope includes TR-03161, whose O.TrdP_2 requires third-party software to be the newest version or the one preceding it. dependency_currency.max_behind.patch is '$PATCH', which permits unlimited patch drift. Set a patch limit (1 meets O.TrdP_2)."
  fi
  if jq -e '.dependency_currency.obsolescence_may_be_accepted == true' <<<"$P" >/dev/null 2>&1; then
    err "$POLICY: regulatory_scope includes TR-03161, whose O.TrdP_8 states that third-party software which is no longer maintained MUST NOT be used. obsolescence_may_be_accepted is therefore not available for this product; the answer is replacement."
  fi
fi

# --- durations ---------------------------------------------------------------
# to_hours: 72h -> 72, 21d -> 504, none/next-release -> sentinels
to_hours() {
  case "$1" in
    ""|null)        echo "-1" ;;
    none)           echo "-2" ;;
    next-release)   echo "-3" ;;
    *h)             echo "${1%h}" ;;
    *d)             echo $(( ${1%d} * 24 )) ;;
    *)              echo "-99" ;;
  esac
}

# --- deadlines: longer than the default needs a reason -----------------------
for track in kev immediate expedited planned monitor; do
  for clock in mitigation remediation; do
    dv=$(jq -r --arg t "$track" --arg c "$clock" '.tracks[$t][$c] // ""' <<<"$D")
    pv=$(jq -r --arg t "$track" --arg c "$clock" '.tracks[$t][$c] // ""' <<<"$P")
    [[ -z "$pv" || "$pv" == "null" ]] && continue      # not overridden

    dh=$(to_hours "$dv"); ph=$(to_hours "$pv")
    if [[ "$ph" == "-99" ]]; then
      err "$POLICY: tracks.$track.$clock = '$pv' is not a duration (expected e.g. 72h, 21d, next-release, none)"
      continue
    fi
    # Only compare when both are real durations. next-release/none are not orderable.
    if [[ "$dh" -ge 0 && "$ph" -ge 0 && "$ph" -gt "$dh" ]]; then
      reason=$(jq -r --arg t "$track" '.tracks[$t].reason // ""' <<<"$P")
      if [[ -z "$reason" ]]; then
        err "$POLICY: tracks.$track.$clock is $pv, longer than the process default $dv, with no reason. Add a 'reason:' under tracks.$track, or tighten it."
      else
        warn "$POLICY: tracks.$track.$clock relaxed $dv -> $pv — \"$reason\""
      fi
    elif [[ "$dh" -ge 0 && "$ph" -ge 0 && "$ph" -lt "$dh" ]]; then
      warn "$POLICY: tracks.$track.$clock tightened $dv -> $pv"
    fi
  done
done

# --- EPSS: higher threshold means fewer escalations, so it is a relaxation ---
for k in elevated high; do
  dv=$(jq -r --arg k "$k" '.epss[$k]' <<<"$D")
  pv=$(jq -r --arg k "$k" '.epss[$k] // ""' <<<"$P")
  [[ -z "$pv" || "$pv" == "null" ]] && continue
  if awk -v a="$pv" -v b="$dv" 'BEGIN{exit !(a>b)}'; then
    reason=$(jq -r '.epss.reason // ""' <<<"$P")
    [[ -n "$reason" ]] \
      && warn "$POLICY: epss.$k raised $dv -> $pv — \"$reason\"" \
      || err "$POLICY: epss.$k is $pv, higher than the default $dv, so fewer findings escalate. Add 'reason:' under epss, or lower it."
  fi
done

# --- currency: more slack than the default needs a reason --------------------
for lvl in major minor patch; do
  dv=$(jq -r --arg l "$lvl" '.dependency_currency.max_behind[$l]' <<<"$D")
  pv=$(jq -r --arg l "$lvl" '.dependency_currency.max_behind[$l] // ""' <<<"$P")
  [[ -z "$pv" || "$pv" == "null" || "$pv" == "unlimited" && "$dv" == "unlimited" ]] && continue
  # Both values numeric before an arithmetic compare — (( )) on a non-number is a silent
  # no-op under this shell configuration, which would let an invalid value through unflagged.
  if [[ "$pv" != "unlimited" ]] && ! [[ "$pv" =~ ^[0-9]+$ ]]; then
    err "$POLICY: dependency_currency.max_behind.$lvl is '$pv' — expected a number or 'unlimited'"
    continue
  fi
  if [[ "$pv" == "unlimited" ]] || { [[ "$dv" != "unlimited" ]] && (( pv > dv )); }; then
    reason=$(jq -r '.dependency_currency.reason // ""' <<<"$P")
    [[ -n "$reason" ]] \
      && warn "$POLICY: currency $lvl relaxed $dv -> $pv — \"$reason\"" \
      || err "$POLICY: dependency_currency.max_behind.$lvl is $pv against a default of $dv. Add 'reason:' or tighten it."
  fi
done

# --- currency: an added staleness exemption is a widening ---------------------
# Adding a publisher here stops a class of findings from asking for a decision, so it goes
# the same way as any other relaxation: allowed, but only with a reason on record.
if jq -e '.dependency_currency | has("stale_exempt_publishers")' <<<"$P" >/dev/null 2>&1; then
  if ! jq -e '.dependency_currency.stale_exempt_publishers | type == "array"' <<<"$P" >/dev/null 2>&1; then
    err "$POLICY: dependency_currency.stale_exempt_publishers must be a list of publisher identities"
  else
    ADDED=$(jq -r --argjson d "$(jq -c '.dependency_currency.stale_exempt_publishers // []' <<<"$D")" \
      '[.dependency_currency.stale_exempt_publishers[]] - $d | join(", ")' <<<"$P")
    if [[ -n "$ADDED" ]]; then
      reason=$(jq -r '.dependency_currency.reason // ""' <<<"$P")
      [[ -n "$reason" ]] \
        && warn "$POLICY: staleness exemption extended to $ADDED — \"$reason\"" \
        || err "$POLICY: dependency_currency.stale_exempt_publishers adds $ADDED beyond the process default. An exemption means those components never ask for a decision. Add 'reason:' under dependency_currency, or remove them."
    fi
  fi
fi

# --- alerts ------------------------------------------------------------------
CH=$(jq -r '.alerts.slack_channel // ""' <<<"$P")
[[ -n "$CH" ]] || warn "$POLICY: no alerts.slack_channel — runs will still write their record, but nobody is notified"

# --- effective policy --------------------------------------------------------
# Deep merge: project over defaults. Emitted even on failure so a caller can see what would
# have applied, but the exit code is what decides whether it may be used.
EFFECTIVE=$(jq -n --argjson d "$D" --argjson p "$P" '
  def deepmerge($a; $b):
    reduce ($b | keys_unsorted[]) as $k
      ($a; if ($a[$k] | type) == "object" and ($b[$k] | type) == "object"
           then .[$k] = deepmerge($a[$k]; $b[$k])
           else .[$k] = $b[$k] end);
  deepmerge($d; $p)
  | . as $m
  | . + {schema: "quickbird.soup-policy/v1"}')

echo "$EFFECTIVE"

if [[ $STATUS -eq 0 ]]; then
  jq -r '"policy ok: \(.product) · CRA \(.cra_scope) · maintenance every \(.maintenance_interval) · reconciliation every \(.reconciliation_interval)"' <<<"$EFFECTIVE" >&2
else
  echo "::error::policy validation failed — the effective policy above is what *would* apply; it must not be used until the errors are fixed" >&2
fi
exit $STATUS
