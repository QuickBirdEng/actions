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

P=$(yq -o=json '.' "$POLICY")   || { echo "::error::$POLICY is not valid YAML" >&2; exit 1; }
D=$(yq -o=json '.' "$DEFAULTS") || { echo "::error::$DEFAULTS is not valid YAML" >&2; exit 1; }

STATUS=0
err() { echo "::error::$*" >&2; STATUS=1; }
warn() { echo "::warning::$*" >&2; }

# --- required fields ---------------------------------------------------------
for f in product tier cra_scope maintenance_interval; do
  # `has` and an explicit null test, not `// ""`. jq's alternative operator treats `false`
  # as absent, so `cra_scope: false` — the value most products will set — would have been
  # reported as missing.
  jq -e --arg f "$f" 'has($f) and .[$f] != null and .[$f] != ""' <<<"$P" >/dev/null 2>&1 \
    || err "$POLICY: '$f' is required and has no safe default"
done

TIER=$(jq -r '.tier // ""' <<<"$P")
if [[ -n "$TIER" ]] && ! jq -e --arg t "$TIER" '.tiers[$t]' <<<"$D" >/dev/null 2>&1; then
  err "$POLICY: tier '$TIER' is not one of: $(jq -r '.tiers | keys | join(", ")' <<<"$D")"
fi

# The tier is not a determination made here — it follows from the customer's SLA, which is also
# where the Basic/Extended vocabulary comes from (GDG-004-01). That makes the value in this file
# a *copy* of a contractual fact, and a copy with no stated origin cannot be checked against the
# thing it copies. Requiring the reference does not stop it drifting; it tells the next reader
# where to look. The backstop reports a tier that changes between runs (determination_drift).
if [[ -n "$TIER" ]] && ! jq -e 'has("tier_source") and .tier_source != null and .tier_source != ""' <<<"$P" >/dev/null 2>&1; then
  warn "$POLICY: tier is '$TIER' but no tier_source is stated. The tier follows from the customer SLA — name the contract or service level it is taken from, so the value can be traced to its source."
fi

CRA=$(jq -r '.cra_scope // ""' <<<"$P")
case "$CRA" in
  true|false|unknown|"") ;;
  *) err "$POLICY: cra_scope must be true, false or unknown — got '$CRA'" ;;
esac
[[ "$CRA" == "unknown" ]] && warn "$POLICY: cra_scope is 'unknown'. Alerts will say so rather than assume. Determine it before 2026-09-11."

# --- maintenance interval vs the tier cap ------------------------------------
# A commitment looser than the tier allows is the one override that cannot be waived with a
# reason: the tier *is* the statement about how often this product is maintained.
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
MI=$(jq -r '.maintenance_interval // ""' <<<"$P")
if [[ -n "$MI" ]]; then
  MI_D=$(to_days "$MI")
  if [[ "$MI_D" == "-99" || "$MI_D" -le 0 ]]; then
    err "$POLICY: maintenance_interval '$MI' is not a duration (e.g. 90d, 3m)"
  elif [[ -n "$TIER" ]]; then
    CAP=$(jq -r --arg t "$TIER" '.tiers[$t].max_maintenance_interval // ""' <<<"$D")
    CAP_D=$(to_days "$CAP")
    if [[ "$CAP_D" -gt 0 && "$MI_D" -gt "$CAP_D" ]]; then
      err "$POLICY: maintenance_interval $MI exceeds the cap for tier $TIER ($CAP). Either commit to maintenance at least every $CAP, or move the product to a tier whose cap it meets — this is not waivable with a reason, because the tier is the statement about how often the product is maintained."
    fi
  fi
fi

# release_cadence was the previous, observation-based field. It set a deadline from a rhythm
# that had already lapsed on most products, so it is replaced rather than kept alongside:
# two fields that approximately mean the same thing eventually disagree.
if jq -e 'has("release_cadence")' <<<"$P" >/dev/null 2>&1; then
  RC=$(jq -r '.release_cadence' <<<"$P")
  if [[ "$RC" == "continuous" ]]; then
    warn "$POLICY: release_cadence: continuous is retained for products that deploy every merge; the maintenance window still applies and is measured against deploys."
  else
    warn "$POLICY: release_cadence ('$RC') is superseded by maintenance_interval (§3.4) and is ignored for deadlines. Remove it once the interval is agreed."
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
for lvl in major minor; do
  dv=$(jq -r --arg l "$lvl" '.dependency_currency.max_behind[$l]' <<<"$D")
  pv=$(jq -r --arg l "$lvl" '.dependency_currency.max_behind[$l] // ""' <<<"$P")
  [[ -z "$pv" || "$pv" == "null" || "$pv" == "unlimited" && "$dv" == "unlimited" ]] && continue
  if [[ "$pv" == "unlimited" ]] || { [[ "$dv" != "unlimited" ]] && (( pv > dv )); }; then
    reason=$(jq -r '.dependency_currency.reason // ""' <<<"$P")
    [[ -n "$reason" ]] \
      && warn "$POLICY: currency $lvl relaxed $dv -> $pv — \"$reason\"" \
      || err "$POLICY: dependency_currency.max_behind.$lvl is $pv against a default of $dv. Add 'reason:' or tighten it."
  fi
done

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
  | .max_maintenance_interval = (($m.tiers[$m.tier].max_maintenance_interval) // null)
  | .backstop = (($m.tiers[$m.tier].backstop) // null)
  | del(.tiers)
  | . + {schema: "quickbird.soup-policy/v1"}')

echo "$EFFECTIVE"

if [[ $STATUS -eq 0 ]]; then
  jq -r '"policy ok: \(.product) · tier \(.tier) · CRA \(.cra_scope) · maintenance every \(.maintenance_interval) · backstop \(.backstop)"' <<<"$EFFECTIVE" >&2
else
  echo "::error::policy validation failed — the effective policy above is what *would* apply; it must not be used until the errors are fixed" >&2
fi
exit $STATUS
