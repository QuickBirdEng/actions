#!/usr/bin/env bash
# Count what a release actually asks of the team, and compare two releases.
#
# The report counts findings, and that number does not survive contact with a team that
# cannot update continuously: osteocoach v1.1.0-qa19 had 76 findings and 10 things anyone
# could do about them. A channel that posts 76 teaches people to stop reading it.
#
# The unit is therefore the remediation unit, not the finding. group-remediation.py already
# establishes that grouping and its docstring carries the measurement that motivated it
# (521 findings -> 2 actions, none of them in code QuickBird writes). This does not redo
# that work; it sorts the units by what they demand:
#
#   act       a bump in an artifact this repository builds, and a fix exists
#   decide    no fix published, or only a prerelease. Needs a VEX statement or a recorded
#             risk acceptance — a decision, not an upgrade
#   external  the artifact is built elsewhere. The lever is a vendor request or a different
#             image, and it does not belong on our sprint board
#   parked    a disposition is already recorded. Visible, not counted as work
#
# Severity deliberately does not appear. It is a property of a vulnerability, not an
# instruction: in the qa17-qa19 series the three loudest findings were CVSS 9.1, 9.3 and 9.8,
# and on the day each arrived none could be acted on — two pinned by a base image we do not
# control, the third a false positive from our own package name.
#
# Input is the assessed BOM, which every release carries as its sbom-<version>.cdx.json
# asset. Not the findings or unit files: those are workflow artefacts and expire, and the
# live column has to work for whatever is deployed, which may be months old.
#
# Usage: summarise-state.sh <bom.cdx.json> <policy.json> [label]        one state, as JSON
#        summarise-state.sh --compare <policy.json> <live.json> <live-label> \
#                                     <qa.json> <qa-label>              the Slack block
# Env:   PYTHON  interpreter that has the cvss module (default python3)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
"$PY" -c 'import cvss' 2>/dev/null || {
  echo "::error::$PY cannot import cvss — classify-findings.py needs it. Set PYTHON to an interpreter that has it." >&2
  exit 1; }

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

# BOM + policy -> the counts, via the pipeline's own classification and grouping. Running
# them rather than reimplementing is the point: a second opinion on what a unit is would
# drift from the report, and then two numbers describe the same release.
classify() {
  local bom="$1" policy="$2" tag="$3"
  [[ -s "$bom" ]]    || { echo "::error::BOM not found or empty: $bom" >&2; return 1; }
  [[ -s "$policy" ]] || { echo "::error::policy not found or empty: $policy" >&2; return 1; }
  "$PY" "$HERE/classify-findings.py" "$bom" "$policy" --out "$WORK/f-$tag.json" >/dev/null 2>&1 || {
    echo "::error::classify-findings failed for $bom" >&2; return 1; }
  "$PY" "$HERE/group-remediation.py" "$WORK/f-$tag.json" "$bom" --out "$WORK/u-$tag.json" >/dev/null 2>&1 || {
    echo "::error::group-remediation failed for $bom" >&2; return 1; }

  jq -c -n --slurpfile f "$WORK/f-$tag.json" --slurpfile u "$WORK/u-$tag.json" '
    ($f[0]) as $F | ($u[0]) as $U
    | ($F.findings // []) as $fs
    # A unit is parked when every finding under it already carries a disposition, and needs a
    # decision when its own text says there is nothing to upgrade to. group-remediation.py
    # writes that text; matching on it keeps the two in step instead of re-deriving the rule.
    | ( [ $fs[] | select(.vex_state != null) | .id ] ) as $disposed
    # The class comes from the unit kind, which group-remediation.py already decides, not
    # from matching its prose. The prose is written for a human reader and will be reworded;
    # the kinds are the vocabulary.
    | ( ($U.units // []) | map(
          . as $unit
          | ( [ ($unit.findings // [])[] ] ) as $ids
          | { action:   ($unit.action // ""),
              kind:     ($unit.kind // "?"),
              artifact: (($unit.artifact // "") | sub("^quickbird:artifact:"; "")),
              label:    ( if ($unit.kind // "") == "base-image-bump" then "bump base image"
                          else (($unit.action // "") | sub("^upgrade "; "") | sub(" in .*$"; "")) end ),
              n:        ($unit.finding_count // ($ids | length)),
              parked:   (($ids | length) > 0
                         and ([ $ids[] | select( . as $i | $disposed | index($i)) ] | length) == ($ids | length)),
              external: (($unit.kind // "") == "third-party-image"),
              decide:   (($unit.kind // "") | IN("no-upgrade-path","no-stable-upgrade-path")) } ) ) as $units
    | ( [ $units[] | select(.parked | not) | select(.external | not) | select(.decide | not) ] ) as $actionable
    | { units_total: ($units | length),
        findings:    ($fs | length),
        parked:      ([ $units[] | select(.parked) ] | length),
        external:    ([ $units[] | select(.parked | not) | select(.external) ] | length),
        decide:      ([ $units[] | select(.parked | not) | select(.external | not) | select(.decide) ] | length),
        act:         ($actionable | length),
        kev:         ([ $fs[] | select(.track == "kev") ] | length),
        overdue:     ([ $fs[] | select(.mitigation_overdue or .remediation_overdue) ] | length),
        # Grouped by artifact, because four of five lines naming the same image is what a
        # reader skips. The finding count rides along per entry: one base-image bump clearing
        # 53 findings and a single jar upgrade are both one line, and only the number says
        # which is which.
        act_by_artifact: ( $actionable
                           | group_by(.artifact)
                           | map({ artifact: .[0].artifact,
                                   findings: (map(.n) | add),
                                   items: (sort_by(-.n) | map("\(.label) (\(.n))")) })
                           | sort_by(-.findings) ) }'
}

# One state, rendered for a reader rather than as JSON. Used when there is nothing to compare
# against — a delta line against the same file would say "unchanged", which is true of any
# file and reads as though the live environment were up to date.
if [[ "${1:-}" == "--render" ]]; then
  BOM="${2:?usage: summarise-state.sh --render <bom> <policy> <label>}"
  POLICY="${3:?policy required}"; LABEL="${4:-state}"
  S=$(classify "$BOM" "$POLICY" "one") || exit 1
  jq -rn --argjson s "$S" --arg l "$LABEL" '
    [ "  \($l)   act \($s.act) · decide \($s.decide) · external \($s.external) · parked \($s.parked)"
      + (if $s.overdue > 0 then "  :alarm_clock: \($s.overdue) overdue" else "" end) ]
    + ( if ($s.act_by_artifact | length) > 0
        then [ "" ] + ( $s.act_by_artifact | map("  • \(.artifact): " + (.items | join(", "))) )
        else [] end )
    | join("\n")'
  exit 0
fi

if [[ "${1:-}" != "--compare" ]]; then
  BOM="${1:?usage: summarise-state.sh <bom.cdx.json> <policy.json> [label]}"
  POLICY="${2:?policy required}"
  classify "$BOM" "$POLICY" "one"
  exit $?
fi

POLICY="${2:?policy required}"
LIVE="${3:?live BOM required}";  LIVE_LABEL="${4:-live}"
QA="${5:?QA BOM required}";      QA_LABEL="${6:-QA}"

L=$(classify "$LIVE" "$POLICY" "live") || exit 1
Q=$(classify "$QA"   "$POLICY" "qa")   || exit 1

jq -rn --argjson a "$L" --argjson b "$Q" --arg la "$LIVE_LABEL" --arg lb "$QA_LABEL" '
  def row($l; $s): "  \($l)   act \($s.act) · decide \($s.decide) · external \($s.external) · parked \($s.parked)"
                   + (if $s.overdue > 0 then "  :alarm_clock: \($s.overdue) overdue" else "" end);
  def d($k): ($b[$k] - $a[$k]);
  def sgn($n): if $n > 0 then "+\($n)" else "\($n)" end;
  [ row($la; $a), row($lb; $b) ]
  + [ ( [ (if d("act")    != 0 then "act \(sgn(d("act")))" else empty end),
          (if d("decide") != 0 then "decide \(sgn(d("decide")))" else empty end),
          (if d("external") != 0 then "external \(sgn(d("external")))" else empty end),
          (if d("parked") != 0 then "parked \(sgn(d("parked")))" else empty end),
          (if d("units_total") != 0 then "actions total \(sgn(d("units_total")))" else empty end) ]
        | if length == 0 then "  -> unchanged since the last state" else "  -> since the last state: " + join(" · ") end ) ]
  + ( if ($b.act_by_artifact | length) > 0
      then [ "" ] + ( $b.act_by_artifact
                      | map("  • \(.artifact): " + (.items | join(", "))) )
      else [] end )
  | join("\n")'
