#!/usr/bin/env bash
# Merge the SOUP assessment records into a CycloneDX BOM.
#
# The BOM says *what* ships. The .soups records say what was *decided* about it —
# requirement results, who approved it and under what condition, and (once the VEX layer
# exists) which CVEs are applicable. This joins the two so the release bundle is one
# self-contained document rather than a BOM plus a separate spreadsheet.
#
# The join is also the first thing that has ever checked the two against each other. A
# SOUP record with no matching component means the SOUP list and the actual build
# disagree — either a SOUP was removed and the record left behind, or the BOM is missing
# something. Both are reportable; neither is visible today.
#
# Usage: merge-assessment.sh <bom.cdx.json> <soups-dir> [out.cdx.json]

set -uo pipefail

BOM="${1:?usage: merge-assessment.sh <bom.cdx.json> <soups-dir> [out]}"
SOUPS="${2:?missing .soups directory}"
OUT="${3:-${BOM%.json}.assessed.json}"
STRICT="${ASSESSMENT_STRICT:-false}"   # true => an unmatched SOUP record fails the run

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$BOM" ]]  || { echo "::error::BOM not found: $BOM" >&2; exit 1; }
[[ -d "$SOUPS" ]] || { echo "::error::soups dir not found: $SOUPS" >&2; exit 1; }

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# Collect the records, tagging each with the purl type implied by its directory
# (.soups/npm/... -> pkg:npm). Without that, an npm "common" and a Maven "common" would
# be indistinguishable by name alone.
: > "$TMP/records.jsonl"
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  eco=$(basename "$(dirname "$f")")
  # Store the path relative to the soups dir, not as given. An absolute path would leak
  # the machine layout into the BOM and break byte-comparison between two runs — the same
  # defect class as the scan-path leakage the BOM gate already checks for.
  rel="${f#"$SOUPS"/}"
  jq -c --arg eco "$eco" --arg src "$rel" '. + {_ecosystem:$eco, _source:$src}' "$f" \
    >> "$TMP/records.jsonl" 2>/dev/null \
    || echo "::warning::skipping unparseable SOUP record: $f" >&2
done < <(find "$SOUPS" -name '*.json' -type f | sort)

N_RECORDS=$(wc -l < "$TMP/records.jsonl" | tr -d ' ')
[[ "$N_RECORDS" != "0" ]] || { echo "::error::no SOUP records found under $SOUPS" >&2; exit 1; }

jq -s -c '.' "$TMP/records.jsonl" > "$TMP/records.json"

jq --slurpfile recs "$TMP/records.json" '
  # All defs first: in jq a def must introduce the expression that follows it, so a
  # leading pipe before "def" is a syntax error.

  # Match a record to a component by name and by the *version family* the approval covers.
  #
  # A SOUP approval is not version-specific: the record carries version "1.x.x" and an
  # metadata.input_version ("1.0.1") that is merely the version checked at approval time.
  # Matching on input_version would mean a component at 1.0.2 finds no record, gets no
  # requirement properties, and the record is reported as orphaned — three wrong answers
  # from one wrong join. The family is what the approval is about.
  #
  # "1.x.x" -> any 1.*        "0.9.x" -> any 0.9.*        "1.0.1" -> exactly that
  # For 0.x the minor is the compatibility axis, which is the same convention the existing
  # cve-check.sh uses when it derives a version range.
  def version_matches($pattern; $v):
    ($pattern // "") as $p
    | ($v // "") as $ver
    | if $p == "" or $ver == "" then true
      elif ($p | test("[xX*]")) then
        ( $p | split(".") ) as $pp
        | ( $pp | map(select(test("^[0-9]+$"))) ) as $fixed
        | ( $fixed | join(".") ) as $prefix
        | if $prefix == "" then true else ($ver | startswith($prefix + ".")) or ($ver == $prefix) end
      else $ver == $p
      end;

  def match_record($records; $c):
    $records
    | map(select(
        (.package // "") == ($c.name // "")
        and version_matches(.version; $c.version)
      ))
    | first;

  # One property per requirement, plus the reason when it is not fulfilled.
  def req_props($r):
    ($r.requirements // {}) | to_entries | map(
      [ { name: ("quickbird:soup:req:" + .key + ":fulfilled"),
          value: ((.value.fulfilled // false) | tostring) },
        { name: ("quickbird:soup:req:" + .key + ":description"),
          value: (.value.description // "") } ]
      + ( if (.value.fulfilled // false) == true then []
          else [ { name: ("quickbird:soup:req:" + .key + ":reason"),
                   value: ((.value.reason_if_requirement_not_fulfilled // "") | tostring) } ]
          end )
    ) | add // [];

  # Approval becomes an annotation: subject = the component, annotator = the approver,
  # timestamp = the approval date, text = the condition. Git history is the provenance.
  def approval_annotation($c; $r):
    ($r.metadata.approval // {}) as $a
    | if (($a.by // "") == "") then null
      else
        { "bom-ref": ("quickbird:approval:" + ($c."bom-ref" // $c.name)),
          subjects: [ ($c."bom-ref" // $c.name) ],
          annotator: { individual: { name: $a.by } },
          timestamp: ($a.date // ""),
          text: ( "SOUP approved by " + $a.by
                  + (if (($a.by_url // "") != "") then " (" + $a.by_url + ")" else "" end)
                  + (if (($a.condition // "") != "") then "; condition: " + $a.condition else "" end)
                  + (if (($a.is_temporary // false) == true) then "; TEMPORARY approval" else "" end) ) }
      end;

  def vex_entries($r):
    ($r.vex // {}) | to_entries | map({
      key: .key,
      value: { state: (.value.state // "under_investigation"),
               justification: (.value.justification // null),
               response: (.value.response // null),
               detail: (.value.detail // null) } });

  ($recs[0]) as $records
  | [ .components[]? | { c: ., r: match_record($records; .) } ] as $pairs
  | ( $pairs | map(select(.r != null)) ) as $matched
  | ( [ $matched[].r.package ] | unique ) as $matched_names
  | ( $records | map(select(((.package // "") as $p | ($matched_names | index($p)) == null))) ) as $orphans
  | ( $records | map(select(.vex != null)) | map(vex_entries(.)) | add // [] ) as $all_vex
  | ( $all_vex | from_entries ) as $vexmap

  | .components = ( $pairs | map(
      if .r == null then .c
      else
        # Bind the record before piping into .c — after `.c |` the context is the
        # component, so a bare .r would resolve against the component and silently
        # yield null. That produced approved=false and record=null on a record that
        # matched perfectly.
        .r as $r
        | .c
        | .properties = ( ((.properties // []) + req_props($r)
                           + [ { name: "quickbird:soup:record",   value: ($r._source // "") },
                               # Three states, not a boolean. A temporary approval is written by
                               # soup-temporary-approval-workflow.yml when a requirement is
                               # unfulfilled and has no stated reason: the approver signs it off on
                               # a branch with a recorded justification. That is a provisional
                               # decision, and reporting it as `true` made it read in the evidence
                               # as a full approval — the one reading that would not survive being
                               # asked about. A consumer comparing to "true" now correctly treats
                               # it as not-yet-approved rather than the other way round.
                               { name: "quickbird:soup:approved",
                                 value: (if (($r.metadata.approval.by // "") == "") then "false"
                                         elif (($r.metadata.approval.is_temporary // false) == true) then "temporary"
                                         else "true" end) },
                               { name: "quickbird:soup:approved-family", value: ($r.version // "") } ]
                           + ( if (($r.metadata.approval.is_temporary // false) == true)
                               then [ { name: "quickbird:soup:approval-temporary-reason",
                                        value: ($r.metadata.approval.is_temporary_reason // "no reason recorded") } ]
                               else [] end )
                           + [ 
                               { name: "quickbird:soup:checked-version", value: ($r.metadata.input_version // "") } ]
                           + ( if (($r.risk_refs // []) | length) > 0
                               then ($r.risk_refs | map({name:"quickbird:soup:risk-ref", value:.}))
                               else [] end ))
                          | sort_by(.name, (.value // "")) )
        | ( approval_annotation(.; $r) ) as $ann
        | if $ann != null then .annotations = ((.annotations // []) + [$ann]) else . end
      end ) )

  # VEX lands on vulnerabilities[].analysis.
  | .vulnerabilities = ( [ (.vulnerabilities // [])[]
      | . as $v
      | ($vexmap[$v.id] // null) as $x
      | if $x == null then $v
        else $v + { analysis: (
              { state: $x.state }
              + (if $x.justification != null then {justification: $x.justification} else {} end)
              + (if $x.response      != null then {response: [$x.response]}         else {} end)
              + (if $x.detail        != null then {detail: $x.detail}               else {} end) ) }
        end ] )

  | .metadata.properties = ( ((.metadata.properties // [])
      + [ { name: "quickbird:soup:records-total",    value: ($records | length | tostring) },
          { name: "quickbird:soup:records-matched",  value: ($matched  | length | tostring) },
          { name: "quickbird:soup:records-orphaned", value: ($orphans  | length | tostring) } ]
      + ( $orphans | map({ name: "quickbird:soup:orphaned-record", value: (.package // "?") })) )
      | sort_by(.name, (.value // "")) )

  | . + { _report: {
            records: ($records | length),
            matched: ($matched | length),
            orphaned: ($orphans | map(.package)),
            components_without_record: ($pairs | map(select(.r == null)) | length),
            vex_statements: ($all_vex | length),
            vex_applied: ([ .vulnerabilities[]? | select(.analysis != null) ] | length),
            vulns_without_analysis: ([ .vulnerabilities[]? | select(.analysis == null) ] | map(.id)) } }
' "$BOM" > "$TMP/merged.json" || { echo "::error::merge failed" >&2; exit 1; }

jq 'del(._report)' "$TMP/merged.json" > "$OUT"
REPORT=$(jq -c '._report' "$TMP/merged.json")

jq -r '
  "SOUP assessment merged into '"$(basename "$OUT")"'",
  "  records:      \(.records) (\(.matched) matched to a component)",
  "  components without a SOUP record: \(.components_without_record)  (expected for transitives)",
  "  VEX statements: \(.vex_statements), applied to \(.vex_applied) vulnerabilities"
' <<<"$REPORT" >&2

STATUS=0

# A record that matches nothing means the SOUP list and the build disagree. Nothing
# checks this today, which is exactly why stale records accumulate.
ORPHANS=$(jq -r '.orphaned | length' <<<"$REPORT")
if [[ "$ORPHANS" != "0" ]]; then
  echo "::warning::$ORPHANS SOUP record(s) match no component in the BOM — the SOUP list and the build disagree" >&2
  jq -r '.orphaned[] | "::warning::  orphaned record: \(.)"' <<<"$REPORT" >&2
  [[ "$STRICT" == "true" ]] && STATUS=1
fi

# Fix-or-VEX: every reported vulnerability needs a disposition. Reported here; the
# release gate is what enforces it.
NOANALYSIS=$(jq -r '.vulns_without_analysis | length' <<<"$REPORT")
if [[ "$NOANALYSIS" != "0" ]]; then
  echo "::warning::$NOANALYSIS vulnerability/ies have no VEX analysis — fix-or-VEX is unsatisfied for these" >&2
  jq -r '.vulns_without_analysis[0:10][] | "::warning::  no analysis: \(.)"' <<<"$REPORT" >&2
fi

exit $STATUS
