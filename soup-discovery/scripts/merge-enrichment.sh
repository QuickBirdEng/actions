#!/usr/bin/env bash
# Merge a KEV/EPSS enrichment document into a BOM's vulnerabilities.
#
# Consumes the output of the kev-epss-enrichment action (DEV-192) and writes:
#   - quickbird:vuln:kev             on vulnerabilities in the KEV catalog
#   - an additional rating           carrying the EPSS score (scoreMethod "other")
#   - the feed provenance            into metadata.properties
#
# The provenance is not decoration. CISA publishes only the *current* KEV catalog, so a
# released bundle that does not record which catalogVersion it used cannot have its KEV
# verdicts reconstructed later. EPSS scores are not comparable across model versions
# either, so the model version travels with the score.
#
# Usage: merge-enrichment.sh <bom.cdx.json> <cve-enrichment.json> [out.cdx.json]

set -uo pipefail

BOM="${1:?usage: merge-enrichment.sh <bom> <enrichment> [out]}"
ENRICH="${2:?missing enrichment json}"
OUT="${3:-${BOM%.json}.enriched.json}"

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }
[[ -f "$BOM" ]]    || { echo "::error::BOM not found: $BOM" >&2; exit 1; }
[[ -f "$ENRICH" ]] || { echo "::error::enrichment not found: $ENRICH" >&2; exit 1; }

jq -e '.schema == "quickbird.cve-enrichment/v1"' "$ENRICH" >/dev/null 2>&1 \
  || { echo "::error::$ENRICH is not a quickbird.cve-enrichment/v1 document" >&2; exit 1; }

# A stale enrichment must not silently become release evidence.
if [[ "$(jq -r '.stale' "$ENRICH")" == "true" ]]; then
  echo "::warning::enrichment is marked stale — at least one feed came from cache rather than a refresh" >&2
fi

jq --slurpfile e "$ENRICH" '
  ($e[0]) as $enr
  | ($enr.cves // {}) as $cves

  | .vulnerabilities = ( [ (.vulnerabilities // [])[]
      | . as $v
      | ($cves[$v.id] // null) as $c
      | if $c == null then $v
        else
          $v
          # kev is tri-state: true, false (checked, absent), null (feed unreachable).
          # Only emit the property when something was actually established — an absent
          # property is honest, "kev=false" from an unreachable feed is not.
          | ( if $c.kev == true then
                .properties = ((.properties // []) + [{name:"quickbird:vuln:kev", value:"true"}])
              elif $c.kev == null then
                .properties = ((.properties // []) + [{name:"quickbird:vuln:kev", value:"unknown"}])
              else . end )
          | ( if $c.kev == true and ($c.kev_date_added // "") != "" then
                .properties = ((.properties // []) + [{name:"quickbird:vuln:kev-date-added", value:$c.kev_date_added}])
              else . end )
          | ( if $c.kev == true and ($c.kev_ransomware // "") == "Known" then
                .properties = ((.properties // []) + [{name:"quickbird:vuln:kev-ransomware", value:"true"}])
              else . end )
          # EPSS as an extra rating rather than a property: it is a score, and CycloneDX
          # models multiple scoring methods on one vulnerability.
          | ( if $c.epss != null then
                .ratings = ((.ratings // []) + [{
                  source: {name: "EPSS"},
                  score: $c.epss,
                  method: "other",
                  justification: ("EPSS " + ($enr.feeds.epss.model_version // "unknown")
                                  + ", percentile " + (($c.epss_percentile // 0) | tostring)) }])
              else . end )
          | .properties = ((.properties // []) | sort_by(.name, (.value // "")))
        end ] )

  | .metadata.properties = ( ((.metadata.properties // [])
      + [ {name:"quickbird:vuln:kev-catalog-version",  value: (($enr.feeds.kev.catalog_version // "unavailable") | tostring)},
          {name:"quickbird:vuln:epss-model-version",   value: (($enr.feeds.epss.model_version  // "unavailable") | tostring)},
          {name:"quickbird:vuln:epss-score-date",      value: (($enr.feeds.epss.score_date     // "unavailable") | tostring)},
          {name:"quickbird:vuln:enrichment-stale",     value: (($enr.stale // false) | tostring)} ] )
      | sort_by(.name, (.value // "")) )
' "$BOM" > "$OUT" || { echo "::error::merge failed" >&2; exit 1; }

TOTAL=$(jq '[.vulnerabilities[]?] | length' "$OUT")
KEV=$(jq '[.vulnerabilities[]? | select(.properties[]? | .name=="quickbird:vuln:kev" and .value=="true")] | length' "$OUT")
EPSS=$(jq '[.vulnerabilities[]? | select(.ratings[]? | .source.name=="EPSS")] | length' "$OUT")
HIGH=$(jq '[.vulnerabilities[]? | select(.ratings[]? | .source.name=="EPSS" and .score >= 0.1)] | length' "$OUT")

{
  echo "enrichment merged into $(basename "$OUT")"
  echo "  $TOTAL vulnerabilities: $KEV in KEV, $EPSS with an EPSS score, $HIGH at EPSS >= 0.10"
  echo "  KEV catalog $(jq -r '.feeds.kev.catalog_version // "unavailable"' "$ENRICH"), EPSS $(jq -r '.feeds.epss.model_version // "unavailable"' "$ENRICH")"
} >&2

# KEV membership is the one signal that is unconditionally Track 1 in the classification,
# so surface it here rather than leaving it to be discovered in the JSON.
if [[ "$KEV" != "0" ]]; then
  echo "::warning::$KEV vulnerability/ies are in the CISA KEV catalog — actively exploited, Track 1 regardless of CVSS" >&2
  jq -r '.vulnerabilities[]? | select(.properties[]? | .name=="quickbird:vuln:kev" and .value=="true") | "::warning::  KEV: \(.id)"' "$OUT" >&2
fi
