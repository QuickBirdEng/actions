#!/usr/bin/env bash
# Find known vulnerabilities for the components of a BOM, via the OSV batch API.
#
# Joins on purl, never on CPE. syft generates large numbers of guessed cpe23 variants and
# matching on those produces phantom findings — the normalisation step strips them for
# exactly this reason.
#
# Writes the vulnerabilities[] array back into the BOM so the document stays
# self-contained. CVSS comes from the advisory; KEV and EPSS are added separately by the
# enrichment step, and the VEX analysis by merge-assessment.sh.
#
# Usage: scan-vulns.sh <bom.cdx.json> [out.cdx.json]

set -uo pipefail

BOM="${1:?usage: scan-vulns.sh <bom.cdx.json> [out]}"
OUT="${2:-${BOM%.json}.vulns.json}"
BATCH="${OSV_BATCH_SIZE:-100}"
OSV="${OSV_API:-https://api.osv.dev}"

for t in jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
[[ -f "$BOM" ]] || { echo "::error::BOM not found: $BOM" >&2; exit 1; }

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# purl -> bom-ref, so a finding can be traced back to the component that carries it
jq -r '[.components[]? | select(.purl != null) | {purl, ref: ."bom-ref"}] | unique_by(.purl) | .[] | "\(.purl)\t\(.ref)"' \
  "$BOM" > "$TMP/purls.tsv"

N=$(wc -l < "$TMP/purls.tsv" | tr -d ' ')
[[ "$N" != "0" ]] || { echo "::error::no components with a purl — nothing to query" >&2; exit 1; }
echo "querying OSV for $N purls" >&2

: > "$TMP/hits.tsv"
split -l "$BATCH" "$TMP/purls.tsv" "$TMP/chunk." 2>/dev/null || \
  { cp "$TMP/purls.tsv" "$TMP/chunk.aa"; }

FAILED=0
for chunk in "$TMP"/chunk.*; do
  cut -f1 "$chunk" | jq -R -s -c 'split("\n") | map(select(length>0) | {package:{purl:.}}) | {queries:.}' \
    > "$TMP/q.json"
  if ! curl -sS --fail --max-time 120 -X POST "$OSV/v1/querybatch" \
        -H 'Content-Type: application/json' -d @"$TMP/q.json" -o "$TMP/r.json" 2>/dev/null; then
    echo "::warning::OSV batch query failed for one chunk — results are incomplete" >&2
    FAILED=$((FAILED+1)); continue
  fi
  # results[] is positionally aligned with queries[]
  paste <(cut -f1 "$chunk") <(cut -f2 "$chunk") \
        <(jq -r '.results[] | [(.vulns // [])[].id] | join(",")' "$TMP/r.json") \
    >> "$TMP/hits.tsv"
done

IDS=$(awk -F'\t' '$3 != "" {print $3}' "$TMP/hits.tsv" | tr ',' '\n' | sort -u)
NID=$(printf '%s\n' "$IDS" | grep -c . || true)
echo "  $NID distinct advisories" >&2

# Fetch each advisory once, in parallel. Sequentially this took over three minutes for
# ~550 advisories, which is the difference between a usable CI step and one people skip.
mkdir -p "$TMP/adv"
printf '%s\n' "$IDS" | grep . | xargs -P "${OSV_PARALLEL:-8}" -I{} \
  sh -c 'curl -sS --fail --max-time 60 "'"$OSV"'/v1/vulns/{}" -o "'"$TMP"'/adv/{}.json" 2>/dev/null || true'

# Severity is not uniformly populated. The Go vulnerability database (GO-*) carries none
# at all, but aliases to a GHSA advisory that does — verified: GO-2022-0646 has
# severity:null while its alias GHSA-f5pg-7wfw-84q9 carries the CVSS vector. Without
# following the alias, every Go finding would arrive with no CVSS, and DEV-190 requires
# one. Collect the aliases that need resolving, then fetch those too.
: > "$TMP/need_alias.txt"
for f in "$TMP"/adv/*.json; do
  [[ -e "$f" ]] || continue
  jq -r 'if ((.severity // []) | length) == 0
         then ((.aliases // []) | map(select(startswith("GHSA-"))) | first // empty)
         else empty end' "$f" >> "$TMP/need_alias.txt" 2>/dev/null
done
sort -u "$TMP/need_alias.txt" | grep . > "$TMP/alias_ids.txt" || true

# Fetch into a separate directory. Writing them next to the primaries meant an alias id
# could collide with an id already in IDS, and a stale or empty file then silently won
# — the first version of this reported "resolved via alias" for 36 advisories while still
# emitting zero ratings for them.
mkdir -p "$TMP/alias"
if [[ -s "$TMP/alias_ids.txt" ]]; then
  while IFS= read -r aid; do
    [[ -z "$aid" ]] && continue
    printf '%s\n' "$aid"
  done < "$TMP/alias_ids.txt" | xargs -P "${OSV_PARALLEL:-8}" -I{} \
    curl -sS --fail --max-time 60 "$OSV/v1/vulns/{}" -o "$TMP/alias/{}.json"
fi
NALIAS=$(wc -l < "$TMP/alias_ids.txt" | tr -d ' ')
NALIAS_OK=$(find "$TMP/alias" -name '*.json' -size +0 2>/dev/null | wc -l | tr -d ' ')
[[ "$NALIAS" == "0" ]] || echo "  severity via GHSA alias: $NALIAS_OK of $NALIAS resolved" >&2

: > "$TMP/vulns.jsonl"
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  f="$TMP/adv/$id.json"
  [[ -s "$f" ]] || { echo "::warning::could not fetch advisory $id" >&2; continue; }
  alias_ghsa=$(jq -r 'if ((.severity // []) | length) == 0
                      then ((.aliases // []) | map(select(startswith("GHSA-"))) | first // "")
                      else "" end' "$f")
  sev='[]'; dbsev='null'
  if [[ -n "$alias_ghsa" && -s "$TMP/alias/$alias_ghsa.json" ]]; then
    sev=$(jq -c '.severity // []' "$TMP/alias/$alias_ghsa.json")
    dbsev=$(jq -c '.database_specific.severity // null' "$TMP/alias/$alias_ghsa.json")
  else
    sev=$(jq -c '.severity // []' "$f")
    dbsev=$(jq -c '.database_specific.severity // null' "$f")
  fi
  jq -c --argjson sev "$sev" --argjson dbsev "$dbsev" --arg via "$alias_ghsa" \
    '{osv_id: .id,
      aliases: (.aliases // []),
      summary: (.summary // ""),
      severity: $sev,
      db_severity: $dbsev,
      severity_via: (if ($via == "" or ($sev | length) == 0) then null else $via end)}' "$f" >> "$TMP/vulns.jsonl"
done <<<"$IDS"

jq -s -c '.' "$TMP/vulns.jsonl" > "$TMP/vulns.json"

# affects[] per advisory, from the purl -> ref map
awk -F'\t' '$3 != "" { n=split($3, ids, ","); for (i=1;i<=n;i++) print ids[i] "\t" $2 }' "$TMP/hits.tsv" \
  | sort -u | jq -R -s -c 'split("\n") | map(select(length>0) | split("\t") | {id:.[0], ref:.[1]})' \
  > "$TMP/affects.json"

jq --slurpfile vulns "$TMP/vulns.json" --slurpfile affects "$TMP/affects.json" '
  ($vulns[0]) as $v
  | ($affects[0]) as $a
  | .vulnerabilities = ( $v | map(
      . as $adv
      # Prefer the CVE id: it is what KEV and EPSS are keyed on. A GHSA-only advisory
      # keeps its own id and simply will not enrich, which is correct rather than hidden.
      | ( ($adv.aliases | map(select(startswith("CVE-"))) | first) // $adv.osv_id ) as $id
      | { id: $id,
          source: { name: "OSV", url: ("https://osv.dev/vulnerability/" + $adv.osv_id) },
          description: $adv.summary,
          ratings: ( ($adv.severity // [])
                     | map(select(.type | startswith("CVSS")))
                     | map({ source: {name:"OSV"},
                             method: (if .type == "CVSS_V3" then "CVSSv31"
                                      elif .type == "CVSS_V4" then "CVSSv4"
                                      else "other" end),
                             vector: .score }) ),
          properties: ( [ {name:"quickbird:vuln:osv-id", value:$adv.osv_id} ]
                        + (if $adv.db_severity != null
                           then [{name:"quickbird:vuln:osv-severity", value:$adv.db_severity}] else [] end)
                        + (if $adv.severity_via != null
                           then [{name:"quickbird:vuln:severity-source", value:$adv.severity_via}] else [] end) ),
          affects: ( $a | map(select(.id == $adv.osv_id)) | map({ref: .ref}) ) }
    )
    # Deduplicate by id. Several databases describe the same CVE — golang.org/x/crypto
    # yielded both GHSA-v778-237x-gjrc and GO-2024-3321 for CVE-2024-45337, giving two
    # entries for one vulnerability on one component. CycloneDX expects a vulnerability
    # to appear once, and a duplicated entry double-counts in every downstream tally.
    # Merge rather than drop: each source contributes affects, ratings and its own osv-id,
    # so provenance survives the merge.
    | group_by(.id)
    | map( if length == 1 then .[0]
           else
             { id: .[0].id,
               source: (map(.source) | .[0]),
               description: ( map(select((.description // "") != "")) | (.[0].description // "") ),
               ratings:    ( map(.ratings[]?)    | unique_by([.method, .vector, .source.name]) ),
               properties: ( map(.properties[]?) | unique_by([.name, .value]) ),
               affects:    ( map(.affects[]?)    | unique_by(.ref) ) }
           end )
    | sort_by(.id) )
' "$BOM" > "$OUT" || { echo "::error::failed to write $OUT" >&2; exit 1; }

TOTAL=$(jq '[.vulnerabilities[]?] | length' "$OUT")
CVES=$(jq '[.vulnerabilities[]? | select(.id | startswith("CVE-"))] | length' "$OUT")
echo "wrote $OUT — $TOTAL vulnerabilities ($CVES with a CVE id)" >&2
[[ "$FAILED" == "0" ]] || echo "::warning::$FAILED chunk(s) failed; the vulnerability list is incomplete" >&2
