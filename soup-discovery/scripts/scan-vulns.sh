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
  if ! curl -sS --fail --max-time 120 --retry 3 --retry-delay 2 -X POST "$OSV/v1/querybatch" \
        -H 'Content-Type: application/json' -d @"$TMP/q.json" -o "$TMP/r.json" 2>/dev/null; then
    echo "::error::OSV batch query failed for one chunk after retries — the vulnerability list would be incomplete" >&2
    FAILED=$((FAILED+1)); continue
  fi
  # results[] is positionally aligned with queries[]
  paste <(cut -f1 "$chunk") <(cut -f2 "$chunk") \
        <(jq -r '.results[] | [(.vulns // [])[].id] | join(",")' "$TMP/r.json") \
    >> "$TMP/hits.tsv"

  # querybatch caps each query at 1000 vulnerability ids and signals the rest with a
  # next_page_token. Rare for library purls, realistic for OS packages — a kernel RPM
  # carries thousands of CVEs, and dropping page two would silently truncate exactly the
  # package with the most findings. Follow the token per affected purl until exhausted.
  while IFS=$'\t' read -r idx token; do
    [[ -z "$idx" ]] && continue
    purl=$(sed -n "$((idx+1))p" "$chunk" | cut -f1)
    ref=$(sed -n "$((idx+1))p" "$chunk" | cut -f2)
    [[ -z "$purl" ]] && continue
    while [[ -n "$token" ]]; do
      jq -n --arg p "$purl" --arg t "$token" '{queries:[{package:{purl:$p}, page_token:$t}]}' > "$TMP/qp.json"
      if ! curl -sS --fail --max-time 120 --retry 3 --retry-delay 2 -X POST "$OSV/v1/querybatch" \
            -H 'Content-Type: application/json' -d @"$TMP/qp.json" -o "$TMP/rp.json" 2>/dev/null; then
        echo "::error::OSV pagination failed for $purl — the vulnerability list would be incomplete" >&2
        FAILED=$((FAILED+1)); break
      fi
      ids=$(jq -r '.results[0] | [(.vulns // [])[].id] | join(",")' "$TMP/rp.json")
      [[ -n "$ids" ]] && printf '%s\t%s\t%s\n' "$purl" "$ref" "$ids" >> "$TMP/hits.tsv"
      token=$(jq -r '.results[0].next_page_token // ""' "$TMP/rp.json")
    done
  done < <(jq -r '.results | to_entries[]
                  | select(.value.next_page_token != null and .value.next_page_token != "")
                  | "\(.key)\t\(.value.next_page_token)"' "$TMP/r.json" 2>/dev/null)
done

IDS=$(awk -F'\t' '$3 != "" {print $3}' "$TMP/hits.tsv" | tr ',' '\n' | sort -u)
NID=$(printf '%s\n' "$IDS" | grep -c . || true)
echo "  $NID distinct advisories" >&2

# Fetch each advisory once, in parallel. Sequentially this took over three minutes for
# ~550 advisories, which is the difference between a usable CI step and one people skip.
mkdir -p "$TMP/adv"
printf '%s\n' "$IDS" | grep . | xargs -P "${OSV_PARALLEL:-8}" -I{} \
  sh -c 'curl -sS --fail --max-time 60 --retry 3 --retry-delay 2 "'"$OSV"'/v1/vulns/{}" -o "'"$TMP"'/adv/{}.json" 2>/dev/null || true'

# Severity is not uniformly populated. The Go vulnerability database (GO-*) carries none
# at all, but aliases to a GHSA advisory that does — verified: GO-2022-0646 has
# severity:null while its alias GHSA-f5pg-7wfw-84q9 carries the CVSS vector. Without
# following the alias, every Go finding would arrive with no CVSS, and the release bundle requires
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
    curl -sS --fail --max-time 60 --retry 3 --retry-delay 2 "$OSV/v1/vulns/{}" -o "$TMP/alias/{}.json"
fi
NALIAS=$(wc -l < "$TMP/alias_ids.txt" | tr -d ' ')
NALIAS_OK=$(find "$TMP/alias" -name '*.json' -size +0 2>/dev/null | wc -l | tr -d ' ')
[[ "$NALIAS" == "0" ]] || echo "  severity via GHSA alias: $NALIAS_OK of $NALIAS resolved" >&2

: > "$TMP/vulns.jsonl"
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  f="$TMP/adv/$id.json"
  if [[ ! -s "$f" ]]; then
    # An advisory that could not be fetched is still a finding — OSV reported the id for a
    # component we ship. Dropping it here silently shrank the list; instead it is carried
    # unscored, which classifies as rule 16 (no CVSS, no vendor label -> planned) until a
    # later run scores it.
    echo "::warning::could not fetch advisory $id after retries — carried unscored, not dropped" >&2
    jq -n --arg id "$id" '{osv_id:$id, aliases:[], summary:"advisory could not be fetched — carried unscored",
                           severity:[], db_severity:null, severity_via:null, fixes:[]}' >> "$TMP/vulns.jsonl"
    continue
  fi
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
      severity_via: (if ($via == "" or ($sev | length) == 0) then null else $via end),
      # Fix availability, per affected package. Without this a deadline can be set on a
      # finding that has no fix to apply, which is not a deadline anyone can meet — the only
      # routes there are a compensating control or a VEX statement, and they need to be
      # distinguishable from "nobody has upgraded yet".
      fixes: [ (.affected // [])[]
               | { name: ((.package.name // "") | ascii_downcase),
                   purl: ((.package.purl // "") | ascii_downcase),
                   ecosystem: (.package.ecosystem // ""),
                   fixed: [ (.ranges // [])[] | (.events // [])[] | .fixed // empty ],
                   last_affected: [ (.ranges // [])[] | (.events // [])[] | .last_affected // empty ],
                   # An advisory that lists a range but publishes no fixed event is stating
                   # that no fix exists yet. That is a different fact from us not looking.
                   has_range: (((.ranges // []) | length) > 0) } ]}' "$f" >> "$TMP/vulns.jsonl"
done <<<"$IDS"

jq -s -c '.' "$TMP/vulns.jsonl" > "$TMP/vulns.json"

# affects[] per advisory, from the purl -> ref map
awk -F'\t' '$3 != "" { n=split($3, ids, ","); for (i=1;i<=n;i++) print ids[i] "\t" $2 "\t" $1 }' "$TMP/hits.tsv" \
  | sort -u | jq -R -s -c 'split("\n") | map(select(length>0) | split("\t") | {id:.[0], ref:.[1], purl:.[2]})' \
  > "$TMP/affects.json"

jq --slurpfile vulns "$TMP/vulns.json" --slurpfile affects "$TMP/affects.json" '
  # A purl can name the same package in several shapes, and OSV is not consistent about which
  # it publishes: golang uses the full module path, maven "group:artifact", rpm the bare name.
  # Rather than guess one, generate the candidates and match on any of them.
  def purl_keys($p):
    ($p | ascii_downcase | sub("^pkg:";"") | split("?")[0] | split("@")[0]) as $body
    | ($body | split("/")) as $seg
    | [ $body,
        ($seg[1:] | join("/")),
        ($seg[1:] | join(":")),
        ($seg[-1]) ]
    | unique ;

  def fix_for($adv; $purl):
    (purl_keys($purl)) as $keys
    | ($purl | ascii_downcase | split("?")[0] | split("@")[0]) as $mine
    | ( [ $adv.fixes[]?
          | . as $fx
          | ($fx.purl | split("@")[0]) as $fp
          | select( ($fp != "" and ($mine | startswith($fp)))
                    or ($fx.name != "" and ($fx.name | IN($keys[]))) ) ] ) as $m
    | if ($m | length) == 0 then
        # Could not tie the advisory to this component. Reporting "no fix" here would be a
        # claim we have not established.
        {status:"unknown", fixed:[], why:"the advisory does not name this package in a shape that could be matched"}
      elif ([$m[].fixed[]] | length) > 0 then
        {status:"available", fixed:([$m[].fixed[]] | unique), why:null}
      elif ([$m[] | select(.has_range)] | length) > 0 then
        {status:"none-published", fixed:[],
         why:"the advisory gives an affected range but publishes no fixed version — mitigation here is a compensating control or a VEX statement, not an upgrade"}
      else
        {status:"unknown", fixed:[], why:"the advisory carries no version ranges"}
      end ;

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
                           then [{name:"quickbird:vuln:severity-source", value:$adv.severity_via}] else [] end)
                        + ( [ $a[] | select(.id == $adv.osv_id) | fix_for($adv; .purl) ] as $fx
                            | ( if any($fx[]; .status == "available") then
                                  [ {name:"quickbird:vuln:fix", value:"available"},
                                    {name:"quickbird:vuln:fix-versions",
                                     value: ([ $fx[] | select(.status=="available") | .fixed[] ] | unique | join(", "))} ]
                                elif (($fx | length) > 0 and all($fx[]; .status == "none-published")) then
                                  [ {name:"quickbird:vuln:fix", value:"none-published"},
                                    {name:"quickbird:vuln:fix-note", value: ($fx[0].why // "")} ]
                                else
                                  [ {name:"quickbird:vuln:fix", value:"unknown"},
                                    {name:"quickbird:vuln:fix-note",
                                     value: (($fx[0].why) // "no affected package in the advisory matched this component")} ]
                                end ) ) ),
          affects: ( $a | map(select(.id == $adv.osv_id))
                     | map( fix_for($adv; .purl) as $fx
                            | { ref: .ref }
                              + (if ($fx.fixed | length) > 0
                                 then { versions: [ $fx.fixed[] | {version: ., status: "unaffected"} ] }
                                 else {} end) ) ) }
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
# Incomplete fails the run. This script's own design note says a failed query is not "no
# vulnerabilities", and exit 0 on a dropped chunk was exactly that: the caller writes an
# assessment that reads as complete over a list that is not. The monitor turns this failure
# into an `incomplete` verdict, which is the honest answer.
if [[ "$FAILED" != "0" ]]; then
  echo "::error::$FAILED OSV request(s) failed after retries — refusing to present an incomplete vulnerability list as an assessment" >&2
  exit 1
fi
