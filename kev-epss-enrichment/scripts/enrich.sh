#!/usr/bin/env bash
# CVE enrichment: CISA KEV membership + EPSS score.
#
# Reads CVE IDs, writes one JSON document with a stable shape that both the release
# evidence bundle (DEV-190) and continuous monitoring (DEV-191) consume.
#
# Offline-tolerant by design: a feed that cannot be refreshed falls back to the cached
# snapshot and marks the result stale. It never silently reports "not in KEV" for a feed
# it could not read.

set -uo pipefail

CACHE_DIR="${QB_ENRICH_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/qb-cve-enrichment}"
CACHE_TTL_HOURS="${QB_ENRICH_CACHE_TTL_HOURS:-6}"
SNAPSHOT_DATE="${QB_ENRICH_SNAPSHOT_DATE:-}"
OUTPUT_FILE="${QB_ENRICH_OUTPUT:-cve-enrichment.json}"
ALLOW_MISSING="${QB_ENRICH_ALLOW_MISSING_FEEDS:-false}"
CVE_LIST_FILE="${QB_ENRICH_CVE_FILE:-}"
CVE_LIST_INLINE="${QB_ENRICH_CVES:-}"

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BASE="https://epss.empiricalsecurity.com"

WARNINGS=()
STALE=false

log()  { printf '%s\n' "$*" >&2; }
warn() { WARNINGS+=("$1"); log "::warning::$1"; }
die()  { log "::error::$1"; exit 1; }

for tool in curl jq awk gzip; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

mkdir -p "$CACHE_DIR" || die "cannot create cache dir: $CACHE_DIR"

# ---------------------------------------------------------------------------
# 1. Collect the CVE IDs to enrich
# ---------------------------------------------------------------------------
# Accepts an explicit list and/or an arbitrary file. For files we scan for CVE
# identifiers rather than assuming a schema, so OSV-Scanner, Docker Scout,
# Dependabot, Trivy and CycloneDX all work without a per-tool adapter.
# Over-inclusion is harmless here: an extra CVE yields an extra row, not a wrong verdict.

WANTED="$CACHE_DIR/wanted.txt"
: > "$WANTED"

if [[ -n "$CVE_LIST_INLINE" ]]; then
  printf '%s\n' "$CVE_LIST_INLINE" | tr ',[:space:]' '\n\n' >> "$WANTED"
fi

if [[ -n "$CVE_LIST_FILE" ]]; then
  [[ -f "$CVE_LIST_FILE" ]] || die "input file not found: $CVE_LIST_FILE"
  grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$CVE_LIST_FILE" >> "$WANTED" || true
fi

# Normalise: uppercase, unique, sorted, drop empties.
LC_ALL=C tr '[:lower:]' '[:upper:]' < "$WANTED" \
  | grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' \
  | LC_ALL=C sort -u > "$WANTED.clean" || true
mv "$WANTED.clean" "$WANTED"

CVE_COUNT=$(wc -l < "$WANTED" | tr -d ' ')
log "CVE IDs to enrich: $CVE_COUNT"

# ---------------------------------------------------------------------------
# 2. Fetch feeds, with cache fallback
# ---------------------------------------------------------------------------
# fetch_with_cache <url> <cache-file> <label>
# Returns 0 if the cache file is usable (fresh or stale), 1 if there is nothing to use.
fetch_with_cache() {
  local url="$1" dest="$2" label="$3"
  local tmp="$dest.tmp"

  if [[ -f "$dest" ]]; then
    local age_h
    age_h=$(( ( $(date +%s) - $(stat -f %m "$dest" 2>/dev/null || stat -c %Y "$dest") ) / 3600 ))
    if (( age_h < CACHE_TTL_HOURS )); then
      log "$label: using cache (${age_h}h old, TTL ${CACHE_TTL_HOURS}h)"
      return 0
    fi
  fi

  if curl -sS -L --fail --max-time 120 -o "$tmp" "$url" 2>/dev/null && [[ -s "$tmp" ]]; then
    mv "$tmp" "$dest"
    log "$label: refreshed"
    return 0
  fi

  rm -f "$tmp"
  if [[ -f "$dest" ]]; then
    local age_h
    age_h=$(( ( $(date +%s) - $(stat -f %m "$dest" 2>/dev/null || stat -c %Y "$dest") ) / 3600 ))
    warn "$label: refresh failed, falling back to cached snapshot (${age_h}h old) — results are STALE"
    STALE=true
    return 0
  fi

  return 1
}

# --- KEV -------------------------------------------------------------------
KEV_FILE="$CACHE_DIR/kev.json"
KEV_AVAILABLE=true
if ! fetch_with_cache "$KEV_URL" "$KEV_FILE" "KEV"; then
  KEV_AVAILABLE=false
fi

if $KEV_AVAILABLE && ! jq -e '.vulnerabilities | type == "array"' "$KEV_FILE" >/dev/null 2>&1; then
  warn "KEV: cached file is not valid KEV JSON — treating feed as unavailable"
  KEV_AVAILABLE=false
fi

# --- EPSS ------------------------------------------------------------------
# A pinned snapshot date makes a past enrichment reproducible. Without one we take
# the current file, which is what a daily monitoring run wants.
if [[ -n "$SNAPSHOT_DATE" ]]; then
  EPSS_URL="$EPSS_BASE/epss_scores-${SNAPSHOT_DATE}.csv.gz"
  EPSS_GZ="$CACHE_DIR/epss-${SNAPSHOT_DATE}.csv.gz"
else
  EPSS_URL="$EPSS_BASE/epss_scores-current.csv.gz"
  EPSS_GZ="$CACHE_DIR/epss-current.csv.gz"
fi

EPSS_FILE="$CACHE_DIR/epss.csv"
EPSS_AVAILABLE=true
if fetch_with_cache "$EPSS_URL" "$EPSS_GZ" "EPSS"; then
  if ! gzip -dc "$EPSS_GZ" > "$EPSS_FILE" 2>/dev/null; then
    warn "EPSS: cached archive could not be decompressed — treating feed as unavailable"
    EPSS_AVAILABLE=false
  fi
else
  EPSS_AVAILABLE=false
fi

if ! $KEV_AVAILABLE && ! $EPSS_AVAILABLE; then
  if [[ "$ALLOW_MISSING" != "true" ]]; then
    die "neither KEV nor EPSS could be obtained and no cache exists — refusing to emit an enrichment that establishes nothing (set allow-missing-feeds: true to override)"
  fi
  warn "both feeds unavailable and no cache — emitting an empty enrichment marked stale"
  STALE=true
fi

# ---------------------------------------------------------------------------
# 3. Feed metadata — what makes a result reproducible
# ---------------------------------------------------------------------------
if $KEV_AVAILABLE; then
  KEV_META=$(jq -c '{
    source: "cisa-kev",
    catalog_version: .catalogVersion,
    date_released: .dateReleased,
    entries: (.vulnerabilities | length),
    available: true
  }' "$KEV_FILE")
else
  KEV_META='{"source":"cisa-kev","available":false,"catalog_version":null,"date_released":null,"entries":0}'
  STALE=true
fi

if $EPSS_AVAILABLE; then
  # The bulk feed's first line carries both the model version and the score date.
  # The per-CVE lookup API returns only a date, which is why the bulk feed is used:
  # EPSS scores are not comparable across model versions.
  EPSS_HEADER=$(head -1 "$EPSS_FILE")
  EPSS_MODEL=$(printf '%s' "$EPSS_HEADER" | sed -n 's/.*model_version:\([^,]*\).*/\1/p')
  EPSS_SCORE_DATE=$(printf '%s' "$EPSS_HEADER" | sed -n 's/.*score_date:\([^,]*\).*/\1/p')
  EPSS_ROWS=$(( $(wc -l < "$EPSS_FILE") - 2 ))

  [[ -n "$EPSS_MODEL" ]] || warn "EPSS: model_version missing from feed header — reproducibility of these scores cannot be established"

  EPSS_META=$(jq -cn \
    --arg model "$EPSS_MODEL" \
    --arg score_date "$EPSS_SCORE_DATE" \
    --argjson rows "$EPSS_ROWS" \
    --arg pinned "${SNAPSHOT_DATE:-}" \
    'def blank_to_null: if . == "" then null else . end;
     {source:"epss-bulk", model_version:($model|blank_to_null), score_date:($score_date|blank_to_null),
      rows:$rows, pinned_snapshot_date:($pinned|blank_to_null), available:true}')
else
  EPSS_META='{"source":"epss-bulk","available":false,"model_version":null,"score_date":null,"rows":0}'
  STALE=true
fi

# ---------------------------------------------------------------------------
# 4. Join
# ---------------------------------------------------------------------------
KEV_HITS='{}'
if $KEV_AVAILABLE && (( CVE_COUNT > 0 )); then
  KEV_HITS=$(jq -c --rawfile wanted "$WANTED" '
    ($wanted | split("\n") | map(select(length > 0)) | map({key:., value:true}) | from_entries) as $w
    | [ .vulnerabilities[]
        | select($w[.cveID] != null)
        | {key: .cveID, value: {
            kev: true,
            kev_date_added: .dateAdded,
            kev_due_date: .dueDate,
            kev_ransomware: (.knownRansomwareCampaignUse // null),
            kev_vendor_project: .vendorProject,
            kev_product: .product
          }} ]
    | from_entries
  ' "$KEV_FILE")
fi

EPSS_HITS='{}'
if $EPSS_AVAILABLE && (( CVE_COUNT > 0 )); then
  # 354k-row CSV: awk-join, not jq. Skip the comment line and the header.
  EPSS_HITS=$(awk -F, '
    NR==FNR { want[$1]=1; next }
    FNR<=2  { next }
    ($1 in want) { printf "%s\t%s\t%s\n", $1, $2, $3 }
  ' "$WANTED" "$EPSS_FILE" \
  | jq -R -s -c 'split("\n") | map(select(length>0) | split("\t"))
      | map({key: .[0], value: {epss: (.[1]|tonumber), epss_percentile: (.[2]|tonumber)}})
      | from_entries')
fi

# ---------------------------------------------------------------------------
# 5. Emit
# ---------------------------------------------------------------------------
# Every requested CVE gets an entry, including misses — "absent from the feed" is a
# finding, not a gap. in_epss=false with an available feed means genuinely unscored
# (typically a very new CVE); with an unavailable feed it means unknown.

jq -n \
  --rawfile wanted "$WANTED" \
  --argjson kev_hits "$KEV_HITS" \
  --argjson epss_hits "$EPSS_HITS" \
  --argjson kev_meta "$KEV_META" \
  --argjson epss_meta "$EPSS_META" \
  --argjson stale "$STALE" \
  --argjson warnings "$(printf '%s\n' "${WARNINGS[@]:-}" | jq -R -s 'split("\n") | map(select(length>0))')" \
  '
  ($wanted | split("\n") | map(select(length > 0))) as $cves
  | {
      schema: "quickbird.cve-enrichment/v1",
      stale: $stale,
      feeds: { kev: $kev_meta, epss: $epss_meta },
      warnings: $warnings,
      summary: {
        requested: ($cves | length),
        kev_members: ($kev_hits | length),
        epss_scored: ($epss_hits | length)
      },
      cves: (
        $cves
        | map({
            key: .,
            value: (
              {
                kev: (if $kev_meta.available then ($kev_hits[.] != null) else null end),
                epss: ($epss_hits[.].epss // null),
                epss_percentile: ($epss_hits[.].epss_percentile // null),
                in_epss: (if $epss_meta.available then ($epss_hits[.] != null) else null end)
              }
              + ($kev_hits[.] // {} | del(.kev))
            )
          })
        | from_entries
      )
    }
  ' > "$OUTPUT_FILE" || die "failed to write $OUTPUT_FILE"

log "wrote $OUTPUT_FILE"
jq -c '{stale, summary, feeds: {kev: .feeds.kev.catalog_version, epss: .feeds.epss.model_version}}' "$OUTPUT_FILE" >&2

# GitHub Action outputs
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "enrichment-file=$OUTPUT_FILE"
    echo "stale=$STALE"
    echo "kev-count=$(jq -r '.summary.kev_members' "$OUTPUT_FILE")"
    echo "kev-catalog-version=$(jq -r '.feeds.kev.catalog_version // ""' "$OUTPUT_FILE")"
    echo "epss-model-version=$(jq -r '.feeds.epss.model_version // ""' "$OUTPUT_FILE")"
  } >> "$GITHUB_OUTPUT"
fi

exit 0
