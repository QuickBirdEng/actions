# CVE Enrichment — KEV + EPSS

Prototype for [DEV-192](https://quickbird.atlassian.net/browse/DEV-192). Annotates CVE IDs with
**CISA KEV** membership and **EPSS** score, in one shape that both the release evidence bundle
(DEV-190) and continuous monitoring (DEV-191) read. Bash + `jq` + `curl` + `awk` only — same
dependency footprint as the existing `soup-*` actions.

Intended destination: `QuickBirdEng/actions/kev-epss-enrichment`.

## Usage

```yaml
- uses: QuickBirdEng/actions/kev-epss-enrichment@main
  id: enrich
  with:
    input-file: osv-scanner-reports/report.json
    output: cve-enrichment.json

- run: echo "KEV hits: ${{ steps.enrich.outputs.kev-count }}"
```

`input-file` is scanned for `CVE-\d{4}-\d{4,}` rather than parsed against a schema, so OSV-Scanner,
Docker Scout, Dependabot, Trivy and CycloneDX all work with no per-tool adapter. Over-inclusion is
harmless: an extra CVE yields an extra row, never a wrong verdict. Pass `cves:` instead (or as well)
for an explicit list.

| Input | Default | Notes |
| --- | --- | --- |
| `cves` | `''` | Comma/whitespace-separated IDs |
| `input-file` | `''` | Any file containing CVE IDs |
| `output` | `cve-enrichment.json` | |
| `snapshot-date` | `''` | Pin EPSS to `YYYY-MM-DD` to reproduce a past enrichment |
| `cache-ttl-hours` | `6` | Reuse a cached feed younger than this |
| `allow-missing-feeds` | `false` | Emit an empty stale result instead of failing |
| `upload-artifact` | `false` | |

Outputs: `enrichment-file`, `stale`, `kev-count`, `kev-catalog-version`, `epss-model-version`.

## Output shape (`quickbird.cve-enrichment/v1`)

```json
{
  "schema": "quickbird.cve-enrichment/v1",
  "stale": false,
  "feeds": {
    "kev":  { "source": "cisa-kev",   "catalog_version": "2026.07.29", "date_released": "…", "entries": 1656, "available": true },
    "epss": { "source": "epss-bulk",  "model_version": "v2026.06.15",  "score_date": "2026-07-31T12:03:43Z",
              "rows": 354453, "pinned_snapshot_date": null, "available": true }
  },
  "warnings": [],
  "summary": { "requested": 5, "kev_members": 3, "epss_scored": 4 },
  "cves": {
    "CVE-2021-44228": { "kev": true, "epss": 0.99999, "epss_percentile": 1.0, "in_epss": true,
                        "kev_date_added": "2021-12-10", "kev_due_date": "2021-12-24",
                        "kev_ransomware": "Known", "kev_vendor_project": "Apache", "kev_product": "Log4j2" },
    "CVE-2024-3094":  { "kev": false, "epss": 0.85974, "epss_percentile": 0.99709, "in_epss": true },
    "CVE-2099-99999": { "kev": false, "epss": null, "epss_percentile": null, "in_epss": false }
  }
}
```

Every requested CVE gets an entry, including misses — "absent from the feed" is a finding, not a gap.

**`kev: null` is not `kev: false`.** `false` means *checked, not in the catalog*. `null` means the
catalog could not be read, so nothing was established. Consumers must treat `null` as unknown; a scan
that cannot reach KEV has not proven a CVE is not actively exploited. Same for `in_epss`.

## Why the bulk feed, not the lookup API

The ticket specifies "query the EPSS API (FIRST.org)". This uses the bulk CSV instead, for two reasons:

1. **`api.first.org/data/v1/epss` returns a `date` but no model version.** EPSS moved from v4
   (2025-03-17) to **v5 (2026-06-15)**, and scores are not comparable across model versions. Recording
   only a date would make a 0.42 from June and a 0.42 from July look like the same evidence. The bulk
   feed carries both on its first line:
   `#model_version:v2026.06.15,score_date:2026-07-31T12:03:43Z`
2. It is one 2.5 MB request for all 354k scored CVEs instead of N requests against a rate-limited
   lookup endpoint — which matters once DEV-191 runs daily across every project.

Bulk feeds are served from `epss.empiricalsecurity.com`; the old `epss.cyentia.com` path redirects
there. The FIRST.org lookup API still works and is the right fallback for a one-off check.

## Reproducibility

`snapshot-date` pins EPSS to a dated file (`epss_scores-2026-07-15.csv.gz`), which is what makes a past
classification reconstructable. Verified: pinning to 2026-07-15 returns `score_date
2026-07-15T12:00:34Z` and 348,601 rows, against 354,453 rows today.

**Known gap: KEV has no historical feed.** CISA publishes only the current catalog, so a past KEV state
cannot be re-fetched — only the `catalogVersion` proves which snapshot was used. To make KEV membership
reproducible, **the consumer must archive the catalog file itself**, keyed by `catalogVersion`. For
DEV-191 that is a natural fit for the per-project evidence store; for DEV-190 the frozen bundle should
carry the `catalogVersion` in `metadata.properties`. Worth adding as an explicit acceptance criterion
on both tickets — the current wording ("emits the feed snapshot date") is satisfiable without it and
would leave KEV unreproducible.

## Behaviour when feeds fail

| Situation | Result |
| --- | --- |
| Feed fresh in cache (< TTL) | Cache used, `stale: false` |
| Refresh fails, cache exists | Cached snapshot used, `stale: true`, warning names the cache age |
| Refresh fails, no cache | **Exit 1.** Refuses to emit an enrichment that establishes nothing |
| Same, with `allow-missing-feeds: true` | Empty result, `stale: true`, `kev`/`in_epss` are `null` |
| Cached file is corrupt / not valid KEV JSON | Feed treated as unavailable, warning emitted |

## Verified against the live feeds (2026-07-31)

| Test | Result |
| --- | --- |
| Explicit list, KEV hit + KEV miss + unscored + bogus ID | 5 requested, 3 KEV, 4 scored |
| File input (OSV-Scanner-shaped, CVEs only in `aliases`) | 3 extracted and enriched |
| Feeds unreachable, cache 282 h old | `stale: true`, 2 warnings, exit 0 |
| Feeds unreachable, no cache | exit 1, no output file |
| Same with `allow-missing-feeds` | empty result, `kev: null` |
| EPSS pinned to 2026-07-15 | different `score_date` and row count, same model version |

CVE-2024-3094 (xz backdoor) is a useful regression case: EPSS 0.86 but **not** in KEV. Under the
draft classification it lands in Track 2, not Track 1 — a good check that KEV and EPSS are read as
separate signals rather than collapsed into one.

## Not in scope here

- **Classification.** This step supplies raw signals only. The CVSS/KEV/EPSS → track mapping lives in
  the process document (see `../classification-draft.md`) and is applied by the consumers, per the
  ticket's own division of labour.
- **CVSS retrieval.** The enrichment joins on CVE ID; CVSS comes from the scanner output that already
  carries it.
- **CPE matching.** Do not feed heuristic CPEs into this. syft generated ~1900 speculative
  `syft:cpe23` variants for the Apellis worker alone; matching on those produces phantom findings.
  Join on `purl`.
