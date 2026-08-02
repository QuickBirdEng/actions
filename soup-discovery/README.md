# SOUP discovery + BOM gate

Prototype for [DEV-195](https://quickbird.atlassian.net/browse/DEV-195). A self-contained
five-stage pipeline that closes the dependency-discovery gaps blocking
[DEV-190](https://quickbird.atlassian.net/browse/DEV-190).
Bash + `jq` + `yq` + pinned syft — same footprint as the existing `soup-*` actions.

```
run-pipeline.sh   repo               -> sbom/              all of the below, one command

  discover.sh       repo               -> candidates.json    exhaustive, no scope decisions
  resolve-scope.sh  + .soup-scope.yml  -> scan-plan.json     fails on any unclassified candidate
  (syft per target)                    -> raw.cdx.json
  normalize-bom.sh  raw.cdx.json       -> bom.cdx.json       deterministic, hashes harvested
  consolidate.sh    N boms             -> solution.cdx.json  self-contained, dedup + merged edges
  verify-bom.sh     bom.cdx.json       -> pass/fail          no unversioned, paths, guessed CPEs

then, for the release bundle (DEV-190):

  scan-vulns.sh        bom            -> bom + vulnerabilities[]   OSV, joined on purl
  merge-enrichment.sh  + enrichment   -> KEV property + EPSS rating + feed provenance
  merge-assessment.sh  + .soups/      -> requirements, approval annotation, VEX analysis
```

## What this fixes, measured

All numbers below are from a real run against `QuickBirdEng/apellis` on 2026-07-31, syft 1.20.0.

### Discovery: 2 candidates → 24

Today's org tooling looks for `package.json`, `pubspec.yaml`, `build.gradle{,.kts}`. In apellis
that finds **2** things. `discover.sh` finds **24** across six ecosystems:

| Ecosystem | Candidates | Notes |
| --- | --- | --- |
| container | 11 | 4 correctly marked `ships=false` — build stages of multi-stage Dockerfiles |
| terraform | 6 | one per root, from `.terraform.lock.hcl` |
| python | 4 | all four turn out to be test/docs tooling — see scope, below |
| go | 1 | scanned as the linked binary, not `go.sum` |
| jvm-gradle | 1 | scanned as the resolved closure, not the build file |
| npm | 1 | |

### JVM: 16 declared → 84 resolved, and the empty-version defect is gone

This is the defect DEV-195 exists for. Running the *existing* org regex against
`apps/analysis-pipeline/worker/build.gradle.kts` extracts 16 of 17 declared lines. The miss is
`implementation(platform("com.azure:azure-sdk-bom:1.2.31"))`, and the consequence is that the four
dependencies whose versions that BOM supplies come out **with an empty version**.

Scanning the resolved runtime closure (`./gradlew installDist`, 81 JARs) instead:

| Component | today | resolved closure |
| --- | --- | --- |
| `com.azure:azure-identity` | *(empty)* | **1.15.0** |
| `com.azure:azure-identity-extensions` | *(empty)* | **1.2.0** |
| `com.azure:azure-messaging-servicebus` | *(empty)* | **7.17.8** |
| `com.azure:azure-storage-blob` | *(empty)* | **12.29.0** |
| total components | 16 | **84** |

An unversioned component is not a valid configuration item under IEC 62304 §8.1.2 and cannot be
CVE-matched. 68 of the 84 are transitive — invisible to declared-only discovery, and where most
CVEs live.

`installDist` was chosen over `gradle.lockfile` because it works today in every repo:
reading a lockfile presupposes `dependencyLocking` is enabled, which is a per-project change.
`discover.sh` prefers the lockfile automatically where one exists.

### Normalisation: 165 → 84 components, hash coverage 0 → 79

Raw syft output is not usable as evidence:

| | raw | normalised |
| --- | --- | --- |
| components | 165 | 84 |
| `type: file` scan artefacts | 81 | 0 |
| speculative `syft:cpe23` properties | **1886** | 0 |
| components with a hash | **0** | 79 |
| byte-identical across two runs | no | **yes** |

Matching CVEs on speculative CPEs produces phantom findings; join on `purl`.

Hash coverage is the reason the `type: file` entries cannot simply be deleted. Maven libraries come
back with empty `hashes` and only a SHA-1 in `externalReferences` — the SHA-256 exists **only** on
the parallel file entries. `normalize-bom.sh` harvests it onto the real component first, then drops
them. Component Hash is a CISA minimum element, so 0 → 79 is the difference between meeting it
and not.

## The scope gate — the part that matters most

`discover.sh` deliberately makes **no** scope decisions. Exhaustive discovery and recorded scope are
separate concerns, and conflating them is how a BOM ends up either bloated with test tooling or
silently missing a component.

`resolve-scope.sh` applies a repo's `.soup-scope.yml` and **fails the run** on:

- any candidate that is neither included nor excluded,
- any candidate matched by two rules of the same specificity,
- any exclusion without a `reason` — an unexplained exclusion is indistinguishable from an oversight
  six months later.

Rules match by exact `id` or by `path` prefix on any of a candidate's markers. **An `id` rule beats
a `path` rule**, because specific should beat general — and the case is real rather than
hypothetical: in kontina-backend, Redis appears both in the local developer compose stack (excluded
by path) and in `k8s/redis/resources.yml` (included by id). Only two rules at the same level are a
genuine conflict.

A worked example is in `examples/kontina-backend.soup-scope.yml` — the proposed pilot project. Its
13 candidates resolve to **6 in scope, 7 out**, each with a reason.

That the exclusions outnumber the inclusions is the point. Blind discovery would have put a
test-only `requirements-test.txt`, the local compose harness, a Docker build stage and a
`ubuntu/curl:latest` probe container into a medical device's SBOM.

**Verified failure mode:** adding `apps/new-service/go.mod` to the repo makes discovery report 25
candidates and the gate exit 1, naming `new-service` as unclassified. That turns "a new SOUP
appeared" into a review event, which is what `WI-006-03` asks for and what nothing enforces today.

## Verified across the real portfolio, not just apellis

apellis is the outlier in the portfolio (Go + Gradle + Terraform + images). The bread and
butter is Flutter + web + backend, so the pipeline was run against three more repos.
**It did not work on them at first** — four defects only visible on real projects:

| Repo | Stack | Candidates | Ecosystems |
| --- | --- | --- | --- |
| apellis | Go / Kotlin / Terraform | 27 | container 14, terraform 6, python 4, go 1, jvm 1, npm 1 |
| mindnet | Flutter + web | 36 | container 25, npm 5, jvm-maven 3, android 1, pub 1, terraform 1 |
| osteocoach | TypeScript + Flutter | 25 | container 17, npm 5, android 1, pub 1, terraform 1 |
| kontina-backend | Python | 13 | container 11, python 2 |

All four: 0 duplicate ids, 0 degenerate ids. Scope gate verified on apellis (10 in, 17 out) and
kontina-backend (6 in, 7 out).

### What broke, and why it only showed up here

1. **`image:` is not a container-only YAML key.** Flutter's `flutter_native_splash.yaml`
   uses it for asset paths, so mindnet reported `assets/logo/logo.png` as a deployed
   container image. Now rejected on file extension before anything else.
2. **Android build files are not JVM services.** mindnet's `app/android/build.gradle` and
   `app/android/app/build.gradle` were classified `jvm-gradle`, whose strategy is
   `installDist` — a task Android builds do not have, so the scan would simply have
   failed. Now detected via an `android/` path segment or a `pubspec.yaml` above, and
   both files collapse into one `android-gradle` candidate.
3. **Duplicate ids.** The same image referenced from production/staging/dev manifests
   produced one candidate per reference — 8 collisions in mindnet, and a scope rule would
   have matched an arbitrary one. Candidates are now keyed by id with a `markers[]` list.
4. **Fully templated refs strip to nothing.** `{{ .Values.image }}` reduced to the id
   `deployed---`, collapsing every Helm-templated image in a repo onto one unusable
   candidate. Falls back to the manifest filename.

### One of those "defects" is actually a finding

Five of mindnet's own deployed services are referenced as `qbsdocker/mindnet-<svc>:<version>`
across production, staging and dev manifests — the tag is a placeholder substituted at
deploy time:

```
deployed-mindnet-rest--version-           <- production-rest-api-deployment.yml, …
deployed-mindnet-web-ui--version-         <- production-web-ui-deployment.yml, …
deployed-mindnet-strapi--version-         <- production-strapi-deployment.yml, …
deployed-mindnet-keycloak--version-       <- production-keycloak-deployment.yml, …
deployed-mindnet-sentry-proxy--version-   <- production-sentry-proxy-deployment.yml, …
```

**From the repository you cannot tell which version of Mindnet is running in production.**
That is exactly [DEV-196](https://quickbird.atlassian.net/browse/DEV-196), now demonstrated
on the flagship product rather than only on apellis. Such candidates are emitted with
`resolvable: false` and listed under `.unresolvable`, rather than dropped or silently
treated as scannable.

## Two bugs the tooling found in itself

Worth recording, because both are the exact class of silent failure this pipeline exists to catch:

1. **Marker path inconsistency.** The Helm/compose image scan used `grep -r`, so its markers carried
   a `./` prefix while every other marker was git-relative. `path:` scope rules silently failed to
   match — the two docker-compose images stayed unclassified. Caught by the scope gate on the first
   real repo, not by reading the code.
2. **The BOM subject is a scan path.** `metadata.component.name` is whatever path was handed to
   syft (relative from one caller, absolute from another) and its `bom-ref` is a hash of that name.
   Two runs over identical content produced different documents. `verify-bom.sh` originally checked
   only `components[]`, so it passed a BOM that was not reproducible. Caught by the determinism
   check. `normalize-bom.sh` now requires `BOM_SUBJECT` and refuses to run without it.

## Known limitations

- **Terraform providers carry no `purl`**, only a CPE — so they cannot be `purl`-joined for CVEs.
  Confirmed: the heyex2 root yields one component, `registry.terraform.io/hashicorp/azurerm 4.58.0`,
  with no purl. Matches what the apellis README records.
- **Container OS packages carry no hash.** The alpine:3.20 scan gives 15 components, 14 with a purl,
  0 with a hash.
- **Unpinned base images.** 5 of the 8 `FROM` lines in apellis are not digest-pinned
  (`node:24-alpine`, `alpine:3.20`, `python:3.12-slim`), so their scanned contents cannot be tied to a
  specific image build. `discover.sh` flags these in `.warnings` rather than failing — pinning is a
  per-repo decision, not something a discovery tool should force.
- **`ships=true` on deployment-manifest images is an assumption.** Anything matched by `image:` in a
  YAML file is treated as deployed. For apellis that wrongly included two docker-compose test
  containers; the scope file catches them, but on a repo with many compose files this will be noisy.
- **No dependency graph is produced here.** `dependencies[]` edges come from the per-ecosystem
  scanners and are merged during rollup — that is DEV-190's job, not this one's.
- **Not yet wired into an action.** These are scripts with verified behaviour, not a packaged
  composite action, and the `runs-on` override on the `soup-*` workflows is not implemented.

## Usage

```bash
cd <repo>
discover.sh .                                   # -> candidates.json
SCOPE_SCAFFOLD=1 resolve-scope.sh candidates.json   # first run: emits .soup-scope.yml.scaffold
# classify every entry, then:
resolve-scope.sh candidates.json .soup-scope.yml    # -> scan-plan.json, or exit 1

# per target in scan-plan.json:
syft scan "<scan_source>" -o cyclonedx-json=raw.cdx.json
BOM_SUBJECT=<stable-id> normalize-bom.sh raw.cdx.json bom.cdx.json
verify-bom.sh bom.cdx.json
```

`KEEP_TIMESTAMP=1` for the release tier, which needs `metadata.timestamp`; omit it for the
committable tier, which needs to be diffable.

## Consolidation

`consolidate.sh` merges the per-target BOMs into one self-contained document, because two
readers want different things and both are legitimate: a dependency-tracking tool wants one
BOM per shipped artifact (a BOM has a single `metadata.component` as its subject), while an
auditor wants one file that answers "what is in this product" without following links.

Verified on three real BOMs (JVM closure + Terraform root + container base):

- 100 component entries in, **103 out** — 3 of them artifact subjects representing the scanned
  targets themselves.
- Components deduplicated by `bom-ref`; dependency edges remapped from each sub-BOM's subject
  onto its artifact ref, so nothing dangles and the document stays schema-valid.
- `quickbird:sbom:complete` plus one `quickbird:sbom:missing` per in-scope candidate that could
  not be scanned. An incomplete BOM that does not say so is the worst outcome available here.
- **Verified that no component from any input is lost.** A silent loss would still look like a
  complete SBOM, so this is checked rather than assumed.

One rough edge: an artifact subject can inherit an odd version — the Terraform lockfile scan
yields the file digest as its subject version. Honest but not meaningful; the subject version
should come from the scan plan instead.

## Property taxonomy

Defined here so it stays one convention rather than growing per repo:

| Property | Where | Meaning |
| --- | --- | --- |
| `quickbird:sbom:complete` | `metadata.properties` | `false` if any in-scope candidate could not be scanned |
| `quickbird:sbom:missing` | `metadata.properties`, repeatable | id of an in-scope candidate absent from this BOM |
| `quickbird:sbom:artifact-count` | `metadata.properties` | number of scanned targets consolidated |

`quickbird:soup:*` (requirement results, approval, risk refs) and `quickbird:vuln:*` (KEV) are
added by DEV-190 on top of this.

## The release-bundle stages

Three further stages turn a component list into release evidence. Run end to end against
the real kontina-backend BOM (633 components):

| Stage | Result |
| --- | --- |
| `scan-vulns.sh` | 618 purls queried against OSV → **521 vulnerabilities**, 112 with a CVE id, 402 with a CVSS vector |
| `merge-enrichment.sh` | 0 in KEV, 111 EPSS scores, 1 at EPSS ≥ 0.10 (CVE-2023-45288, 0.92) |
| `merge-assessment.sh` | requirements → properties, approval → annotation, VEX → `analysis` |

`scan-vulns.sh` joins on **purl, never CPE** — the normalisation step strips syft's guessed
CPEs precisely so nothing downstream is tempted to match on them.

### Three defects found by running it against real data

1. **The Go vulnerability database carries no severity.** `GO-2022-0646` has `severity:
   null`, so every Go finding arrived with no CVSS — and DEV-190 requires one. It aliases
   to `GHSA-f5pg-7wfw-84q9`, which does carry the vector. Following the alias raised
   coverage by 36 advisories.
2. **Duplicate vulnerabilities.** Several databases describe the same CVE:
   `golang.org/x/crypto` produced both `GHSA-v778-237x-gjrc` and `GO-2024-3321` for
   CVE-2024-45337 — two entries, one vulnerability, one component. 28 duplicates in 549
   entries, and each one double-counts in every downstream tally. Now merged by id, keeping
   every source's `osv-id`, ratings and affects so provenance survives.
3. **Sequential advisory fetches took 3m16s** for ~550 advisories — the difference between
   a CI step people run and one they skip. Parallelised to **56s**.

### Enrichment provenance is not decoration

`merge-enrichment.sh` writes the KEV `catalogVersion` and the EPSS `model_version` +
`score_date` into `metadata.properties`. CISA publishes only the *current* KEV catalog, so
a released bundle that does not record which snapshot it used cannot have its KEV verdicts
reconstructed. EPSS scores are not comparable across model versions either.

`kev` is tri-state: `true`, absent (checked, not in the catalog), or `"unknown"` (the feed
could not be read). A `false` derived from an unreachable feed would be a claim nobody
established.
