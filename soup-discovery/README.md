# SOUP discovery + SBOM

Discover every artefact in a repository that can contain third-party components, enforce a recorded
scope decision for each, scan what is in scope, and produce one assessed CycloneDX document per build.

The rules this implements — classification, timeframes, currency limits, responsibilities — are in the
Work Instruction in the QMS. `policy-defaults.yml` is its machine-readable counterpart, and a change to
one is a change to the other. Section references in this repository (`WI: Classification of a finding`, `Annex B B.1.1`) point
there.

## Usage

```yaml
- uses: QuickBirdEng/actions/soup-discovery@main
  with:
    product: my-product
    version: ${{ github.ref_name }}      # the release tag; not a placeholder
    release-tag: ${{ github.ref_name }}  # required when the tag did not trigger the run
```

Normally called through the reusable workflow `soup-sbom.yml` in `QuickBirdEng/workflows` rather than
directly; `patches/README.md` has the wiring and the triggers.

Standalone, for a local run:

```bash
scripts/run-pipeline.sh <product> <version> [repo-root]
```

Or stage by stage, which is also how the tests drive it:

```bash
scripts/discover.sh .                                    # -> candidates.json
SCOPE_SCAFFOLD=1 scripts/resolve-scope.sh candidates.json  # first run: emits a scaffold to classify
scripts/resolve-scope.sh candidates.json .soup-scope.yml  # -> scan-plan.json, or exit 1
scripts/assess-bom.sh bom/solution.cdx.json effective-policy.json
```

Prerequisites on the runner: `jq`, `yq`, `curl`, `docker`. syft is fetched at a pinned version if it is
not present — never `latest`, because the component list must not change because a scanner updated
itself between two runs of the same commit.

`KEEP_TIMESTAMP=1` when the document needs `metadata.timestamp`. Leave it unset for a committable,
diffable document: successive builds of the same commit then differ only where the components differ.

## The scope gate

Discovery lists candidates. Every candidate must appear in `.soup-scope.yml`, either included or
excluded, each with a reason:

```yaml
include:
  - id: backend
    reason: The service we ship. requirements.txt is the resolved set.
exclude:
  - id: dev-compose-cache
    reason: Local developer stack only, never deployed.
```

**A candidate in neither list stops the run.** Without that, "not listed" and "deliberately excluded"
look identical in the document, and the inventory can no longer claim to be complete.

The same component can legitimately be in scope in one place and out of scope in another — a cache image
in the deployment manifest is shipped, the same image in a developer compose file is not. Ids are per
artefact, not per component, so both decisions can be recorded and neither is a contradiction.

Two templates are in `examples/`: a straightforward one, and one that shows a justified relaxation —
the case the reason rule exists for.

## What a run produces

Under `sbom/`:

| File | Content |
|---|---|
| `candidates.json` | Everything discovery found, before any scope decision. |
| `scan-plan.json` | Candidates joined with their decision and reason. |
| `bom/<target>.cdx.json` | One document per scanned target. |
| `bom/solution.cdx.json` | The consolidated inventory: each component's originating artefact, the identity of each scanned image, and whether the inventory is complete. |
| `bom/solution.assessed.cdx.json` | The same document with vulnerabilities, enrichment provenance, VEX analysis, classification and remediation units. This is the release asset. |
| `bom/solution.assessed.pdf` | The readable rendering, with the document level on the cover. |
| `effective-policy.json` | Defaults merged with the project's configuration — what this run actually applied. |

Consolidation exists because two readers want different things and both are legitimate: a
dependency-tracking tool wants one document per shipped artefact, since a document has a single
`metadata.component` as its subject, while a reviewer wants one file that answers "what is in this
product" without following links. The consolidated document keeps the per-artefact subjects as
components of the product and carries each one's hashes and properties, so the digest of what was
scanned survives into the published bundle.

## Exit behaviour

| Situation | Result |
|---|---|
| A candidate has no scope decision | Run fails. |
| A produced document fails the gate — no components, missing purls, a component with no version | Run fails. |
| Consolidation loses a component | Run fails. |
| An in-scope artefact cannot be scanned — private registry without credentials, an image reference resolvable only at deploy time | Recorded as a named gap; `complete` is `false`. The run does not fail: the document has to state the gap, and failing would discard the evidence of it. |

## Property taxonomy

Everything recorded uses the `quickbird:` namespace, so a document can be audited after the fact: what
was scanned (`scan:image-digest`, `scan:image-id`, `scan:image-created`), which artefact a component came
from (`component:artifact`), which feed version produced the enrichment (`feed:kev-catalog-version`,
`feed:epss-model`, `feed:epss-score-date`), and the classification with both dated deadlines
(`finding:track`, `finding:rule`, `finding:mitigation-due`, `finding:remediation-due`,
`finding:clock-start`).

The EPSS model version is part of the finding, not decoration: scores are not comparable between model
versions, so a threshold reviewed against one model says nothing about the next.

## Known limitations

- **An image reference substituted at deploy time cannot be resolved from the repository.** It is
  recorded as a gap with that reason. Resolving it needs the deployment record.
- **Our own release-versioned images** carry the chart `appVersion`, so the concrete version is known
  only from the deployment record. Their contents are covered by the Dockerfile candidate that builds
  them.
- **Go binaries and Android APKs** are discovered and scanned, but no product has exercised those paths
  end to end.
- **Version staleness inside a release family**: where a patch is published for an older minor line, the
  currency check reports the distance to the newest release overall. It does not know which line a
  product follows.
- **Declared is not resolved.** A build file lists declared dependencies; the resolved closure needs the
  build tool to run. Where the closure cannot be resolved, the document says so rather than presenting
  the declared set as complete.

## Scripts and tests

`scripts/` holds one script per stage, each runnable on its own — which is how they are tested.
`run-pipeline.sh` and `assess-bom.sh` are the two entry points; Annex B in the QMS lists what each
script does.

`tests/run-tests.sh` — cases that hit live feeds are skipped unless `TEST_NETWORK=1` is set.
