# soup-discovery: implementation reference

What the tooling is made of: which component does what, which files a run produces, which
keys a project sets, where objects are stored.

This states no rules. Classification, timeframes, currency limits, escalation and
responsibilities are in the work instruction WI-006-09 Dependency and Vulnerability
Management, which governs.

## Where the tooling lives

Repository `QuickBirdEng/actions`. Two composite actions, called by a product's own workflows. Both take the product's configuration from the product repository; neither holds product-specific values.

Three repositories are involved, and the split matters because a file in the wrong one does not run:

Repository| Holds  
---|---  
QuickBirdEng/actions| The composite actions. An action never has a trigger of its own; it runs when a workflow calls it.  
QuickBirdEng/workflows| The reusable workflows, with `on: workflow_call` only. Staged in this repository under `patches/workflows-repo/`.  
The product repository| A thin caller per workflow. **This is where every trigger lives.** Staged under `patches/product-repo/`.  
  
A reusable workflow must not declare `workflow_dispatch` itself: the inputs then come from the dispatch form rather than from the caller, so `product` arrives empty and `runs-on` arrives as an empty string, which fails `fromJSON` before any step runs.

Reusable workflow| Triggered by the caller on | Does  
---|---|---  
soup-sbom.yml | `workflow_run` of the product's release workflow, completed and successful; `workflow_dispatch` with a tag | WI-006-09, Inventory, via the `soup-discovery` action.  
soup-kev-monitor.yml | `schedule`, daily at a per-product minute; `workflow_dispatch` | WI-006-09, Observe, via the `kev-monitor` action.  
soup-backstop.yml | `schedule`, matching the product's `reconciliation_interval`; `workflow_dispatch` with a window | WI-006-09, Reconcile. Reads the period's records back out of the object store.  
  
Each of the three can be started manually, and each has a reason to be: to produce the inventory of a version released before the workflow existed, to reproduce a run whose record is questioned, and to reconcile a period on demand.

### Why the SBOM workflow is not triggered by the tag push

The release workflow is what pushes the images of a tag. The pipeline scans an image by pulling it and records the digest of what it pulled, so an image that is not in the registry yet becomes a gap. The caller therefore waits for the release workflow rather than starting alongside it.

This is also why the action takes the tag as an input rather than reading `github.ref_name`. Under `workflow_run` the ref is the default branch, and the bundle would be attached to a release named after it and stored under the branch prefix. Making the reusable workflow a final job of the release workflow instead removes the ordering question, at the cost of editing that workflow.

### Scripts

Grouped by the stage they serve. Each is runnable on its own, which is how they are tested; the two orchestrating scripts are the entry points a workflow calls.

Script| Purpose  
---|---  
run-pipeline.sh| **Entry point for a build run.** Fetches syft pinned if absent, then runs the sequence below. Non-zero if a candidate lacks a scope decision, if a produced document fails the gate, or if consolidation loses a component.  
discover.sh| Find candidates: dependency manifests per ecosystem, Dockerfile stages, images referenced by Helm charts and Compose files. Resolves `{{ .Values.x }}` against the chart's own `values.yaml`; an unresolvable reference is emitted as `@unresolved` rather than guessed.  
wait-for-release-runs.sh| `workflow_run` fires when *one* named workflow finishes, never when all have. Where two release workflows produce different parts of the inventory — one pushing the images, another the android BOM — the faster one starts the scan while the slower is still building. Waits for the runs of this tag that are still going, names any that failed, and continues either way: a gap with a reason beats no document.  
filter-gradle-lockfile.sh| A `gradle.lockfile` written by `dependencyLocking { lockAllConfigurations() }` tags every configuration onto one line undifferentiated. Filters it to the runtimeClasspath entries, and any line with no discernible tag, before syft ever sees it.  
resolve-scope.sh| Join candidates against the scope declaration. Exits non-zero on the first unclassified candidate.  
resolve-tier.sh| Document level from the tag shape, not from `github.ref_type`, which is `tag` for a QA tag too. Fails loudly on an invalid `tag_pattern` rather than falling through to a level.  
normalize-bom.sh| Per scanned target: record the identity. Image digest, image id, manifest digest and the image build date. Needs syft's native format as well as CycloneDX, because only the native one carries them.  
verify-bom.sh| Gate a produced document before it is merged: schema, a non-empty component list, purls present.  
consolidate.sh| Merge the per-target documents into one, stamping each component with the artefact it came from and carrying the target's hashes and properties onto the artefact component.  
assess-bom.sh| **Entry point for assessment.** Six stages: scan, enrich, merge enrichment, merge SOUP records and VEX, classify, check currency. Exists because the stages were separate scripts and two of them were called by nothing, so the enrichment never reached the document and no finding was ever given a deadline.  
scan-vulns.sh| Vulnerabilities per component, joined on purl.  
merge-enrichment.sh| KEV membership and EPSS onto the vulnerabilities, feed provenance into the metadata: KEV catalog version, EPSS model version and score date.  
merge-assessment.sh| SOUP requirement results, approval annotations and VEX analysis into the document.  
classify-findings.py| WI-006-09-01, Classification of a finding and Timeframes: track, both dated deadlines, latching, onboarding baseline. Annotates a contradiction where a SOUP record claims no known vulnerabilities while the scan reports some.  
group-remediation.py| WI-006-09-01, What carries the timeframe: findings into remediation units, and the vendor state of a third-party image.  
maintenance-windows.py| WI-006-09-01, The maintenance window: the window grid, and whether a window was met, missed or is still open.  
mark-scope.py| Reads the direct/transitive decision from the manifests per ecosystem (pubspec markers, package.json join, pom declarations, go.mod indirect flags, gradle declarations) and stamps it onto each component. Containers: contents transitive, the image itself direct.  
mark-graph.py| Derives the dependency graph per ecosystem and writes standard CycloneDX dependencies[] edges into the per-target BOM. npm: from the lockfiles (yarn v1 and berry, package-lock v2/v3 with nearest-first resolution). pub: one registry call per hosted package; dependency names resolve against the locked versions. gradle: the POM of each locked artifact names its runtime dependencies; every version resolves against the lockfile. Registry fetches degrade per package. Ecosystems without a derivable graph keep no edges; operating-system packages inside images arrive with edges from syft.  
check-currency.py| WI-006-09-02, Currency and obsolescence: version distance and upstream staleness. Operating-system packages excluded; container images checked by build date.  
check-fix-or-vex.sh| WI-006-09, Assess: the pull-request gate. Every vulnerability of the version needs a fix or a VEX statement.  
resolve-deployed.sh| The deployed version from the GitHub deployment record, and its published inventory from the release asset.  
monitor-kev.sh| The daily run. Refuses to exit 0 on an empty or invalid record, because an empty record read as success is indistinguishable from an all-clear.  
track-lifecycle.py| Today's findings against yesterday's record: new, breached, resolved.  
escalate-breaches.py| Breaches per remediation unit, with the decision deadline of WI-006-09, Decide.  
compose-alert.sh| The notification. Four independent blocks, so a non-KEV breach is notified even when there is no KEV finding.  
backstop-report.py| WI-006-09, Reconcile. Production deployments per repository, maintenance windows, expired risk acceptances, drift in the parameters of WI-006-09-02, Scope of the product, Service level and Onboarding, and whether this reconciliation itself fired as often as `reconciliation_interval` promises. The last one needs `--previous`, the earlier reports.  
validate-policy.sh| Merge project configuration onto the defaults. Refuses a missing required parameter, an interval that is not a duration, a loosened value without a reason, and the two configurations TR-03161 forbids (WI-006-09, BSI TR-03161).  
render-sbom-pdf.py| The SBOM report: composition only, direct dependencies with supplier/licence and record, every transitive/OS component with its via-path and containing artefact, scanned artefacts with digests; sections subdivided by platform. One per release; contains nothing that ages.  
render-vdr-pdf.py| The Dependency & Vulnerability Report: the dated assessment against the configured rules, applied-rules block with config/default source, updates beyond and within the limits, CVEs per library with EPSS, via-path, fixed-in and VEX, stale/deprecated, remediation actions; sections subdivided by platform. Rows shaded by decision state.  
  
## What a build run produces

Under `sbom/` in the workspace. The two files in bold are the output; the rest are intermediates, kept because a question about a run is usually a question about one stage of it.

File| Content  
---|---  
candidates.json| Everything discovery found, before the scope decision.  
scan-plan.json| Candidates joined with their scope decision and reason.  
bom/<target>.cdx.json| One document per scanned target.  
bom/<target>.syft.json| The native scan output. Deleted after the identity has been recorded, on the gap paths too.  
**bom/solution.cdx.json**|  The consolidated inventory: components, their artefact, the identity of each scanned image, and whether the inventory is complete.  
**bom/solution.assessed.cdx.json**|  The same document with vulnerabilities, enrichment provenance, VEX analysis, classification and remediation units. This is the release asset.  
bom/solution.assessed.pdf| The readable rendering.  
effective-policy.json| Defaults merged with the project configuration — the values this run actually applied.  
  
Findings and dispositions live inside the assessed document rather than beside it, so that a finding cannot become separated from what was decided about it.

## What a daily run produces

File| Content  
---|---  
deployed.json| Which version the deployment record names, and which asset its inventory was taken from.  
findings.json| Today's classified findings.  
remediation-units.json| The grouping, with each unit's track, deadline and member findings.  
maintenance-windows.json| The grid and the state of each window.  
<target>.lifecycle.json  
<target>.escalation.json | Lifecycle states and deadline escalation per target; merged into one product view inside the dated record.  
currency.json| Version distance and staleness per component.  
state-<target>.json  
lifecycle-state-<target>.json | Carried to the next run, one pair per live target: clock starts and latched tracks. Without them, a track could drop when EPSS falls and take its deadline with it; with one shared file, a product with two live targets restarted the second one's clocks on every run.  
escalation.json| Breaches and their decision deadlines.  
**< YYYY-MM-DD>-<product>.json**| The dated record. Written on every run, including runs with no findings.  
  
## The three files a project owns

All three in the product repository, under version control, with CODEOWNERS on the first two. A snippet is in `soup-discovery/examples/CODEOWNERS.snippet`.

File| Holds| Reviewer  
---|---|---  
.soup-policy.yml| The parameters of WI-006-09-02, Parameters defined per project. Only what differs from the defaults.| QM, for the service-level and scope parameters  
.soup-scope.yml| `include:` and `exclude:`, each entry an `id` and a `reason`. The run fails while a discovered candidate appears in neither.| Development lead  
.soup-scope.yml, `built_image` on an include entry| The image a Dockerfile candidate actually produces, `${version}` substituted from the run. Without it the candidate is scanned from its FROM line, which is the *base* image: anything the Dockerfile adds afterwards is missing from the inventory and anything it deletes is still reported. Declared rather than derived — the reference lives in a compose file and a release workflow, and the naming between them is per-product. May be a single reference or a map of tier (`staging`, `candidate`, `branch`) to reference, for a product that pushes `<version>-staging` from one release workflow and `<version>` from another. A declaration that cannot be applied stops the run; a version the run does not know, or a tier the map does not name, makes the candidate a reported gap, never a silent fallback to the base image.| SOUP approver  
.soup-decisions.yml| Risk acceptances, revised remediation dates and `vendor_requests` with their follow-up dates.| SOUP approver  
  
## Configuration keys

Defaults ship as `soup-discovery/policy-defaults.yml`. A project sets only what differs. Meaning, who decides each value and where it comes from: WI-006-09-02, Parameters defined per project.

Key| Default| Note  
---|---|---  
product| —| Required.  
cra_scope| unknown| Required to be stated explicitly.  
maintenance_interval| —| Required. No upper bound is enforced.  
reconciliation_interval| 12m| How often the reconciliation runs. The cron in the product caller has to match it.  
regulatory_scope| []| `tr-03161-1|-2|-3`, `cra`, `mdr`. An unknown entry fails the run.  
tracks.<track>.mitigation  
tracks.<track>.remediation | WI-006-09-01, Timeframes| `none`, a duration, or `next-release`.  
epss.elevated / epss.high| 0.10 / 0.50| —  
breach.decision_within| 5d| —  
breach.risk_acceptance_approvers| 1| —  
dependency_currency.max_behind  
.major / .minor / .patch | 0 / 1 / unlimited | `unlimited` patch is refused in TR-03161 scope.  
dependency_currency.stale_after| 12m| —  
dependency_currency.  
stale_exempt_publishers| dart.dev, flutter.dev| Publishers whose staleness is answered by the process rather than per product: an SDK-pinned package releases on the platform cadence and can never look current. Keyed on the registry-*verified* publisher, which today only pub.dev exposes — an npm `author` string is free text and never earns it. Answers staleness only; being behind the update limit still owes an upgrade. Adding a publisher is a widening and needs `dependency_currency.reason`.  
dependency_currency.  
obsolescence_may_be_accepted| false | `true` is refused in TR-03161 scope.  
production_release.tag_pattern| ^v?\d+\\.\d+\\.\d+$ | Selects the document level only.  
onboarded  
baseline_clocks_start| — | Deliberately without a default: a default would hand a product a baseline nobody agreed to.  
alerts.threshold| high| KEV and breaches are not subject to it.  
alerts.slack_channel| —| Without it, runs are recorded and nobody is notified.  
process_version| date| Stamped into every record, so a record states which version of the rules produced it.  
  
## Object store layout

Space `quickbird-soup-artifacts`, region `fra1`, dedicated to SOUP data so a sync of it never pulls in unrelated build artefacts. Credentials per product as repository secrets.

Prefix| Content  
---|---  
<repo>/soup-sbom/<level>/<ref>/ | Inventory and rendering per build. The level segment keeps candidate documents apart from staging and branch documents. `<ref>` is the tag, or the commit for a product that deploys without tags, for such a product this is the only durable location.  
<repo>/soup-evidence/<year>/ | The dated records. The year segment lets the backstop sync one prefix.  
<repo>/soup-backstop/<year>/ | Reconciliation reports. Read back by the next reconciliation, which is how a schedule that drifted from `reconciliation_interval` becomes visible.  
  
The release asset carries a fixed name, `sbom-<tag>.cdx.json`, because the daily run looks for exactly that. A per-project naming scheme would make the lookup guesswork.

## Properties recorded in the document

CycloneDX property namespace `quickbird:`. These are what makes a document auditable after the fact: what was scanned, by what, against which feed version.

Property| States  
---|---  
quickbird:sbom:tier| Candidate, staging or branch.  
quickbird:sbom:complete| Whether every in-scope artefact was scanned.  
quickbird:sbom:missing| One entry per gap, with its reason.  
quickbird:scan:image-digest  
quickbird:scan:image-id | What was scanned, as opposed to the tag that was requested.  
quickbird:scan:image-created| The image build date, for the age check.  
quickbird:component:artifact| Which artefact a component came from.  
quickbird:soup:approval-drift  
quickbird:soup:record-version-mismatch | A SOUP approval exists and does not cover the shipped version, on the component, and as a per-record line in the metadata. A review event (WI-006-09, Observe), distinct from an orphaned record.  
quickbird:feed:kev-catalog-version  
quickbird:feed:epss-model / :epss-score-date| Which feed version produced the enrichment. EPSS scores are not comparable between model versions, so the version is part of the finding.  
quickbird:finding:track / :rule / :why / :cvss  
:mitigation-due / :remediation-due / :*-overdue  
:clock-start | The classification on the vulnerability itself: track, matched rule, score, both dated deadlines and their overdue state. What the PDF renders as the assessment.  
quickbird:dependency:scope | `direct`, `dev` (build/test tooling, chosen, in the inventory, not shipped, no record required) or `transitive`, from the manifests. Absence means undetermined. The coverage figure and the currency selection stand on this.  
quickbird:soup:direct-without-record  
(+ :direct-without-record-name) | A component the manifests mark as a direct choice, with no SOUP record, chosen, shipped, never approved. Count in the metadata, one named entry per component.  
quickbird:currency:latest  
:status / :detail | The latest available version next to the shipped one, per component: current, behind, stale, stale-and-behind, or unknown with the reason.  
quickbird:currency:publisher  
:stale-exempt | The registry-verified publisher (pub only), and the process-default reason where one answers this component's staleness. The row stays in section 4 of the report either way — the staleness is a fact — but an exempt row is unshaded and carries the reason instead of "No decision recorded."  
quickbird:vuln:fix | `available`, `prerelease-only`, `none-published` or `unknown`. `prerelease-only` means upstream has a fix but only as an alpha/rc, which a released product cannot adopt: the work is to track the stable release, not to bump. Separate from `none-published`, where no fix exists at all and the answer is a compensating control or a VEX statement.  
  
The scanner version is pinned, currently syft 1.51.0, and never `latest`: the component list must not change because a scanner updated itself between two runs of the same commit.

## Implementation limits

Limit| Effect  
---|---  
Untested scan paths | Go binaries and Android APKs are discovered and scanned, but no product has exercised them end to end. A gap there would surface as a gap in the document rather than as a silent omission.  
Version staleness inside a family | Where a patch release is published for an older minor line, the currency check reports the distance to the newest release overall. It does not know which line the product follows.  
Unresolvable image references | A reference that cannot be resolved from the repository, a value injected at deploy time — becomes a gap. It cannot be resolved without reading the cluster, which is not a source this process uses.  
Store credentials | Without them a run keeps its records as workflow artefacts, which expire after 90 days. The run does not fail, so the absence shows up only at the backstop.  
No write-once protection | The object store has no object lock configured. It holds the working copies and the observation records; the records that carry the retention period are attached to the release page in Confluence.  
Upload action age | The upload action's newest release is from February 2024 and it publishes no moving major tag, so it is pinned to an exact version. As a product dependency it would be an obsolescence finding.
