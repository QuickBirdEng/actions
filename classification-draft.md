# SOUP & SBOM Vulnerability Management Process — §2.1 Classification and Timeframes

**Status: DRAFT / working copy.** Not a controlled record. This drafts the section that
[DEV-190](https://quickbird.atlassian.net/browse/DEV-190),
[DEV-191](https://quickbird.atlassian.net/browse/DEV-191) and
[DEV-192](https://quickbird.atlassian.net/browse/DEV-192) all reference as the "classification source
of truth", and which is currently not findable as a released document. Scope is deliberately narrow:
the decision function (which finding gets which deadline), the two clocks, the VEX rules, and the
currency policy. Everything else in the process document is out of scope here.

Anchored to what already exists, so this does not contradict prior decisions:

- `GDG-004-01 Streamlined Proposal (2026-07-01)` — the track shape ("KEV/Critical immediate,
  High/Medium bundled to next release"), the Basic-tier annual backstop, the detection tools
  (Dependabot / OSV Scanner / Docker Scout), and the three acceptance criteria quoted in §6.
- `WI-006-03 SOUP Management` — the SOUP approver role, which this section extends to VEX authorship.
- DEV-191's stated defaults — Critical 72 h / 21 d, High 20 d / 40 d.

---

## 1. Scope and inputs

This section classifies **known vulnerabilities in third-party components** (SOUP, transitive
dependencies, container base images, OS packages) of a released product. It does not classify
first-party defects — those follow the problem-resolution process and the SLA severity table.

Four inputs, in this precedence order:

| Input | Source | Role in the decision |
| --- | --- | --- |
| **Applicability (VEX)** | `.soups/**/*.json`, authored by the SOUP approver | Gate. A justified `not_affected` removes the finding from the tracks entirely. |
| **KEV membership** | CISA KEV catalog (`catalogVersion`) | Overrides CVSS upward. Actively exploited in the wild. |
| **EPSS score** | EPSS bulk feed (`model_version` + `score_date`) | Escalates within CVSS bands. Probability of exploitation in the next 30 days. |
| **CVSS base score** | NVD / advisory source, with vector | Baseline band only. Never the sole input. |

**CVSS alone is not a disposition.** It measures theoretical severity of the vulnerability, not the
risk to this product. KEV and EPSS are what make the tracks defensible, and applicability is what
makes them finite.

---

## 2. Track assignment (the decision function)

Evaluated top to bottom; **the first matching rule wins.**

| # | Condition | Track |
| --- | --- | --- |
| 0 | VEX state is `not_affected` **with** a valid justification (§4) | **Not applicable** — recorded, no clock, no alert |
| 1 | CVE is in the CISA KEV catalog | **1 — Immediate** |
| 2 | CVSS base ≥ 9.0 (Critical) | **1 — Immediate** |
| 3 | CVSS base 7.0–8.9 (High) **and** EPSS ≥ 0.50 | **1 — Immediate** |
| 4 | CVSS base 7.0–8.9 (High) | **2 — Expedited** |
| 5 | CVSS base 4.0–6.9 (Medium) **and** EPSS ≥ 0.10 | **2 — Expedited** |
| 6 | CVSS base 4.0–6.9 (Medium) | **3 — Planned** |
| 7 | CVSS base 0.1–3.9 (Low) **and** EPSS ≥ 0.10 | **3 — Planned** |
| 8 | CVSS base 0.1–3.9 (Low) | **4 — Monitor** |
| 9 | No CVSS score available | **2 — Expedited**, until a score exists |

Rule 9 is deliberate: an unscored finding is an unknown, not a low. It is triaged as High until the
advisory is scored or a VEX statement resolves it.

### 2.1 EPSS thresholds

Defaults: **0.10** (elevated) and **0.50** (high). **Configurable per project** — the values live in
the per-project config alongside the alert threshold and the deadlines (DEV-191), not hard-coded in
the classifier. Changes are recorded with a rationale.

These are policy choices, not properties of EPSS. They are set where they are because 0.10 already
selects a small fraction of all scored CVEs while covering a large share of what actually gets
exploited, and 0.50 is high enough that combining it with a High CVSS justifies pre-empting the
Critical track. **Both thresholds must be re-reviewed whenever the EPSS model version changes** —
scores are not comparable across model versions (see §5).

### 2.2 Latching

Once a finding enters a track, **it does not move to a lower track.** It may only move *up*.

Reason: EPSS is recalculated daily and decays. Without latching, a Track 1 finding drops to Track 2 a
week later, the deadline moves outward, and the audit trail shows a deadline that was never breached
because it kept receding. A finding leaves its track only by being remediated (§3) or by receiving a
justified `not_affected` (§4).

New KEV membership or a rescored CVSS **does** escalate an existing finding, and the new track's clock
starts from the date of escalation, not retroactively.

---

## 3. Timeframes — the two clocks

Every track carries **two independent deadlines**. Both start when the finding is first reported by a
scan of the **deployed version** (per DEV-191), or on the date an `under_investigation` statement
resolves to `affected`.

**The clock starts at our discovery, not at CVE publication** (decided 2026-08-02). A CVE published
three weeks before our feed picked it up still gets its full deadline from the day our scan first
reported it. The reason is that the alternative would generate breaches for periods in which we could
not have known, which makes the breach signal meaningless. The trade this accepts is that a slow feed
silently extends every deadline — so **the scan interval is itself a control**, and the dated per-run
records in the evidence store are what make the discovery date auditable rather than merely asserted.

| Track | Mitigation deadline | Remediation deadline |
| --- | --- | --- |
| **1 — Immediate** | 72 h | 21 d |
| **2 — Expedited** | 20 d | 40 d |
| **3 — Planned** | 30 d | next regular release (see §3.4) |
| **4 — Monitor** | — | next regular release; reconciled at the backstop |

**All values are calendar time, not service hours.** This differs from the support SLA table in
`GDG-004-01`, where TTR is counted in service hours (Mon–Fri 09:00–18:00). The difference is
intentional — an actively exploited vulnerability does not pause over the weekend — and must stay
explicit wherever both tables are read together. Where a customer SLA is stricter than a track
deadline, the stricter value governs.

### 3.1 What satisfies each clock

**Mitigation** — exposure is measurably reduced, and the measure is documented:

- a fix merged to `main` **plus** a scheduled release date, or
- a compensating control in the deployed system (network restriction, WAF rule, feature flag,
  configuration change, disabling the unused component), or
- a documented determination that no exposure exists which does not meet the bar for a VEX
  `not_affected` (e.g. reachable but not exploitable in this configuration).

**Remediation** — the fix is **live in the version users run.** Nothing else stops this clock.

This is the load-bearing rule of the whole section. A merged fix is not a remediation, because the
deployed product is still vulnerable. It maps directly onto DEV-191's three finding states: `open` →
`fix ready – release pending` (mitigation met, remediation still running) → `deployed / resolved`.

### 3.2 Release-required signal

A Track 1 finding in state `fix ready – release pending` whose **remediation** deadline falls before
the next scheduled release raises a **release-required** signal: an out-of-band bugfix release is
needed to meet the deadline. This is the only mechanism by which vulnerability management can force a
release, and it is deliberately narrow — Track 1 only.

### 3.3 Breach

A missed deadline is not silently absorbed. On breach:

1. The finding is escalated in the project's Slack channel with an explicit deadline-breached marker.
2. A documented decision is required within 5 working days: revised remediation date, or a risk
   acceptance.
3. A **risk acceptance** requires an ISO 14971 re-evaluation of the affected hazard and **one
   approver**, who may be the SOUP approver of the affected component. It is recorded,
   time-limited, and re-reviewed at the backstop.

   *Decided 2026-08-02. Two stricter variants were considered and rejected: a PRRC signature
   disjoint from the SOUP approver, and two signatures of any kind. Both were judged
   disproportionate at this team size. The controls that carry the weight instead are the ones
   that do not depend on headcount: the acceptance is written down, it expires, and the backstop
   re-reviews it. If an auditor challenges the single signature, that is the argument, and the
   escalation path is to require a second reviewer for Track 1 acceptances only.*
4. Safety relevance is assessed for MDR Art. 87 vigilance reportability, per the problem-resolution
   process already defined in the maintenance plan.
5. For products in scope of the CRA (see §7), a KEV finding additionally triggers the 24 h
   actively-exploited reporting assessment.

### 3.4 What "next regular release" means

Decided 2026-08-02: **each project declares its release cadence in its configuration**, and
the Track 3/4 deadline is derived from it — next scheduled release plus a grace period.

The alternative, a flat 90-day ceiling for everyone, was rejected as too blunt: a product
shipping fortnightly and one shipping twice a year should not carry the same Track 3
deadline.

Two consequences that follow, and have to be handled rather than assumed away:

- **A project without a declared cadence has no Track 3/4 deadline.** That must surface as
  a configuration gap in the monitoring run, not as an absent deadline that quietly looks
  like compliance. Same principle as the scope gate: unclassified fails loudly.
- **A declared cadence can go stale.** If a project declares "monthly" and has not released
  in five months, the derived deadline is fiction. The backstop report compares the declared
  cadence against the actual release history and flags the divergence; that check is what
  keeps this field honest. Measured on 2026-08-03: Mindnet holds, Osteocoach, Dermafy and
  Alvie do not.
- **"Actual release history" is itself a per-project declaration.** A GitHub repo offers three
  signals for "this release went to production" — the tag shape, the `prerelease` flag, and a
  `-production` release asset — and across this portfolio they disagree by up to 315 days on
  the same repo. Because Track 3 remediation *is* "next release", the choice of signal sets a
  deadline, so each project declares it (`production_release.detect_by`) and the backstop
  reports a disagreement between the three rather than silently picking one. This is also
  what decides whether a build is a release or a staging document (§5.2), so a project cannot
  redefine one without redefining the other.
- **A project may have no releases at all.** Apellis deploys every merge by git SHA and has
  neither tags nor releases. Declaring a cycle there would manufacture a deadline out of
  releases that never happen, so the cadence is declared `continuous` and measured against the
  *deploy* history with a ceiling on the gap rather than a cycle. Track 3's "next release"
  then means the next deploy, which is stricter than any declared cycle, not looser. The first
  measurement of this immediately found that none of Apellis's recorded deployments names a
  production environment, so the check reports `unknown` rather than healthy.

---

## 4. Applicability — VEX rules

VEX is what keeps the applicable set finite. It is also the single easiest control to abuse, so the
rules are tighter than the format requires.

**Ownership.** A VEX statement is **drafted by a developer and countersigned by a SOUP approver**
(decided 2026-08-02). Reachability is a question about the code, so the person who works in it writes
the claim; authority to accept it stays with the approvers. Because the statement lives in a SOUP
record, the countersign is enforced by the existing approval workflow rather than by a new rule — a
developer cannot merge their own `not_affected`.

**States.** `not_affected` · `affected` · `fixed` · `under_investigation`.

**Justification vocabulary** for `not_affected` — exactly one of, aligned to CSAF VEX 2.0 (and
therefore to CycloneDX 1.7, which adopted the same vocabulary):

| Justification | Means |
| --- | --- |
| `component_not_present` | The component is not actually in the shipped artifact. |
| `vulnerable_code_not_present` | The component ships, the vulnerable code does not. |
| `vulnerable_code_not_in_execute_path` | Present but never reached at runtime. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Reachable, but not with attacker-controlled input. |
| `inline_mitigations_already_exist` | An existing control in the product blocks exploitation. |

A justification code alone is not sufficient: every `not_affected` also carries a free-text `detail`
stating *why*, specific to this product. "Not exploitable" is not a detail.

**`under_investigation` expires.** It is a holding state, not a resting state. If it is still
`under_investigation` when the track's **mitigation** deadline elapses, it defaults to `affected` and
the finding alerts. Without this rule `under_investigation` becomes the mute button that
`not_affected` was designed not to be.

**Scope.** A VEX statement is bound to a component version range and a product. It does not
automatically carry over to a new major version of the component, and it is re-reviewed when the
component version changes.

**Where it lives.** In the SOUP records (`.soups/**/*.json`) as the authoritative, living source, per
DEV-190. The release bundle serialises a point-in-time copy into CycloneDX
`vulnerabilities[].analysis`. When the two differ, the SOUP record is authoritative for *current*
applicability and the bundle is authoritative for *what was known at release* — both are correct, for
different questions.

---

## 5. Reproducibility of a classification

A track assignment must be reconstructable months later. Every classification therefore records:

| Field | Why |
| --- | --- |
| CVSS base score, **vector**, and source | Scores get revised; the vector shows which one was used. |
| KEV `catalogVersion` | Pins the catalog snapshot. |
| EPSS `model_version` **and** `score_date` | The score date alone is insufficient — see below. |
| EPSS score and percentile as read | The value the decision actually used. |
| Rule number from §2 that matched | Makes the decision auditable without re-running the logic. |
| Track, both deadlines, and the clock start date | The clock start is the audit-relevant fact. |

**The EPSS model version is not optional.** EPSS has moved from v4 (from 2025-03-17) to v5 (from
2026-06-15), and scores are not comparable across model versions. Recording only a date would make a
0.42 from June and a 0.42 from July look like the same evidence. The bulk feed carries both on its
first line:

```
#model_version:v2026.06.15,score_date:2026-07-31T12:03:43Z
```

which is one reason to prefer the bulk feed over per-CVE lookups — the lookup API returns a `date`
but no model version.

**Stale feeds are flagged, never silently tolerated.** If a feed cannot be refreshed, the run
proceeds with the last cached snapshot and marks every affected classification as based on stale data,
naming the snapshot age. A scan that cannot reach the KEV catalog has not established that a CVE is
not in KEV.

---

### 5.1 Base images and their OS packages

Decided 2026-08-02: **the base image is the SOUP; its OS packages are not.**

What we select and approve is `nginx:mainline-alpine`, not the ~600 Debian packages inside it.
Those packages are:

- **fully enumerated in the SBOM** — they are configuration items and they are in CVE scope,
- **classed `transitive`** — no individual approver, no per-package requirement evaluation,
- **not subject to the currency policy individually** — the base image is what gets bumped.

The practical weight of this: mindnet carries ~960 OS packages across deb, apk and rpm. Requiring a
SOUP evaluation per package would produce a thousand records that nobody reads, at the cost of the
attention that the ~30 direct dependencies actually deserve.

What follows from it is the obligation the decision creates rather than removes: **a CVE in an OS
package is remediated by bumping the base image**, so base images must be pinned by digest and bumped
deliberately. A base image pinned to a floating tag cannot be remediated in a way anyone can verify.

### 5.2 Which SBOMs are records, and which are not

An SBOM is produced for **every tagged build**, staging included. Nothing about that is a compliance
requirement — it is generated because a component list is only useful for comparison if an earlier one
exists. A dependency that appears for the first time at the release tag is discovered too late for
`WI-006-03` to treat its arrival as a review event, and a pipeline that only runs at release is a
pipeline that fails at release.

But a staging document and a release document render identically, and that is the risk worth
designing against: sooner or later one of them is forwarded to a customer or a notified body.
What prevents that is the tier recorded **inside** the document (`quickbird:sbom:tier`), stated
above everything else on page one of the PDF — not where the file is kept.

The tier follows the **tag shape**, which is the same signal §3.4 uses to decide which releases
are production ones. A project that redefines `production_release.tag_pattern` redefines this at
the same time, so the two cannot drift.

| | release tier (`v1.0.15`) | staging tier (`v1.0.15-qa4`) | branch tier (no tag) |
|---|---|---|---|
| Attached to its own release | yes — the controlled record | yes, as `sbom-v1.0.15-qa4.cdx.json` on the prerelease | refused: no version identity |
| Read by continuous monitoring | yes | yes, **if that is what got deployed** | refused |
| Recorded in the monitoring evidence | `sbom_tier: release` | `sbom_tier: staging` | n/a |
| Timestamped | yes (`--release`) | no, so successive builds stay diffable | no |

Staging bundles are attached to their own prerelease rather than kept only as a 90-day
workflow artifact, because an artifact that has expired cannot be pulled when someone needs to
know what a build contained. The asset name carries the tag, so the two are not confusable by
name either.

What the monitor requires is **not** a release-tier document but the document that describes
the version actually deployed. If a product deploys a pre-release tag to production — and the
release flags on Dermafy and Alvie suggest some do — then the staging-tier bundle is the
correct document for what is running, and refusing it would break monitoring for exactly the
products that most need it. A `branch` bundle is refused, because it carries no version
identity and nothing could tie it to a deployment. The tier is written into the evidence
record either way, so a reader is never left assuming which kind of document a scan rested on.

## 6. Dependency currency policy

Separate concern from CVEs: how far a dependency may lag behind its latest version. A component with
no known CVE can still be unmaintainable, and IEC 81001-5-1 expects components to be kept reasonably
current.

**Default policy, per semver level:** 0 major behind · 1 minor behind · unlimited patch behind.
Configurable per project.

**Upstream staleness is a second, separate test.** A component whose latest release is itself
older than **12 months** is treated as no longer maintained. This is deliberately not the same
finding as being behind, because it has a different answer: when we are behind, the answer is to
upgrade; when upstream has stopped releasing, there is nothing to upgrade to and the answer is
replacement or documented acceptance. A component can be perfectly current *and* stale — being
on the newest version of an abandoned library is exactly the case the semver test cannot see.
The 12-month window matches the analysis period the SOUP records already use in `grq-3` ("Is
maintained and support is available").

One measurement caveat, because it produced a wrong answer in testing: npm's `modified`
timestamp is not a release date. For `request` it reads 2026-07-17 while the last actual
release was 2020-02-11 — five and a half years apart. Staleness is therefore computed from the
newest **version publish time**, never from registry metadata that any change touches.

- A dependency outside policy is flagged in the **overview and the backstop report**. On its own it is
  **not** a Slack alert — it becomes urgent only when it coincides with an applicable CVE.
- A per-SOUP justification overrides the policy, recorded in the existing SOUP `reason` field. This is
  the mechanism behind the acceptance criterion "Remaining non-current dependencies are justified".
- At release, the release gate checks direct production dependencies against the policy ("libs
  current" hygiene). Transitive dependencies are in scope for CVEs but not for the currency check.

---

## 7. Tier and cadence

| | **Basic** | **Extended** |
| --- | --- | --- |
| Automated scan of deployed version | daily | daily |
| Backstop reconciliation report | annual | quarterly |
| Track 3 remediation ceiling | 90 d | 60 d |
| Risk-acceptance re-review | at backstop | quarterly |

The backstop exists because automation fails silently. It reconciles the evidence store against the
released versions and confirms that every product was actually scanned, that every open finding has a
current disposition, and that time-limited risk acceptances have not quietly expired.

**Regulatory scope note.** Products regulated as medical devices under MDR/IVDR are currently outside
the CRA's product requirements (CRA Art. 2). This does **not** make the CRA irrelevant here:
body-worn wearables are in scope; companion apps, cloud services and update infrastructure that are
not themselves MDR devices are in scope; and the Commission proposed in December 2025 to remove the
medical-device exemption. From **11 September 2026**, in-scope products must report *actively
exploited* vulnerabilities within **24 hours** — which is why KEV membership is Track 1 unconditionally
and why the scan target is the deployed version. Per-product CRA scope is determined once and recorded
in the project configuration.

---

## 8. Acceptance criteria this section serves

Verbatim from `GDG-004-01`, so the mapping is explicit:

| Acceptance criterion | Satisfied by |
| --- | --- |
| "Known applicable vulnerabilities are remediated within the defined timeframes" | §2 (applicable), §3 (timeframes) |
| "Non-applicable findings carry a justified VEX statement" | §4 |
| "Remaining non-current dependencies are justified" | §6 |

---

## 9. Decisions taken and what stays open

Decided 2026-08-02, each recorded in the section named:

| Topic | Decision | §  |
| --- | --- | --- |
| Risk-acceptance sign-off | One approver, who may be the SOUP approver | 3.3 |
| Clock start | At our discovery, not at CVE publication | 3 |
| Track 3/4 deadline | Derived from a per-project release cadence | 3.4 |
| VEX authorship | Developer drafts, SOUP approver countersigns | 4 |
| Base-image OS packages | The image is the SOUP; packages are transitive | 5.1 |
| EPSS thresholds | 0.10 / 0.50, configurable per project | 2.1 |

Decided 2026-08-03:

| Topic | Decision | § |
| --- | --- | --- |
| Which SBOMs are records | Tier in the document, from the tag shape; staging attached to its own prerelease | 5.2 |
| What the monitor requires | The document describing the deployed version, not a release-tier one | 5.2 |
| "Production release" | Per-project signal (`production_release.detect_by`); disagreement is reported | 3.4 |
| Products without releases | `release_cadence: continuous`, measured against deploys with a gap ceiling | 3.4 |
| Upstream staleness | 12 months without a release, tested separately from semver currency | 6 |

### Standing review items

Not open questions — things that must be re-examined on a trigger rather than decided once:

1. **EPSS thresholds** must be re-checked whenever the EPSS model version changes, because scores are
   not comparable across versions, and against our own finding history once DEV-191 has a few months
   of data.
2. **Declared release cadences** must be compared against actual release history at each backstop.
   A cadence that no longer matches reality turns every Track 3 deadline into fiction (§3.4).
3. **Base images must stay digest-pinned.** §5.1 makes bumping the image the remediation route for an
   OS-package CVE; a floating tag makes that unverifiable.

### Still genuinely open

1. **The approval field schema is inconsistent.** Records in `qb-soups` carry
   `approval.{date,by,condition}`; the approval workflow additionally writes `by_url`; DEV-190 assumes
   `is_temporary`. The tooling tolerates all three shapes, but the schema should be pinned down before
   the PDF and the approval annotation are treated as controlled output.
2. **Tier assignment per product** (Basic / Extended) drives the backstop cadence in §7 and is not
   recorded anywhere yet.
3. **Track 3/4 remediation has no computed deadline yet.** §3.4 and §7 describe one; the
   classifier currently writes the cadence and the ceiling into a *basis string* and leaves
   `remediation_due` empty, so 210 of 521 findings on a real product carry no date and cannot
   breach. Blocked on one decision: when a declared cadence is longer than the tier ceiling
   (Dermafy declares biannual, tier Basic caps Track 3 at 90 d), which governs. Until that is
   answered, §3.4 describes an intent rather than a control.
4. **The first scan of a product starts every clock at once.** §3 starts both clocks at first
   discovery, so onboarding a product with a backlog produces its whole backlog as
   simultaneously-due findings — on Kontina that is 23 Track 1 findings with a 72 h mitigation
   deadline on day one. No onboarding provision exists; without one, every product's first run
   is a breach event.
5. **§5.1 rewards leaving an image unpinned.** The section requires base images to be
   digest-pinned so that bumping the image is a verifiable remediation. But an unpinned image
   cannot be scanned reproducibly, so scope files exclude it — meaning pinning an image brings
   its CVEs into scope while leaving it floating keeps them out. Currently affects 5 of 8
   Apellis `FROM` lines and three `curl:latest` health-check cronjobs. The incentive needs
   inverting: an unpinned in-scope image should be a finding, not an exclusion.
6. **The regulatory claim in §7 needs an owner's confirmation.** "The Commission proposed in
   December 2025 to remove the medical-device exemption" is the kind of statement an auditor
   will test, and it should be verified by whoever holds regulatory accountability before this
   becomes a controlled document.
