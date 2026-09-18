# VEX extension to the SOUP record

The data layer the release bundle owns. Today a `.soups/**/*.json` record carries `package`,
`version`, `requirements{}` and `metadata.approval{}` — there is nowhere to record whether
a reported CVE actually applies to this product. This adds that, and `merge-assessment.sh`
serialises it into CycloneDX `vulnerabilities[].analysis`.

## Two new optional keys

```jsonc
{
  "package": "nestjs-epa-client",
  "metadata": { "input_version": "1.0.1", "approval": { … } },
  "requirements": { … },

  "risk_refs": ["HAZ-014", "RC-022"],

  "vex": {
    "CVE-2025-29927": {
      "state": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "detail": "The Next.js middleware path is never invoked; the connector uses only the REST client export."
    },
    "CVE-2024-3094": {
      "state": "affected",
      "response": "update",
      "detail": "Fix scheduled for 1.0.2."
    }
  }
}
```

`risk_refs` becomes `quickbird:soup:risk-ref` properties (ISO 14971 hazard / risk-control
IDs). `vex` becomes the `analysis` block on the matching vulnerability.

## Rules

**`state`** — exactly one of `not_affected`, `affected`, `fixed`, `under_investigation`.

**`justification`** — required for `not_affected`, and must be one of the five CSAF VEX 2.0
codes. CycloneDX 1.7 adopted the same vocabulary, so these are standard values rather than
house strings:

| Code | Means |
| --- | --- |
| `component_not_present` | The component is not actually in the shipped artifact. |
| `vulnerable_code_not_present` | The component ships, the vulnerable code does not. |
| `vulnerable_code_not_in_execute_path` | Present but never reached at runtime. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Reachable, but not with attacker-controlled input. |
| `inline_mitigations_already_exist` | An existing control in the product blocks exploitation. |

> **The table above is the CSAF 2.0 vocabulary; `merge-assessment.sh` validates against the
> CycloneDX 1.6 one.** The two name the same concepts differently, and a statement written
> with the codes above is rejected as `quickbird:vex:invalid-justification` — it does not
> suppress anything. Until the two are reconciled, write the code the implementation
> accepts: `code_not_present`, `code_not_reachable`, `requires_configuration`,
> `requires_dependency`, `requires_environment`, `protected_by_compiler`,
> `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`.

**`detail`** — required alongside every `not_affected`, and product-specific. A code on its
own is not an argument. "Not exploitable" is not a detail.

**`response`** — optional, for `affected`: `can_not_fix`, `will_not_fix`, `update`,
`rollback`, `workaround_available`.

**`covers`** — optional, a list of component names the statement also speaks for.

A transitive has no record of its own, so before this there was nowhere to put a
disposition for a finding under one: it stayed "no decision recorded" for good, which is
the mute button the states were meant to replace. The direct dependency that pulls the
transitive in is what the SOUP list actually approves, and its owner is the person who can
answer the reachability question, so its record is where the statement belongs.

```jsonc
"vex": {
  "CVE-2026-53571": {
    "state": "not_affected",
    "justification": "code_not_present",
    "covers": ["vite"],
    "detail": "The strapi runtime stage deletes /opt/node_modules/vite unless STRAPI_DEVELOPMENT_MODE=true, so it is not in the shipped image."
  }
}
```

Two guards, both of which refuse rather than assume:

- The covered component must be **named**. Nothing widens by accident — that was the
  cross-component defect, where the coverage map was keyed on the CVE alone.
- It must be **reachable from the covering component** in the BOM `dependencies` graph, so
  a record only ever speaks for its own subtree.

A claim failing either is dropped and reported as `quickbird:vex:covers-rejected` on the
vulnerability, never applied. That includes the ecosystems `mark-graph.py` derives no edges
for — go, python, container contents. With no graph a subtree claim cannot be checked, and
an unverifiable claim is worth less than a visible gap: findings inside a scanned image
still need a record on the affected component itself.

**Ownership — drafted by a developer, countersigned by a SOUP approver.** Decided
2026-08-02. The developer writes the statement, because whether the vulnerable code path is
reachable is a question about the code and the person who works in it is the one who knows.
A SOUP approver then countersigns.

The useful part: **no new mechanism is needed to enforce the countersign.** A VEX statement
lives in a `.soups/**/*.json` record, so adding one is a change to a SOUP file — which
already triggers `soup-approval-verification-workflow`, and that workflow already refuses
any approval not coming from `vars.SOUP_APPROVERS`. The countersign is structural rather
than procedural: a developer cannot merge their own VEX statement without an authorised
approver reviewing the PR.

What this does not do is check *who typed it*. The gate validates that a statement exists
and is well-formed; the review is what validates that someone with authority agreed. That
split is deliberate — a script cannot judge whether "not reachable from our code" is true,
and pretending otherwise would be the more dangerous design.

**`under_investigation` expires.** It is a holding state, not a resting state — if it is
still `under_investigation` when the finding's mitigation deadline elapses, it reverts to
`affected` and alerts (see WI-006-09-01: Classification of a finding, rule 0). Without that rule
`under_investigation` becomes the mute button `not_affected` was designed not to be.

**Scope — the approval is a version *family*, not a version.** The record's `version` field
carries the family (`1.x.x`), and `metadata.input_version` is merely the version that was
checked when the approval was granted. A component shipping 1.0.4 is covered by a record
that says `1.x.x` / checked `1.0.1`; it does not need re-approval for every patch bump.
`merge-assessment.sh` joins on the family for that reason — joining on `input_version`
would leave the component with no requirement properties *and* report the record as
orphaned, two wrong answers from one wrong join.

Both values are preserved in the BOM so the difference stays visible:
`quickbird:soup:approved-family` and `quickbird:soup:checked-version`. A new major version
is a new family and does need a fresh approval — verified: a 2.0.0 component does not match
a `1.x.x` record.

A VEX statement inherits that scope. It is bound to the family and to this product, and is
re-reviewed when the family changes.

## What the merge produces

Verified against a real record (`qb-soups:.soups/npm/nestjs-epa-client-1.x.x.json`) with an
approval and the block above added:

- 7 requirements → 14 `quickbird:soup:req:*` properties (`:fulfilled` + `:description`,
  plus `:reason` where a requirement is not met)
- `quickbird:soup:approved=true`, `quickbird:soup:record=npm/nestjs-epa-client-1.x.x.json`
- 2 `quickbird:soup:risk-ref` properties
- one `annotations[]` entry: annotator `grafele`, timestamp `2026-07-20T09:14:00Z`,
  text `SOUP approved by grafele (https://github.com/grafele); condition: >=1.0.1`
- 2 of 3 vulnerabilities given an `analysis` block; the third reported as
  **fix-or-VEX unsatisfied**

Components with no SOUP record are left untouched — that is normal for transitives, and the
count is reported rather than treated as an error.

## The consistency check nobody has today

The merge is the first thing that compares the SOUP list against the actual build. A record
matching no component means the two disagree: either a dependency was removed and its record
left behind, or the BOM is missing something. Both are worth knowing and neither is visible
today.

Reported as `quickbird:soup:orphaned-record` in the BOM and as a warning. Set
`ASSESSMENT_STRICT=true` to make it fail the run — recommended at release, where a stale
SOUP list is a documentation defect. Verified: a record for a package absent from the BOM
gives exit 0 lenient, exit 1 strict.

## Open questions for the approval workflow

1. ~~Where the fix-or-VEX gate runs.~~ **Resolved:** implemented as `check-fix-or-vex.sh`
   plus the `soup-fix-or-vex` action, wired into `soup-approval-verification-workflow`
   before approval is recorded.
3. **Approval fields are inconsistent.** The record in `qb-soups` has
   `approval.{date,by,condition}`; the approval workflow writes `by_url` as well; the release bundle
   assumes `is_temporary`. The merge tolerates all three shapes, but the schema should be
   pinned down.
