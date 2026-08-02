# VEX extension to the SOUP record

The data layer DEV-190 owns. Today a `.soups/**/*.json` record carries `package`,
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

**`detail`** — required alongside every `not_affected`, and product-specific. A code on its
own is not an argument. "Not exploitable" is not a detail.

**`response`** — optional, for `affected`: `can_not_fix`, `will_not_fix`, `update`,
`rollback`, `workaround_available`.

**Ownership.** VEX statements are authored by the **SOUP approver**, not by whoever is
annoyed by the alert. A `not_affected` is a defensible reachability claim about this
product, and it is the claim that suppresses a Slack alert in DEV-191.

**`under_investigation` expires.** It is a holding state, not a resting state — if it is
still `under_investigation` when the finding's mitigation deadline elapses, it reverts to
`affected` and alerts (see `classification-draft.md` §4). Without that rule
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

1. **Where the fix-or-VEX gate runs.** The merge *reports* vulnerabilities without an
   analysis; `soup-approval-verification-workflow` is where it should *block*. That workflow
   currently checks requirements and the version condition only — CVEs do not appear in it
   at all, so this is new behaviour rather than a tightening.
2. **Who may author a VEX statement.** `vars.SOUP_APPROVERS` already gates who may approve a
   SOUP. Reusing it for VEX is the obvious choice, but should be a decision, not a default.
3. **Approval fields are inconsistent.** The record in `qb-soups` has
   `approval.{date,by,condition}`; the approval workflow writes `by_url` as well; DEV-190
   assumes `is_temporary`. The merge tolerates all three shapes, but the schema should be
   pinned down.
