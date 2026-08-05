# What goes where

Three repositories are involved, and a file in the wrong one does not run.

| Directory | Destination | Contains |
|---|---|---|
| `workflows-repo/` | `QuickBirdEng/workflows/.github/workflows/` | The reusable workflows. `on: workflow_call` only — a reusable workflow that also declares `workflow_dispatch` takes its inputs from the dispatch form, so `product` arrives empty. |
| `product-repo/` | `<product>/.github/workflows/` | The thin callers. These own the triggers: the schedule, the manual trigger, the release hook. Fill in the placeholders in angle brackets. |
| `*.patch` | as named | One-off changes to existing files. |

The actions themselves (`soup-discovery/`, `kev-monitor/`) live in this repository and are referenced
as `QuickBirdEng/actions/<name>@main`. They have no triggers; a composite action never does.

## Wiring a product

1. Copy the three files from `product-repo/` into the product, replacing `<product>`, the Slack
   channel id, and in `soup-sbom.yml` the `name:` of the product's release workflow.
2. Add `.soup-policy.yml`, `.soup-scope.yml` and the CODEOWNERS entry — see
   `soup-discovery/examples/`.
3. Set the secrets: `DO_ACCESS_KEY`, `DO_SECRET_KEY`, `SLACK_BOT_TOKEN`, and
   `REGISTRY_USERNAME` / `REGISTRY_PASSWORD` where the product pulls private images. Without the
   store credentials a run keeps its records as 90-day workflow artefacts and the backstop cannot
   reconcile a longer period.
4. Run `soup-sbom.yml` manually for the current production tag, so the daily monitor has an
   inventory to resolve. Without it the monitor reports the product as having been released without
   one.
5. Run `soup-kev-monitor.yml` manually once and check the record before relying on the schedule.

Step 4 before step 5: the monitor resolves a deployed version to the inventory published for that
version, and reports the absence as a finding rather than assessing a different version.

## Order of the two automated workflows

`soup-sbom.yml` scans images by pulling them, so it has to run after the release workflow has pushed
them. The caller triggers on that workflow completing rather than on the tag push. Making the
reusable workflow a final job of the release workflow instead removes the ordering question, at the
cost of editing that workflow.
