#!/usr/bin/env bash
# Resolve what a product currently has deployed, and whether an SBOM exists for it.
#
# This is the input DEV-191/DEV-197 need: "scan the deployed version" has to resolve to
# something. The convention (decided 2026-08-02) is git tag + release assets, with the
# deploy step recording what went live.
#
# The script's job is as much to report when the question CANNOT be answered as to answer
# it. Three distinct negative results, deliberately not collapsed into one:
#
#   - no deployment recorded for an environment  -> we do not know what is running
#   - deployed ref is not a tag (a branch build) -> no release, therefore no SBOM
#   - deployed tag has no SBOM asset             -> released before the pipeline existed
#
# Reporting "unknown" is the correct answer to a question we cannot answer. Falling back to
# "the newest tag" would produce a confident wrong one.
#
# Usage: resolve-deployed.sh <owner/repo> [environment]

set -uo pipefail

REPO="${1:?usage: resolve-deployed.sh <owner/repo> [environment]}"
WANT_ENV="${2:-}"
ASSET_PATTERN="${SBOM_ASSET_PATTERN:-sbom-%s.cdx.json}"

for t in gh jq; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done

deployments=$(gh api "repos/$REPO/deployments?per_page=100" 2>/dev/null) || {
  echo "::error::cannot read deployments for $REPO" >&2; exit 1; }

if [[ "$(jq 'length' <<<"$deployments")" == "0" ]]; then
  jq -n --arg repo "$REPO" '{
    schema: "quickbird.deployed-version/v1",
    repo: $repo,
    resolvable: false,
    reason: "no GitHub deployments recorded — nothing states what is running, and the latest tag is not evidence of it",
    environments: []
  }'
  echo "::warning::$REPO: no deployments recorded — the deployed version is unknown" >&2
  exit 0
fi

# latest deployment per environment
latest=$(jq -c '[.[] | {env: .environment, ref: .ref, sha: .sha, at: .created_at, id: .id}]
                | group_by(.env) | map(sort_by(.at) | last)' <<<"$deployments")
[[ -n "$WANT_ENV" ]] && latest=$(jq -c --arg e "$WANT_ENV" 'map(select(.env == $e))' <<<"$latest")

out='[]'
while IFS=$'\t' read -r env ref sha at id; do
  [[ -z "$env" ]] && continue

  state=$(gh api "repos/$REPO/deployments/$id/statuses?per_page=1" --jq '.[0].state // "unknown"' 2>/dev/null)

  is_tag=false
  gh api "repos/$REPO/git/ref/tags/$ref" >/dev/null 2>&1 && is_tag=true

  sbom_url=""; sbom_state=""
  if $is_tag; then
    asset=$(printf "$ASSET_PATTERN" "$ref")
    sbom_url=$(gh api "repos/$REPO/releases/tags/$ref" \
                 --jq --arg a "$asset" '[.assets[] | select(.name==$a) | .browser_download_url][0] // ""' \
                 2>/dev/null || echo "")
    if [[ -n "$sbom_url" ]]; then
      sbom_state="available"
    else
      # Distinguish "no release" from "release without the asset" — different fixes.
      if gh api "repos/$REPO/releases/tags/$ref" >/dev/null 2>&1; then
        sbom_state="release exists but carries no $asset — released before the SBOM pipeline, or the publish step did not run"
      else
        sbom_state="tag exists but has no GitHub release, so there is nowhere for an SBOM asset to live"
      fi
    fi
  else
    sbom_state="deployed ref is not a tag — a branch build has no release and therefore no SBOM"
  fi

  out=$(jq -c --arg env "$env" --arg ref "$ref" --arg sha "$sha" --arg at "$at" \
           --arg state "$state" --argjson is_tag "$is_tag" \
           --arg url "$sbom_url" --arg sstate "$sbom_state" \
    '. + [{environment:$env, ref:$ref, sha:$sha, deployed_at:$at, status:$state,
           ref_is_tag:$is_tag, sbom: (if $url == "" then null else $url end),
           sbom_status:$sstate}]' <<<"$out")
done < <(jq -r '.[] | "\(.env)\t\(.ref)\t\(.sha)\t\(.at)\t\(.id)"' <<<"$latest")

jq -n --arg repo "$REPO" --argjson envs "$out" '{
  schema: "quickbird.deployed-version/v1",
  repo: $repo,
  environments: $envs,
  scannable: [$envs[] | select(.sbom != null) | .environment],
  unresolvable: [$envs[] | select(.sbom == null) | {environment, ref, why: .sbom_status}]
}'

# Warnings on stderr so a CI job surfaces them without parsing the JSON.
jq -r '.[] | select(.sbom == null)
       | "::warning::\(.environment): deployed ref \(.ref) has no SBOM — \(.sbom_status)"' <<<"$out" >&2
