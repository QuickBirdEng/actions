#!/usr/bin/env bash
# The newest published bundle that is younger than what is deployed.
#
# track-lifecycle.py needs something to compare the running version against, or every finding
# reads as `open` and the state this whole lifecycle exists for -- a fix that is merged and
# waiting to ship -- cannot be told apart from nobody having looked. Measured on mindnet:
# 125 findings in the deployed v1.0.15 are gone in v1.1.0-qa2, four of them Track 1.
#
# A QA bundle rather than a scan of main, because it already exists and already covers the
# images. A scan of main can only read the manifests, and on mindnet those hold 34 of 1756
# findings -- the rest are OS packages inside the images we build.
#
# Younger than the deployed release, not merely the newest QA tag: an older QA bundle predates
# the deployment and every finding fixed since would read as still open, or worse, findings the
# deployment already carries would read as fixed.
#
# What this cannot say: the bundle is a snapshot at its tag, not the current state of main.
# Anything merged after it is invisible here. The tag is printed so the alert can date the claim.
#
# Usage: find-staged-bundle.sh <owner/repo> <deployed-version> <out-file>
#        prints the tag it chose; exit 1 when there is nothing newer to compare against
#        STAGED_RELEASES_JSON  read the release list from a file instead of the API -- for tests

set -uo pipefail

REPO="${1:?missing repo}"
DEPLOYED="${2:?missing deployed version}"
OUT="${3:?missing output path}"

releases() {
  if [[ -n "${STAGED_RELEASES_JSON:-}" ]]; then cat "$STAGED_RELEASES_JSON"; return; fi
  gh api "repos/$REPO/releases?per_page=100" --paginate 2>/dev/null
}

LIST=$(releases)
[[ -n "$LIST" ]] || { echo "::warning::could not read the releases of $REPO" >&2; exit 1; }

# published_at is null on a draft, and a draft is not something that was released.
SINCE=$(jq -r --arg t "$DEPLOYED" \
  '[.[] | select(.tag_name == $t) | .published_at // .created_at][0] // ""' <<<"$LIST")
if [[ -z "$SINCE" || "$SINCE" == "null" ]]; then
  echo "::warning::$DEPLOYED has no release, so nothing can be shown to be newer than it" >&2
  exit 1
fi

# One line per candidate: date, tag, asset url. Sorted so the newest is first.
CAND=$(jq -r --arg since "$SINCE" '
  [ .[]
    | select(.draft | not)
    | (.published_at // .created_at) as $d
    | select($d != null and $d > $since)
    | . as $r
    | (.assets[] | select(.name | test("^sbom-.*\\.cdx\\.json$")))
    | {d: $d, tag: $r.tag_name, url: .url} ]
  | sort_by(.d) | reverse | .[] | "\(.d)\t\(.tag)\t\(.url)"' <<<"$LIST")

[[ -n "$CAND" ]] || { echo "::warning::no bundle published after $DEPLOYED" >&2; exit 1; }

while IFS=$'\t' read -r date tag url; do
  [[ -z "$tag" ]] && continue
  # file:// so the path can be exercised without the API, the same way monitor-kev.sh takes a
  # local SBOM.
  if [[ "$url" == file://* ]]; then
    cp "${url#file://}" "$OUT" 2>/dev/null && HTTP=200 || HTTP=000
  elif [[ -n "${GH_TOKEN:-}" ]]; then
    HTTP=$(curl -sSL --max-time 180 -w '%{http_code}' \
      -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/octet-stream" \
      "$url" -o "$OUT" 2>/dev/null || echo 000)
  else
    HTTP=$(curl -sSL --max-time 180 -w '%{http_code}' \
      -H "Accept: application/octet-stream" "$url" -o "$OUT" 2>/dev/null || echo 000)
  fi
  if [[ "$HTTP" != "200" ]] || ! jq -e '.bomFormat == "CycloneDX"' "$OUT" >/dev/null 2>&1; then
    echo "::warning::$tag: bundle could not be read (HTTP $HTTP)" >&2
    : > "$OUT"; continue
  fi
  TIER=$(jq -r '[.metadata.properties[]? | select(.name=="quickbird:sbom:tier")][0].value // "unmarked"' "$OUT")
  # A branch bundle has no version identity, so it cannot be dated against a deployment.
  if [[ "$TIER" == "branch" ]]; then
    echo "::warning::$tag: branch bundle, skipped" >&2
    : > "$OUT"; continue
  fi
  echo "  comparing against $tag ($TIER, published ${date%%T*})" >&2
  echo "$tag"
  exit 0
done <<<"$CAND"

echo "::warning::no usable bundle newer than $DEPLOYED" >&2
exit 1
