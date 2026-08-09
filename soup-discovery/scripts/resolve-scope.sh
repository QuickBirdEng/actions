#!/usr/bin/env bash
# Applies a repo's declared scope to the discovered candidates.
#
# The one property this exists for: **every candidate is either in scope with a reason
# or out of scope with a reason, and anything unclassified fails the run.**
#
# Without that, a new ecosystem appearing in the repo (someone adds a Go service, a
# Python job, a base image) silently either bloats the SBOM with test tooling or is
# silently omitted from it. Both are invisible failures, and the second is the one that
# matters for CVE scope: WI-006-03 wants "a new SOUP appeared" to be a review event.
#
# Usage: resolve-scope.sh <candidates.json> [.soup-scope.yml]

set -uo pipefail

CANDIDATES="${1:-candidates.json}"
SCOPE_FILE="${2:-.soup-scope.yml}"
OUTPUT="${SCOPE_OUTPUT:-scan-plan.json}"

for tool in jq yq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "::error::$tool required" >&2; exit 1; }
done
[[ -f "$CANDIDATES" ]] || { echo "::error::candidates file not found: $CANDIDATES" >&2; exit 1; }

if [[ ! -f "$SCOPE_FILE" ]]; then
  cat >&2 <<EOF
::error::no scope declaration found at $SCOPE_FILE

Discovery found $(jq -r '.candidate_count' "$CANDIDATES") candidates. Each needs a scope decision.
Create $SCOPE_FILE with an 'include:' and 'exclude:' list; every entry needs a 'reason'.
Run with SCOPE_SCAFFOLD=1 to emit a starting point with every candidate listed as unclassified.
EOF
  if [[ "${SCOPE_SCAFFOLD:-0}" == "1" ]]; then
    jq -r '"# Generated scaffold — classify every entry, then delete this comment.\ninclude: []\nexclude: []\n\n# Unclassified candidates:\n" +
           (.candidates | map("#   - id: \(.id)          # \(.ecosystem), ships=\(.ships), \(.markers | join(", "))") | join("\n"))' \
       "$CANDIDATES" > "$SCOPE_FILE.scaffold"
    echo "wrote $SCOPE_FILE.scaffold" >&2
  fi
  exit 1
fi

SCOPE_JSON=$(yq -o=json '.' "$SCOPE_FILE")

# A rule matches a candidate by exact id or by a path prefix on the marker.
PLAN=$(jq -n \
  --argjson cand "$(jq -c '.candidates' "$CANDIDATES")" \
  --argjson scope "$SCOPE_JSON" \
  '
  def rules(k): ($scope[k] // []);
  def matches($c; $r):
    ($r.id // null) as $id
    | ($r.path // null) as $p
    | (if $id != null then $c.id == $id else false end)
      or (if $p != null then ($c.markers | any(startswith($p))) else false end);

  # An exact id rule is more specific than a path prefix, so it wins. The case is real:
  # the same image can run in the local compose stack (excluded by path) and in
  # production (included by id). Only rules of equal specificity are a genuine conflict.
  def by_id($c; k):   (rules(k) | map(select((.id // null) != null and .id == $c.id)) | first);
  # bind the path of the rule before entering any(): inside any(), . is the marker string
  def by_path($c; k):
    (rules(k)
     | map(select((.path // null) as $p | $p != null and ($c.markers | any(startswith($p)))))
     | first);

  def classify($c):
    by_id($c; "include")   as $inc_id
    | by_id($c; "exclude") as $exc_id
    | by_path($c; "include")   as $inc_p
    | by_path($c; "exclude")   as $exc_p
    | (if $inc_id != null or $exc_id != null
         then {inc: $inc_id, exc: $exc_id}      # id level decides on its own
         else {inc: $inc_p,  exc: $exc_p} end) as $r
    | $r.inc as $inc | $r.exc as $exc
    | if $inc != null and $exc != null then
        $c + {decision:"conflict", reason:"matched both include and exclude at the same specificity"}
      elif $inc != null then
        $c + {decision:"include", reason:($inc.reason // "")}
      elif $exc != null then
        $c + {decision:"exclude", reason:($exc.reason // "")}
      else
        $c + {decision:"unclassified", reason:null}
      end;

  ($cand | map(classify(.))) as $all
  | {
      schema: "quickbird.soup-scan-plan/v1",
      counts: {
        total:        ($all | length),
        include:      ($all | map(select(.decision=="include"))      | length),
        exclude:      ($all | map(select(.decision=="exclude"))      | length),
        unclassified: ($all | map(select(.decision=="unclassified")) | length),
        conflict:     ($all | map(select(.decision=="conflict"))     | length)
      },
      unclassified: ($all | map(select(.decision=="unclassified")) | map({id, ecosystem, markers, ships})),
      conflicts:    ($all | map(select(.decision=="conflict"))     | map({id, markers})),
      # Includes as well as excludes: WI-006-09: Introduce says every entry carries a reason, and an
      # unexplained include is how test tooling ends up in the shipped inventory unnoticed.
      missing_reason: ($all | map(select((.decision=="exclude" or .decision=="include")
                                         and (.reason == "" or .reason == null))) | map({id, decision, markers})),
      scan: ($all | map(select(.decision=="include"))),
      excluded: ($all | map(select(.decision=="exclude")) | map({id, ecosystem, markers, reason}))
    }
  ')

echo "$PLAN" > "$OUTPUT"
jq -r '"scope: \(.counts.include) in, \(.counts.exclude) out, \(.counts.unclassified) unclassified, \(.counts.conflict) conflicting"' "$OUTPUT" >&2

STATUS=0

if [[ "$(jq -r '.counts.unclassified' "$OUTPUT")" != "0" ]]; then
  echo "::error::candidates with no scope decision — add each to include: or exclude: in $SCOPE_FILE" >&2
  jq -r '.unclassified[] | "::error::  unclassified: \(.id)  (\(.ecosystem), ships=\(.ships))  \(.markers | join(", "))"' "$OUTPUT" >&2
  STATUS=1
fi

if [[ "$(jq -r '.counts.conflict' "$OUTPUT")" != "0" ]]; then
  echo "::error::candidates matched by both include and exclude" >&2
  jq -r '.conflicts[] | "::error::  conflict: \(.id)  \(.markers | join(", "))"' "$OUTPUT" >&2
  STATUS=1
fi

# An exclusion without a reason is the failure mode this whole file exists to prevent:
# it is indistinguishable from an oversight six months later.
if [[ "$(jq -r '.missing_reason | length' "$OUTPUT")" != "0" ]]; then
  echo "::error::scope entries without a reason — an unexplained decision is not a decision" >&2
  jq -r '.missing_reason[] | "::error::  no reason (\(.decision)): \(.id)  \(.markers | join(", "))"' "$OUTPUT" >&2
  STATUS=1
fi

if [[ $STATUS -eq 0 ]]; then
  echo "wrote $OUTPUT — every candidate has a recorded decision" >&2
fi
exit $STATUS
