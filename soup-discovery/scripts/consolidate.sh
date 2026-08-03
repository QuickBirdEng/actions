#!/usr/bin/env bash
# Merge the per-target BOMs into one self-contained CycloneDX document.
#
# Two readers want different things and both are legitimate:
#   - a dependency-tracking tool wants one BOM per shipped artifact, because a BOM has a
#     single metadata.component as its subject;
#   - an auditor or a regulatory submission wants one file that answers "what is in this
#     product" without following links.
# So the per-target BOMs stay, and this produces the consolidated one alongside them,
# self-contained rather than a set of pointers.
#
# Usage: consolidate.sh <product-name> <product-version> <out.cdx.json> <bom>...

set -uo pipefail

PRODUCT="${1:?usage: consolidate.sh <product> <version> <out> <bom>...}"
VERSION="${2:?missing product version}"
OUT="${3:?missing output path}"
shift 3
[[ $# -gt 0 ]] || { echo "::error::no input BOMs given" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || { echo "::error::jq required" >&2; exit 1; }

KEEP_TIMESTAMP="${KEEP_TIMESTAMP:-0}"
# release | staging | branch. Stamped into the document because a staging SBOM is a
# debugging artifact and a release SBOM is a controlled record, and they are otherwise
# indistinguishable — which is how one eventually reaches an auditor by accident.
SBOM_TIER="${SBOM_TIER:-branch}"
# Set to the list of in-scope candidates that could NOT be scanned (resolvable:false, or
# a scan that was skipped). Drives quickbird:sbom:complete — a consolidated BOM must say
# whether it is whole, because the incomplete case is easy to produce and hard to notice.
MISSING="${SBOM_MISSING:-}"

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

INPUTS=()
for b in "$@"; do
  [[ -f "$b" ]] || { echo "::error::BOM not found: $b" >&2; exit 1; }
  jq -e '.bomFormat == "CycloneDX"' "$b" >/dev/null 2>&1 \
    || { echo "::error::not CycloneDX: $b" >&2; exit 1; }
  INPUTS+=("$b")
done

# Each input's subject becomes a component of the product, and every edge rooted at that
# subject is remapped onto it. Without the remap each sub-BOM's root ref dangles and the
# consolidated document is schema-invalid.
jq -n \
  --arg product "$PRODUCT" \
  --arg version "$VERSION" \
  --argjson keep_ts "$KEEP_TIMESTAMP" \
  --arg missing "$MISSING" \
  --arg tier "$SBOM_TIER" \
  --slurpfile boms <(for b in "${INPUTS[@]}"; do jq -c '.' "$b"; done) \
  '
  ("quickbird:product:" + $product + "@" + $version) as $root

  # one component per input BOM, representing the scanned artifact itself
  | ( $boms | map(
        (.metadata.component // {name:"unknown"}) as $subj
        | { "bom-ref": ("quickbird:artifact:" + ($subj.name // "unknown")),
            type: ($subj.type // "application"),
            name: ($subj.name // "unknown"),
            version: ($subj.version // $version) }
      ) ) as $artifacts

  # old subject ref -> new artifact ref, for edge remapping
  | ( $boms | map(
        { key: ((.metadata.component["bom-ref"]) // (.metadata.component.name) // "?"),
          value: ("quickbird:artifact:" + (.metadata.component.name // "unknown")) }
      ) | from_entries ) as $remap

  # union of every component, deduplicated by bom-ref
  | ( [ $boms[] | .components[]? ]
      | group_by(."bom-ref" // (.purl // (.name + "@" + (.version // ""))))
      | map(.[0]) ) as $components

  | ( [ $boms[] | .dependencies[]? ]
      | map( .ref      |= ($remap[.] // .)
           | .dependsOn |= (map($remap[.] // .) // []) )
      | group_by(.ref)
      | map({ ref: .[0].ref, dependsOn: (map(.dependsOn[]?) | unique) }) ) as $deps

  | ($missing | if . == "" then [] else split(",") end) as $missing_list

  | {
      "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: (
        {
          component: {
            "bom-ref": $root,
            type: "application",
            name: $product,
            version: $version
          },
          properties: (
            [ { name: "quickbird:sbom:tier", value: $tier },
              { name: "quickbird:sbom:complete",
                value: (if ($missing_list | length) == 0 then "true" else "false" end) },
              { name: "quickbird:sbom:artifact-count", value: ($artifacts | length | tostring) } ]
            + ( $missing_list | map({ name: "quickbird:sbom:missing", value: . }) )
          )
        }
        + (if $keep_ts == 1 then {timestamp: (env.SBOM_TIMESTAMP // "")} else {} end)
      ),
      components: (($artifacts + $components) | sort_by((.name // ""), (.version // ""))),
      dependencies: (
        ( [ { ref: $root, dependsOn: ($artifacts | map(."bom-ref") | sort) } ] + $deps )
        | sort_by(.ref)
      )
    }
  ' > "$OUT" || { echo "::error::consolidation failed" >&2; exit 1; }

# bom-ref must be unique within a document. The "no component lost" check does not catch a
# violation, because a duplicated ref still leaves both entries present — the document is
# simply invalid. Found by feeding consolidation an input component whose ref collided with
# a generated `quickbird:artifact:*` ref: two components came out sharing one ref, and every
# check passed.
DUPES=$(jq -r '[.components[]."bom-ref"] | group_by(.) | map(select(length > 1) | .[0]) | .[]' "$OUT")
if [[ -n "$DUPES" ]]; then
  echo "::error::duplicate bom-ref in the consolidated document — CycloneDX requires them to be unique" >&2
  printf '::error::  duplicate: %s\n' $DUPES >&2
  echo "::error::  most likely an input component using a reserved quickbird:artifact:* ref" >&2
  exit 1
fi

TOTAL=$(jq '[.components[]] | length' "$OUT")
ARTIFACTS=$(jq '[.components[] | select(."bom-ref" | startswith("quickbird:artifact:"))] | length' "$OUT")
COMPLETE=$(jq -r '.metadata.properties[] | select(.name=="quickbird:sbom:complete") | .value' "$OUT")
RAW_SUM=$(for b in "${INPUTS[@]}"; do jq '[.components[]?] | length' "$b"; done | paste -sd+ - | bc)

{
  echo "consolidated ${#INPUTS[@]} BOMs -> $OUT"
  echo "  $RAW_SUM component entries in, $TOTAL out ($ARTIFACTS of them artifact subjects)"
  echo "  quickbird:sbom:complete = $COMPLETE"
} >&2

# Every component of every input must survive into the consolidated document. A silent
# loss here is the worst failure this file could have: the output still looks like a
# complete SBOM.
for b in "${INPUTS[@]}"; do
  LOST=$(jq -r --slurpfile out "$OUT" '
    ([$out[0].components[] | ."bom-ref"] | map({key:., value:true}) | from_entries) as $have
    | [ .components[]? | select($have[."bom-ref"] == null) | .name ] | length' "$b")
  if [[ "$LOST" != "0" ]]; then
    echo "::error::$LOST component(s) from $b are missing from the consolidated BOM" >&2
    exit 1
  fi
done
echo "  verified: no component lost from any input" >&2
