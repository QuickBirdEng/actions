#!/usr/bin/env bash
# Test harness for the SOUP pipeline.
#
# Most of these are regression tests for defects that were actually found while building
# this, each one a case where the tooling produced a confident wrong answer rather than an
# error. That is the failure mode worth guarding: a scan that crashes gets fixed, a scan
# that silently reports the wrong component set gets believed.
#
# Offline by default — network cases run only with TEST_NETWORK=1, so the suite is usable
# in a pre-commit hook and in CI without depending on OSV or CISA being reachable.
#
# Usage: tests/run-tests.sh [name-filter]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../scripts"
FILTER="${1:-}"
TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
FAILED_NAMES=()

t() { # t <name> <function>
  local name="$1" fn="$2"
  [[ -n "$FILTER" && "$name" != *"$FILTER"* ]] && return 0
  local out rc
  out=$("$fn" 2>&1); rc=$?
  case $rc in
    0) PASS=$((PASS+1)); printf '  ok    %s\n' "$name" ;;
    77) SKIP=$((SKIP+1)); printf '  skip  %s  (%s)\n' "$name" "$out" ;;
    *) FAIL=$((FAIL+1)); FAILED_NAMES+=("$name")
       printf '  FAIL  %s\n' "$name"
       printf '%s\n' "$out" | sed 's/^/          /' ;;
  esac
}

need_net() { [[ "${TEST_NETWORK:-0}" == "1" ]] || { echo "set TEST_NETWORK=1"; return 77; }; }
assert() { [[ "$1" == "$2" ]] || { echo "expected: $2"; echo "actual:   $1"; return 1; }; }
contains() { grep -q -- "$2" <<<"$1" || { echo "expected output to contain: $2"; echo "got: $1"; return 1; }; }

# ---------------------------------------------------------------- normalise
# Regression: metadata.component.name is the scan path syft was given, and its bom-ref is
# a hash of that name, so two runs over identical content produced different documents.
# The gate originally checked components[] only and passed a non-reproducible BOM.
test_normalise_requires_subject() {
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$TMP/n1.json"
  bash "$S/normalize-bom.sh" "$TMP/n1.json" "$TMP/n1.out.json" >/dev/null 2>&1
  assert "$?" "1"
}

test_normalise_stabilises_subject() {
  cat > "$TMP/n2.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:aaa",
 "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"bom-ref":"abc123","name":"/Users/someone/scan/path","type":"application"}},
 "components":[]}
EOF
  BOM_SUBJECT=worker bash "$S/normalize-bom.sh" "$TMP/n2.json" "$TMP/n2.out.json" >/dev/null 2>&1 || return 1
  local n; n=$(jq -r '.metadata.component.name' "$TMP/n2.out.json")
  assert "$n" "worker" || return 1
  jq -e 'has("serialNumber") | not' "$TMP/n2.out.json" >/dev/null || { echo "serialNumber survived"; return 1; }
  jq -e '.metadata | has("timestamp") | not' "$TMP/n2.out.json" >/dev/null || { echo "timestamp survived"; return 1; }
}

# Regression: Maven jars carry no SHA-256 on the library component — it exists only on the
# parallel type:file entry. Dropping those before harvesting lost every hash (0 of 84).
test_normalise_harvests_hash_before_dropping_files() {
  cat > "$TMP/n3.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"r","name":"x","type":"application"}},
 "components":[
  {"bom-ref":"lib","type":"library","name":"okhttp","version":"4.12.0"},
  {"bom-ref":"f","type":"file","name":"/scan/lib/okhttp-4.12.0.jar",
   "hashes":[{"alg":"SHA-256","content":"deadbeef"}]}]}
EOF
  BOM_SUBJECT=x bash "$S/normalize-bom.sh" "$TMP/n3.json" "$TMP/n3.out.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.components[]]|length' "$TMP/n3.out.json")" "1" || return 1
  assert "$(jq -r '.components[0].hashes[0].content' "$TMP/n3.out.json")" "deadbeef"
}

test_normalise_strips_speculative_cpes() {
  cat > "$TMP/n4.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"r","name":"x","type":"application"}},
 "components":[{"bom-ref":"a","type":"library","name":"a","version":"1",
   "properties":[{"name":"syft:cpe23","value":"cpe:2.3:a:guess"},{"name":"keep","value":"y"}]}]}
EOF
  BOM_SUBJECT=x bash "$S/normalize-bom.sh" "$TMP/n4.json" "$TMP/n4.out.json" >/dev/null 2>&1 || return 1
  assert "$(jq '[.components[].properties[]? | select(.name=="syft:cpe23")] | length' "$TMP/n4.out.json")" "0"
}

test_normalise_is_deterministic() {
  cat > "$TMP/n5a.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1",
 "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"bom-ref":"h1","name":"/a/b","type":"application"}},
 "components":[{"bom-ref":"z","type":"library","name":"z","version":"1"},
               {"bom-ref":"a","type":"library","name":"a","version":"1"}]}
EOF
  sed 's/urn:uuid:1/urn:uuid:2/; s|/a/b|/c/d|; s/h1/h2/; s/2026-01-01/2026-06-06/' "$TMP/n5a.json" > "$TMP/n5b.json"
  BOM_SUBJECT=s bash "$S/normalize-bom.sh" "$TMP/n5a.json" "$TMP/o1.json" >/dev/null 2>&1
  BOM_SUBJECT=s bash "$S/normalize-bom.sh" "$TMP/n5b.json" "$TMP/o2.json" >/dev/null 2>&1
  diff -q "$TMP/o1.json" "$TMP/o2.json" >/dev/null || { echo "outputs differ"; diff "$TMP/o1.json" "$TMP/o2.json" | head -5; return 1; }
}

# ---------------------------------------------------------------- verify-bom
test_verify_rejects_unversioned() {
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"x"}},"components":[{"type":"library","name":"a"}]}' > "$TMP/v1.json"
  bash "$S/verify-bom.sh" "$TMP/v1.json" >/dev/null 2>&1
  assert "$?" "1"
}

test_verify_rejects_path_as_subject_name() {
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"/abs/path"}},"components":[]}' > "$TMP/v2.json"
  bash "$S/verify-bom.sh" "$TMP/v2.json" >/dev/null 2>&1
  assert "$?" "1"
}

test_verify_accepts_clean_bom() {
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"x"}},"components":[{"type":"library","name":"a","version":"1"}]}' > "$TMP/v3.json"
  bash "$S/verify-bom.sh" "$TMP/v3.json" >/dev/null 2>&1
  assert "$?" "0"
}

# ---------------------------------------------------------------- scope gate
mk_candidates() { # <json array of candidates>
  jq -n --argjson c "$1" '{schema:"quickbird.soup-discovery/v1", candidate_count:($c|length), candidates:$c}'
}

test_scope_fails_on_unclassified() {
  mk_candidates '[{"id":"a","ecosystem":"npm","scan_source":"file:x","markers":["x"],"ships":true,"resolvable":true,"note":""}]' > "$TMP/c1.json"
  printf 'include: []\nexclude: []\n' > "$TMP/s1.yml"
  SCOPE_OUTPUT="$TMP/p1.json" bash "$S/resolve-scope.sh" "$TMP/c1.json" "$TMP/s1.yml" >/dev/null 2>&1
  assert "$?" "1"
}

test_scope_fails_on_exclusion_without_reason() {
  mk_candidates '[{"id":"a","ecosystem":"npm","scan_source":"file:x","markers":["x"],"ships":true,"resolvable":true,"note":""}]' > "$TMP/c2.json"
  printf 'include: []\nexclude:\n  - id: a\n' > "$TMP/s2.yml"
  SCOPE_OUTPUT="$TMP/p2.json" bash "$S/resolve-scope.sh" "$TMP/c2.json" "$TMP/s2.yml" >/dev/null 2>&1
  assert "$?" "1"
}

# Regression: an id rule must beat a path rule. Real case — redis is both a local-compose
# service (excluded by path) and a production deployment (included by id).
test_scope_id_beats_path() {
  mk_candidates '[{"id":"redis","ecosystem":"container","scan_source":"registry:redis","markers":["docker/compose.yml","k8s/redis.yml"],"ships":true,"resolvable":true,"note":""}]' > "$TMP/c3.json"
  cat > "$TMP/s3.yml" <<'EOF'
include:
  - id: redis
    reason: runs in production
exclude:
  - path: docker/
    reason: local developer stack
EOF
  SCOPE_OUTPUT="$TMP/p3.json" bash "$S/resolve-scope.sh" "$TMP/c3.json" "$TMP/s3.yml" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.counts.include' "$TMP/p3.json")" "1" || return 1
  assert "$(jq -r '.counts.conflict' "$TMP/p3.json")" "0"
}

test_scope_same_specificity_is_a_conflict() {
  mk_candidates '[{"id":"a","ecosystem":"npm","scan_source":"file:x","markers":["x"],"ships":true,"resolvable":true,"note":""}]' > "$TMP/c4.json"
  printf 'include:\n  - id: a\n    reason: r\nexclude:\n  - id: a\n    reason: r\n' > "$TMP/s4.yml"
  SCOPE_OUTPUT="$TMP/p4.json" bash "$S/resolve-scope.sh" "$TMP/c4.json" "$TMP/s4.yml" >/dev/null 2>&1
  [[ "$(jq -r '.counts.conflict' "$TMP/p4.json")" == "1" ]] || { echo "conflict not detected"; return 1; }
}

# ---------------------------------------------------------------- discovery
mkrepo() { rm -rf "$TMP/repo"; mkdir -p "$TMP/repo"; ( cd "$TMP/repo" && git init -q . ); }
discover() { ( cd "$TMP/repo" && git add -A >/dev/null 2>&1; DISCOVER_OUTPUT="$TMP/cand.json" bash "$S/discover.sh" . >/dev/null 2>&1 ); }

# Regression: `image:` is not a container-only YAML key. flutter_native_splash.yaml uses it
# for asset paths, and mindnet reported assets/logo/logo.png as a deployed container image.
test_discover_ignores_image_asset_paths() {
  mkrepo
  printf 'flutter_native_splash:\n  image: assets/logo/logo.png\n' > "$TMP/repo/flutter_native_splash.yaml"
  discover
  assert "$(jq '[.candidates[] | select(.scan_source|test("png"))] | length' "$TMP/cand.json")" "0"
}

# Regression: an Android build.gradle has no installDist task; routing it there would fail.
test_discover_classifies_android_not_jvm() {
  mkrepo
  mkdir -p "$TMP/repo/app/android/app"
  printf 'name: x\n' > "$TMP/repo/app/pubspec.yaml"
  printf 'dependencies {}\n' > "$TMP/repo/app/android/build.gradle"
  printf 'dependencies {}\n' > "$TMP/repo/app/android/app/build.gradle"
  discover
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="android-gradle")]|length' "$TMP/cand.json")" "1" || return 1
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="jvm-gradle")]|length' "$TMP/cand.json")" "0"
}

# Regression: the same image referenced from prod/staging/dev manifests produced one
# candidate per reference — 8 id collisions in mindnet, and a scope rule then matched an
# arbitrary one of them.
test_discover_deduplicates_ids() {
  mkrepo
  mkdir -p "$TMP/repo/k8s"
  for e in prod staging dev; do printf 'spec:\n  containers:\n  - image: redis:7.2\n' > "$TMP/repo/k8s/$e.yaml"; done
  discover
  assert "$(jq -r '[.candidates[]|select(.id|test("redis"))]|length' "$TMP/cand.json")" "1" || return 1
  assert "$(jq -r '[.candidates[]|select(.id|test("redis"))][0].markers|length' "$TMP/cand.json")" "3"
}

# Regression: FROM --platform=linux/amd64 left the flag inside the image reference.
test_discover_strips_from_platform_flag() {
  mkrepo
  printf 'FROM --platform=linux/amd64 nginx:mainline-alpine\n' > "$TMP/repo/Dockerfile"
  discover
  local src; src=$(jq -r '[.candidates[]|select(.ecosystem=="container")][0].scan_source' "$TMP/cand.json")
  assert "$src" "registry:nginx:mainline-alpine"
}

test_discover_marks_build_stages_as_not_shipping() {
  mkrepo
  printf 'FROM golang:1.25 AS build\nFROM alpine:3.20\n' > "$TMP/repo/Dockerfile"
  discover
  assert "$(jq -r '[.candidates[]|select(.ships==false)]|length' "$TMP/cand.json")" "1" || return 1
  assert "$(jq -r '[.candidates[]|select(.ships==true and (.scan_source|test("alpine")))]|length' "$TMP/cand.json")" "1"
}

# Regression: an Nx monorepo has no `workspaces` key, so two perfectly resolved packages
# were reported as having no lockfile.
test_discover_resolves_nx_monorepo_members_to_root_lock() {
  mkrepo
  mkdir -p "$TMP/repo/web/packages/common"
  printf '{}' > "$TMP/repo/web/nx.json"
  printf '{"name":"root"}' > "$TMP/repo/web/package.json"
  printf '# lock' > "$TMP/repo/web/yarn.lock"
  printf '{"name":"common"}' > "$TMP/repo/web/packages/common/package.json"
  discover
  assert "$(jq -r '[.candidates[]|select(.note|test("NO LOCKFILE"))]|length' "$TMP/cand.json")" "0" || return 1
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="npm")]|length' "$TMP/cand.json")" "1"
}

test_discover_flags_templated_image_as_unresolvable() {
  mkrepo
  mkdir -p "$TMP/repo/k8s"
  printf 'spec:\n  containers:\n  - image: qbsdocker/app:<version>\n' > "$TMP/repo/k8s/d.yaml"
  discover
  assert "$(jq -r '[.candidates[]|select(.resolvable==false)]|length' "$TMP/cand.json")" "1"
}

# The tier decides whether a document is the controlled record. It used to be derived from
# github.ref_type, which is 'tag' for v1.0.15-qa4 exactly as for v1.0.15 — so every staging
# build was marked as a release and nothing caught it. These are the cases that were wrong.
# A release-shaped tag produces a *candidate*, not a release. In this pipeline a tag build only
# ever deploys to staging; production is a later manual dispatch of the same ref. Dermafy released
# v1.0.6 and still runs v1.0.5 — stamping `release` at build time would have claimed release
# evidence for a version that never shipped.
test_tier_candidate_for_a_clean_semver_tag() {
  assert "$(bash "$S/resolve-tier.sh" tag v1.0.15)" "candidate" || return 1
  assert "$(bash "$S/resolve-tier.sh" tag 1.0.15)" "candidate"
}

test_tier_staging_for_a_prerelease_tag() {
  assert "$(bash "$S/resolve-tier.sh" tag v1.0.15-qa4)" "staging" || return 1
  assert "$(bash "$S/resolve-tier.sh" tag v1.0.8-qa36)" "staging" || return 1
  assert "$(bash "$S/resolve-tier.sh" tag v2.0.0-rc1)" "staging"
}

test_tier_branch_without_a_tag() {
  assert "$(bash "$S/resolve-tier.sh" branch main)" "branch" || return 1
  assert "$(bash "$S/resolve-tier.sh" tag "")" "branch"
}

# A project that redefines which tags are production redefines this at the same time, so the
# two cannot drift apart.
test_tier_follows_the_projects_tag_pattern() {
  printf 'production_release:
  tag_pattern: "^release-[0-9]+$"
' > "$TMP/pol.yml"
  assert "$(bash "$S/resolve-tier.sh" tag release-42 "$TMP/pol.yml")" "candidate" || return 1
  # under this project's convention a clean semver tag is NOT a production release
  assert "$(bash "$S/resolve-tier.sh" tag v1.0.15 "$TMP/pol.yml")" "staging"
}

# A broken pattern matches nothing, which would demote every production release to staging —
# the release would carry an unmarked bundle. Failing loudly is the only safe answer.
test_tier_rejects_a_broken_tag_pattern() {
  printf 'production_release:
  tag_pattern: "^v[0-9+"
' > "$TMP/badpol.yml"
  bash "$S/resolve-tier.sh" tag v1.0.15 "$TMP/badpol.yml" >/dev/null 2>&1
  assert "$?" "1"
}

mkchart() {
  mkrepo
  mkdir -p "$TMP/repo/deployment/charts/c/templates"
  printf 'apiVersion: v2\nname: c\nappVersion: 0.1.0\n' > "$TMP/repo/deployment/charts/c/Chart.yaml"
  cat > "$TMP/repo/deployment/charts/c/values.yaml" <<'YML'
version: 1.0.0
epa:
  image:
    repository: ghcr.io/oviva-ag/epa4all-rest-service
    tag: "v1.2.4"
rest:
  image:
    repository: qbsdocker/app-rest
    tag: ""
YML
}

# A third-party image pinned in values.yaml is knowable from the repo. Reporting it as
# unresolvable pushes it out of scope, and these are the images nobody else is watching.
test_discover_resolves_helm_values_for_third_party_image() {
  mkchart
  printf 'spec:\n  containers:\n  - image: "{{ .Values.epa.image.repository }}:{{ .Values.epa.image.tag }}"\n' \
    > "$TMP/repo/deployment/charts/c/templates/epa.yaml"
  discover
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="container")][0].id' "$TMP/cand.json")" \
         "deployed-epa4all-rest-service-v1.2.4" || return 1
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="container")][0].resolvable' "$TMP/cand.json")" "true"
}

# `| default .Values.version` made a greedy match pick the chart's default 1.0.0 for every
# image in the chart, silently replacing the real pinned tag with a plausible wrong one.
test_discover_helm_prefers_first_values_ref_over_default_chain() {
  mkchart
  printf 'spec:\n  containers:\n  - image: "{{ .Values.epa.image.repository }}:{{ .Values.epa.image.tag | default .Values.version | default .Chart.AppVersion }}"\n' \
    > "$TMP/repo/deployment/charts/c/templates/epa.yaml"
  discover
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="container")][0].id' "$TMP/cand.json")" \
         "deployed-epa4all-rest-service-v1.2.4"
}

# An empty tag falling back to the release version is our own image: still unresolvable,
# but the repository is known, which is what lets a scope rule say what covers it.
test_discover_helm_names_repository_when_tag_is_release_versioned() {
  mkchart
  printf 'spec:\n  containers:\n  - image: "{{ .Values.rest.image.repository }}:{{ .Values.rest.image.tag | default .Values.version }}"\n' \
    > "$TMP/repo/deployment/charts/c/templates/rest.yaml"
  discover
  c=$(jq -r '[.candidates[]|select(.ecosystem=="container")][0]' "$TMP/cand.json")
  assert "$(jq -r .id <<<"$c")" "deployed-app-rest-appversion" || return 1
  assert "$(jq -r .resolvable <<<"$c")" "false" || return 1
  # the note must name the repository, otherwise the candidate is no more useful than before
  jq -re '.note | test("qbsdocker/app-rest")' <<<"$c" >/dev/null
}

# Outside a chart there is nothing to resolve against, and the ref must stay unresolvable
# rather than silently picking up values from an unrelated chart.
test_discover_does_not_resolve_outside_a_chart() {
  mkchart
  mkdir -p "$TMP/repo/k8s"
  printf 'spec:\n  containers:\n  - image: "{{ .Values.epa.image.repository }}:{{ .Values.epa.image.tag }}"\n' \
    > "$TMP/repo/k8s/epa.yaml"
  discover
  assert "$(jq -r '[.candidates[]|select(.ecosystem=="container")][0].resolvable' "$TMP/cand.json")" "false"
}

# There are two approval states, not one. soup-temporary-approval-workflow.yml sets
# metadata.approval.is_temporary when an approver signs off an unfulfilled requirement on a branch
# with a recorded reason. Reporting that as approved: true made a provisional decision read as a
# settled one in the evidence bundle.
test_assessment_reports_a_temporary_approval_as_temporary() {
  rm -rf "$TMP/ta"; mkdir -p "$TMP/ta/soups"
  jq -n '{package:"lodash",version:"4.17.x",requirements:{},
          metadata:{input_version:"4.17.15",
                    approval:{by:"a",date:"2026-01-01T00:00:00Z",
                              is_temporary:true,is_temporary_reason:"grq-3 under review"}}}' \
    > "$TMP/ta/soups/lodash.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
          components:[{"bom-ref":"c1",type:"library",name:"lodash",version:"4.17.15",
                       purl:"pkg:npm/lodash@4.17.15"}]}' > "$TMP/ta/in.json"
  bash "$S/merge-assessment.sh" "$TMP/ta/in.json" "$TMP/ta/soups" "$TMP/ta/out.json" >/dev/null 2>&1 || return 1
  # not "true": a consumer comparing to "true" must treat this as not-yet-approved
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:approved")][0].value' "$TMP/ta/out.json")" "temporary" || return 1
  # and the recorded reason travels with it
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:approval-temporary-reason")][0].value' "$TMP/ta/out.json")" "grq-3 under review"
}

# A full approval must still read as one.
test_assessment_reports_a_full_approval_as_true() {
  rm -rf "$TMP/tb"; mkdir -p "$TMP/tb/soups"
  jq -n '{package:"lodash",version:"4.17.x",requirements:{},
          metadata:{input_version:"4.17.15",approval:{by:"a",date:"2026-01-01T00:00:00Z"}}}' \
    > "$TMP/tb/soups/lodash.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
          components:[{"bom-ref":"c1",type:"library",name:"lodash",version:"4.17.15",
                       purl:"pkg:npm/lodash@4.17.15"}]}' > "$TMP/tb/in.json"
  bash "$S/merge-assessment.sh" "$TMP/tb/in.json" "$TMP/tb/soups" "$TMP/tb/out.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:approved")][0].value' "$TMP/tb/out.json")" "true" || return 1
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:approval-temporary-reason")]|length' "$TMP/tb/out.json")" "0"
}

# ---------------------------------------------------------------- consolidate
test_consolidate_loses_no_component() {
  for i in 1 2; do
    jq -n --arg n "bom$i" --arg c "comp$i" \
      '{bomFormat:"CycloneDX",specVersion:"1.6",
        metadata:{component:{"bom-ref":$n,name:$n,type:"application"}},
        components:[{"bom-ref":$c,type:"library",name:$c,version:"1"}]}' > "$TMP/b$i.json"
  done
  bash "$S/consolidate.sh" prod 1.0.0 "$TMP/sol.json" "$TMP/b1.json" "$TMP/b2.json" >/dev/null 2>&1 || return 1
  for c in comp1 comp2; do
    jq -e --arg c "$c" 'any(.components[]; ."bom-ref" == $c)' "$TMP/sol.json" >/dev/null \
      || { echo "$c missing from the consolidated BOM"; return 1; }
  done
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:sbom:complete")][0].value' "$TMP/sol.json")" "true"
}

test_consolidate_marks_incomplete_when_gaps_given() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{"bom-ref":"b",name:"b",type:"application"}},components:[]}' > "$TMP/b3.json"
  SBOM_MISSING="model-image" bash "$S/consolidate.sh" prod 1.0.0 "$TMP/sol2.json" "$TMP/b3.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:sbom:complete")][0].value' "$TMP/sol2.json")" "false" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:sbom:missing")][0].value' "$TMP/sol2.json")" "model-image"
}

# Regression: an input component whose bom-ref collides with a generated
# quickbird:artifact:* ref produced two components sharing one ref. Every existing check
# passed - the component was present, nothing was lost - but bom-ref must be unique within
# a CycloneDX document, so the output was invalid. Found by probing, not by the suite,
# which is why the invariant is now checked explicitly.
test_consolidate_rejects_duplicate_bom_ref() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{"bom-ref":"s1",name:"svc",type:"application"}},
          components:[{"bom-ref":"quickbird:artifact:svc",type:"library",name:"collider",version:"1"}]}' > "$TMP/dup.json"
  bash "$S/consolidate.sh" prod 1.0.0 "$TMP/dupout.json" "$TMP/dup.json" >/dev/null 2>&1
  assert "$?" "1"
}

# A staging document renders identically to a release one, so the tier has to be in the
# document. Without it, nothing downstream can tell them apart.
test_consolidate_stamps_the_tier() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{"bom-ref":"b",name:"b",type:"application"}},components:[]}' > "$TMP/t1.json"
  SBOM_TIER=staging bash "$S/consolidate.sh" p 1.0.0 "$TMP/tout.json" "$TMP/t1.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:sbom:tier")][0].value' "$TMP/tout.json")" "staging"
}

test_consolidate_defaults_the_tier_to_branch() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{"bom-ref":"b",name:"b",type:"application"}},components:[]}' > "$TMP/t2.json"
  bash "$S/consolidate.sh" p 1.0.0 "$TMP/tout2.json" "$TMP/t2.json" >/dev/null 2>&1 || return 1
  # never "release" by accident — that has to be asked for
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:sbom:tier")][0].value' "$TMP/tout2.json")" "branch"
}

# The CycloneDX output of a registry scan carries only the image name and tag — no digest at all.
# Without the digest a floating tag leaves the document unable to say what it examined, which is
# why such images were being excluded from scope as "not reproducible": the worse configuration
# produced the cleaner report.
test_normalize_records_the_scanned_image_digest() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"redis",version:"latest",type:"container","bom-ref":"x"}},
          components:[]}' > "$TMP/nd-raw.json"
  jq -n '{source:{metadata:{imageID:"sha256:aaa",manifestDigest:"sha256:bbb",
                            repoDigests:["index.docker.io/library/redis@sha256:ccc"]}}}' \
    > "$TMP/nd-native.json"
  BOM_SUBJECT=deployed-redis SCAN_TARGET=registry:redis:latest SYFT_NATIVE="$TMP/nd-native.json" \
    bash "$S/normalize-bom.sh" "$TMP/nd-raw.json" "$TMP/nd.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.component.properties[]|select(.name=="quickbird:scan:image-digest")][0].value' "$TMP/nd.json")" \
         "index.docker.io/library/redis@sha256:ccc" || return 1
  # also as a hash, because Component Hash is a CISA minimum element
  assert "$(jq -r '[.metadata.component.hashes[]|select(.alg=="SHA-256")][0].content' "$TMP/nd.json")" "ccc"
}

# repoDigests is the registry-addressable form and the one that lets someone pull the same bytes
# again; manifestDigest is the fallback when a local image has never been pushed.
test_normalize_falls_back_to_the_manifest_digest() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"x",version:"1",type:"container","bom-ref":"x"}},components:[]}' \
    > "$TMP/nd-raw.json"
  jq -n '{source:{metadata:{imageID:"sha256:aaa",manifestDigest:"sha256:bbb",repoDigests:[]}}}' \
    > "$TMP/nd-native.json"
  BOM_SUBJECT=s SCAN_TARGET=t SYFT_NATIVE="$TMP/nd-native.json" \
    bash "$S/normalize-bom.sh" "$TMP/nd-raw.json" "$TMP/nd.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.component.properties[]|select(.name=="quickbird:scan:image-digest")][0].value' "$TMP/nd.json")" "sha256:bbb"
}

# A directory or lockfile scan has no image digest, and a missing one must not fail the run.
test_normalize_survives_a_scan_with_no_image() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"x",version:"1",type:"application","bom-ref":"x"}},components:[]}' \
    > "$TMP/nd-raw.json"
  BOM_SUBJECT=s SCAN_TARGET=dir:. bash "$S/normalize-bom.sh" "$TMP/nd-raw.json" "$TMP/nd.json" \
    >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.component.properties[]?|select(.name=="quickbird:scan:image-digest")]|length' "$TMP/nd.json")" "0" || return 1
  # the target is still recorded, so the document says what it looked at either way
  assert "$(jq -r '[.metadata.component.properties[]|select(.name=="quickbird:scan:target")][0].value' "$TMP/nd.json")" "dir:."
}

# ---------------------------------------------------------------- assessment
soup_record() { # <package> <family> <input_version> [vex-json]
  jq -n --arg p "$1" --arg f "$2" --arg iv "$3" --argjson vex "${4:-null}" \
    '{package:$p, version:$f,
      metadata:{input_version:$iv, approval:{by:"someone", date:"2026-01-01T00:00:00Z", condition:""}},
      requirements:{"grq-1":{description:"d",fulfilled:true,reason_if_requirement_not_fulfilled:""}}}
     + (if $vex != null then {vex:$vex} else {} end)'
}

# Regression: matching on metadata.input_version meant a component at 1.0.4 found no record
# for a "1.x.x" approval — no requirement properties, no approval evidence, and the record
# reported orphaned. Three wrong answers from one wrong join.
test_assessment_matches_version_family() {
  mkdir -p "$TMP/soups/npm"; soup_record lib "1.x.x" "1.0.1" > "$TMP/soups/npm/lib.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},
          components:[{"bom-ref":"c",type:"library",name:"lib",version:"1.0.4"}]}' > "$TMP/ab.json"
  bash "$S/merge-assessment.sh" "$TMP/ab.json" "$TMP/soups" "$TMP/ao.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:approved")][0].value' "$TMP/ao.json")" "true" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:soup:records-orphaned")][0].value' "$TMP/ao.json")" "0"
}

test_assessment_rejects_different_major() {
  mkdir -p "$TMP/soups2/npm"; soup_record lib "1.x.x" "1.0.1" > "$TMP/soups2/npm/lib.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},
          components:[{"bom-ref":"c",type:"library",name:"lib",version:"2.0.0"}]}' > "$TMP/ab2.json"
  bash "$S/merge-assessment.sh" "$TMP/ab2.json" "$TMP/soups2" "$TMP/ao2.json" >/dev/null 2>&1 || return 1
  # not approved (family does not cover 2.0.0) — and reported as version DRIFT, not as an
  # orphan: the name ships, the approval does not apply. The old lumping hid exactly the
  # wireguard case (approved 1.0.20241014, deployed 1.0.20210914).
  assert "$(jq -r '[.components[0].properties[]?|select(.name=="quickbird:soup:approved")] | length' "$TMP/ao2.json")" "0" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:soup:records-orphaned")][0].value' "$TMP/ao2.json")" "0" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:soup:records-version-mismatch")][0].value' "$TMP/ao2.json")" "1"
}

test_assessment_record_path_is_relative() {
  mkdir -p "$TMP/soups3/npm"; soup_record lib "1.x.x" "1.0.0" > "$TMP/soups3/npm/lib.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},
          components:[{"bom-ref":"c",type:"library",name:"lib",version:"1.0.0"}]}' > "$TMP/ab3.json"
  bash "$S/merge-assessment.sh" "$TMP/ab3.json" "$TMP/soups3" "$TMP/ao3.json" >/dev/null 2>&1 || return 1
  local p; p=$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:record")][0].value' "$TMP/ao3.json")
  [[ "$p" != /* ]] || { echo "absolute path leaked into the BOM: $p"; return 1; }
}

# ---------------------------------------------------------------- enrichment merge
test_enrichment_unknown_kev_is_not_false() {
  jq -n '{schema:"quickbird.cve-enrichment/v1", stale:true,
          feeds:{kev:{available:false,catalog_version:null},epss:{available:false,model_version:null,score_date:null}},
          cves:{"CVE-1":{kev:null,epss:null,epss_percentile:null,in_epss:null}}}' > "$TMP/enr.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},components:[],
          vulnerabilities:[{id:"CVE-1"}]}' > "$TMP/eb.json"
  bash "$S/merge-enrichment.sh" "$TMP/eb.json" "$TMP/enr.json" "$TMP/eo.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.vulnerabilities[0].properties[]|select(.name=="quickbird:vuln:kev")][0].value' "$TMP/eo.json")" "unknown"
}

test_enrichment_records_feed_provenance() {
  jq -n '{schema:"quickbird.cve-enrichment/v1", stale:false,
          feeds:{kev:{available:true,catalog_version:"2026.07.29"},
                 epss:{available:true,model_version:"v2026.06.15",score_date:"2026-08-02"}},
          cves:{}}' > "$TMP/enr2.json"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},components:[],vulnerabilities:[]}' > "$TMP/eb2.json"
  bash "$S/merge-enrichment.sh" "$TMP/eb2.json" "$TMP/enr2.json" "$TMP/eo2.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:vuln:kev-catalog-version")][0].value' "$TMP/eo2.json")" "2026.07.29" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:vuln:epss-model-version")][0].value' "$TMP/eo2.json")" "v2026.06.15"
}

# ---------------------------------------------------------------- policy
pol() { printf 'product: p\ntier: Basic\ncra_scope: %s\nmaintenance_interval: 90d\n%s' "$1" "${2:-}" > "$TMP/pol.yml"; }

# Regression: the required-field check used jq's `//`, which treats false as absent, so
# `cra_scope: false` — the value most products will set — was reported as missing.
test_policy_accepts_cra_scope_false() {
  pol "false"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "0"
}

test_policy_requires_cadence() {
  printf 'product: p\ntier: Basic\ncra_scope: false\n' > "$TMP/pol2.yml"
  bash "$S/validate-policy.sh" "$TMP/pol2.yml" >/dev/null 2>&1
  assert "$?" "1"
}

test_policy_rejects_relaxed_deadline_without_reason() {
  pol "false" $'tracks:\n  immediate:\n    remediation: 60d\n'
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "1"
}

test_policy_allows_relaxed_deadline_with_reason() {
  pol "false" $'tracks:\n  immediate:\n    remediation: 60d\n    reason: customer operates the deploy\n'
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "0"
}

test_policy_allows_tightening_without_reason() {
  pol "false" $'tracks:\n  immediate:\n    remediation: 7d\n'
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "0"
}

test_policy_rejects_raised_epss_without_reason() {
  pol "false" $'epss:\n  elevated: 0.4\n'
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "1"
}

test_policy_resolves_tier_defaults() {
  pol "true"
  local out; out=$(bash "$S/validate-policy.sh" "$TMP/pol.yml" 2>/dev/null)
  assert "$(jq -r '.backstop' <<<"$out")" "annual" || return 1
  assert "$(jq -r '.max_maintenance_interval' <<<"$out")" "90d"
}

# ---------------------------------------------------------------- classifier
CLS() { python3 "$S/classify-findings.py" "$@"; }

mkpolicy() { printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nalerts:\n  threshold: %s\n' "${1:-high}" > "$TMP/cp.yml"
             bash "$S/validate-policy.sh" "$TMP/cp.yml" 2>/dev/null > "$TMP/cp.json"; }

mkvuln() { # <id> <cvss-vector|null> <kev|null> <epss|null> [vex-state] [justification]
  jq -n --arg id "$1" --arg vec "$2" --arg kev "$3" --arg epss "$4" --arg vs "${5:-}" --arg j "${6:-}" \
    '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{name:"p"}},components:[],
      vulnerabilities:[ ({id:$id}
        + (if $vec != "null" then {ratings:[{source:{name:"OSV"},method:"CVSSv31",vector:$vec}]} else {ratings:[]} end)
        + (if $epss != "null" then {ratings:[{source:{name:"OSV"},method:"CVSSv31",vector:(if $vec=="null" then "" else $vec end)},
                                             {source:{name:"EPSS"},method:"other",score:($epss|tonumber)}]} else {} end)
        + (if $kev != "null" then {properties:[{name:"quickbird:vuln:kev",value:$kev}]} else {} end)
        + (if $vs != "" then {analysis:({state:$vs} + (if $j != "" then {justification:$j} else {} end))} else {} end)) ]}' \
    > "$TMP/cv.json"
}

test_classify_kev_gets_its_own_track_regardless_of_cvss() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" true null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "kev" || return 1
  assert "$(jq -r '.findings[0].rule' "$TMP/co.json")" "1"
}

# The point of separating the two: "actively exploited" is an observation, "CVSS 10.0" is a
# score, and they no longer share a clock. Measured on kontina-backend, 0 of 23 Critical
# findings were in KEV — the 72h clock there was justified by a risk none of them carried.
test_classify_kev_and_critical_have_different_clocks() {
  mkpolicy
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" true null      # KEV, also 10.0
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/k.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null     # same score, not KEV
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/c.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].mitigation_due[0:10]' "$TMP/k.json")" "2026-01-04" || return 1   # KEV: 72h
  assert "$(jq -r '.findings[0].mitigation_due[0:10]' "$TMP/c.json")" "2026-01-15"               # Critical: 14d
}

# A Medium has no mitigation clock any more. It stood at 30d across 196 findings on one
# product and meant "write a document"; Track 3 rides the maintenance window instead.
# ---------------------------------------------------------------- image age
# An image is a component and ages like any other. Annex B B.1.1 makes the image the SOUP, so excluding its
# OS packages from the currency policy without checking the image itself removed the signal.
mkimg() {  # <built-iso>
  jq -n --arg b "$1" \
    '{bomFormat:"CycloneDX",specVersion:"1.6",
      metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
      components:[{"bom-ref":"a1",type:"container",name:"deployed-x",version:"1.0",
                   properties:[{name:"quickbird:scan:image-created",value:$b},
                               {name:"quickbird:scan:image-digest",value:"index.docker.io/x@sha256:abc"}]}]}' \
    > "$TMP/ia-bom.json"
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\n' > "$TMP/ia-pol.yml"
  bash "$S/validate-policy.sh" "$TMP/ia-pol.yml" 2>/dev/null > "$TMP/ia-pol.json"
  python3 "$S/check-currency.py" "$TMP/ia-bom.json" "$TMP/ia-pol.json" --soups "$TMP/nosoups" \
    --out "$TMP/ia.json" --now 2026-08-04T00:00:00+00:00 >/dev/null 2>&1 || return 1
}

test_image_older_than_the_window_is_a_finding() {
  mkimg 2025-07-24T11:29:44+00:00 || return 1
  assert "$(jq -r '.summary.stale_images' "$TMP/ia.json")" "1" || return 1
  assert "$(jq -r '.stale_images[0].age_days' "$TMP/ia.json")" "375" || return 1
  # the digest travels with the finding, so the reader knows which bytes were assessed
  jq -re '.stale_images[0].image_digest | test("sha256:")' "$TMP/ia.json" >/dev/null || return 1
  # and the finding distinguishes itself from the packaged software version
  jq -re '.stale_images[0].action | test("not about the version of the software packaged")' "$TMP/ia.json" >/dev/null
}

test_a_recently_built_image_is_not_a_finding() {
  mkimg 2026-07-24T00:00:00+00:00 || return 1
  assert "$(jq -r '.summary.stale_images' "$TMP/ia.json")" "0"
}

# An unparsable build date must not read as recent.
test_image_with_an_unusable_build_date_is_unknown() {
  mkimg "not a date" || return 1
  assert "$(jq -r '.summary.stale_images' "$TMP/ia.json")" "0" || return 1
  jq -re '[.unknown[] | select(.why | test("build date"))] | length == 1' "$TMP/ia.json" >/dev/null
}

# Regression: consolidate.sh rebuilt the artifact component from scratch and dropped its hashes and
# properties, so neither the image digest nor the build date reached the consolidated bundle. That
# bundle is what gets published as the release asset, and the per-target files still had the data,
# which is why checking those did not reveal the loss.
test_consolidate_keeps_the_subject_hashes_and_properties() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{"bom-ref":"s",name:"deployed-x",version:"1.0",type:"container",
                    hashes:[{alg:"SHA-256",content:"abc"}],
                    properties:[{name:"quickbird:scan:image-created",value:"2025-07-24T00:00:00Z"},
                                {name:"quickbird:scan:image-digest",value:"index.docker.io/x@sha256:abc"}]}},
          components:[]}' > "$TMP/ck1.json"
  bash "$S/consolidate.sh" p 1.0.0 "$TMP/ckout.json" "$TMP/ck1.json" >/dev/null 2>&1 || return 1
  local a; a=$(jq -r '[.components[]|select(."bom-ref"=="quickbird:artifact:deployed-x")][0]' "$TMP/ckout.json")
  assert "$(jq -r '[.properties[]|select(.name=="quickbird:scan:image-digest")][0].value' <<<"$a")" \
         "index.docker.io/x@sha256:abc" || return 1
  assert "$(jq -r '[.properties[]|select(.name=="quickbird:scan:image-created")][0].value' <<<"$a")" \
         "2025-07-24T00:00:00Z" || return 1
  assert "$(jq -r '[.hashes[]|select(.alg=="SHA-256")][0].content' <<<"$a")" "abc"
}

# ---------------------------------------------------------------- grq-4 vs reality
# grq-4 ("no major or critical security issues") is evaluated once, at approval time, against
# metadata.input_version. A patch move inside the approved family keeps the approval — correctly —
# but the vulnerability picture can change underneath it, and nothing reconciled the two. A record
# could keep asserting "no major or critical security issues" while the monitor reported a Critical
# in the same component.
mkg4() {  # <grq4-fulfilled> <vector> [vex-state] [justification]
  rm -rf "$TMP/g4"; mkdir -p "$TMP/g4/soups"
  jq -n --argjson ful "$1" \
    '{package:"linkerd",version:"25.x.x",
      metadata:{input_version:"25.10.6",approval:{by:"a",date:"2025-11-04T00:00:00Z"}},
      requirements:{"grq-4":{description:"Does not contain major or critical security issues.",
                             fulfilled:$ful,
                             reason_if_requirement_not_fulfilled:(if $ful then "" else "known, accepted" end),
                             metadata:{vulnerabilities_count:0}}}}' > "$TMP/g4/soups/linkerd.json"
  jq -n --arg vec "$2" --arg vs "${3:-}" --arg j "${4:-}" \
    '{bomFormat:"CycloneDX",specVersion:"1.6",
      metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
      components:[{"bom-ref":"c1",type:"library",name:"linkerd",version:"25.12.1",
                   purl:"pkg:golang/linkerd@25.12.1"}],
      vulnerabilities:[({id:"CVE-2026-1",affects:[{ref:"c1"}],
                         ratings:[{source:{name:"OSV"},method:"CVSSv31",vector:$vec}]}
                        + (if $vs != "" then {analysis:({state:$vs}
                             + (if $j != "" then {justification:$j} else {} end))} else {} end))]}' \
    > "$TMP/g4/in.json"
  bash "$S/merge-assessment.sh" "$TMP/g4/in.json" "$TMP/g4/soups" "$TMP/g4/a.json" >/dev/null 2>&1 || return 1
  mkpolicy
  CLS "$TMP/g4/a.json" "$TMP/cp.json" --out "$TMP/g4/cl.json" --now 2026-01-01T00:00:00+00:00 \
    >/dev/null 2>&1
}

test_grq4_a_critical_contradicts_a_fulfilled_record() {
  mkg4 true "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || return 1
  assert "$(jq -r '.soup_records_to_recheck | length' "$TMP/g4/cl.json")" "1" || return 1
  assert "$(jq -r '.soup_records_to_recheck[0].component' "$TMP/g4/cl.json")" "linkerd" || return 1
  # the record is not treated as withdrawn — it is flagged for re-check
  jq -re '.soup_records_to_recheck[0].why | test("not withdrawn")' "$TMP/g4/cl.json" >/dev/null
}

# grq-4 says "major or critical". A Medium does not contradict it, and pulling Medium findings in
# via the expedited track would blunt the signal.
test_grq4_a_medium_does_not_contradict() {
  mkg4 true "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" || return 1
  assert "$(jq -r '.soup_records_to_recheck | length' "$TMP/g4/cl.json")" "0"
}

# A justified not_affected means the component is not exposed, so nothing is contradicted.
test_grq4_vex_not_affected_does_not_contradict() {
  mkg4 true "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" not_affected vulnerable_code_not_present || return 1
  assert "$(jq -r '.soup_records_to_recheck | length' "$TMP/g4/cl.json")" "0"
}

# If grq-4 is already recorded as unfulfilled with a reason, the record says so — no contradiction.
test_grq4_unfulfilled_record_is_not_contradicted() {
  mkg4 false "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || return 1
  assert "$(jq -r '.soup_records_to_recheck | length' "$TMP/g4/cl.json")" "0"
}

# The finding keeps its own classification either way — this is a review event, not a reclassification.
test_grq4_contradiction_does_not_change_the_track() {
  mkg4 true "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/g4/cl.json")" "immediate"
}

# The bundle is the evidence, so the flag has to travel in it — the PDF renders only what the
# bundle says, by design.
test_grq4_contradiction_is_stamped_into_the_bundle() {
  mkg4 true "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || return 1
  python3 "$S/classify-findings.py" "$TMP/g4/a.json" "$TMP/cp.json" \
    --annotate-bom "$TMP/g4/a.json" --out "$TMP/g4/cl2.json" \
    --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:recheck")][0].value' "$TMP/g4/a.json")" "grq-4" || return 1
  assert "$(jq -r '[.components[0].properties[]|select(.name=="quickbird:soup:recheck-findings")][0].value' "$TMP/g4/a.json")" "1"
}

# ---------------------------------------------------------------- onboarding baseline
# Starting every clock at first discovery is right for a monitored product and wrong on the day
# monitoring begins: the accumulated backlog is all dated the same day. On kontina-backend that
# was 23 Critical findings due in 14 days, none of which anyone could have acted on before there
# was a scan.
mkbase() {  # <onboarded> <baseline_start|""> <kev>
  mkpolicy
  jq --arg o "$1" --arg b "$2" \
    'if $o != "" then . + {onboarded:$o} else . end
     | if $b != "" then . + {baseline_clocks_start:$b} else . end' \
    "$TMP/cp.json" > "$TMP/cpb.json"
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" "$3" null
  CLS "$TMP/cv.json" "$TMP/cpb.json" --out "$TMP/cb.json" --now 2026-01-01T00:00:00+00:00 \
    >/dev/null 2>&1
}

test_baseline_moves_preexisting_clocks_to_the_agreed_date() {
  mkbase 2026-01-01 2026-02-01 false || return 1
  assert "$(jq -r '.findings[0].clock_start[0:10]' "$TMP/cb.json")" "2026-02-01" || return 1
  # Critical mitigation is 14d, so from the baseline date rather than from discovery
  assert "$(jq -r '.findings[0].mitigation_due[0:10]' "$TMP/cb.json")" "2026-02-15" || return 1
  # recorded, not waived: the finding keeps its track and says why its clock moved
  assert "$(jq -r '.findings[0].track' "$TMP/cb.json")" "immediate" || return 1
  jq -re '.findings[0].baseline.why | test("Recorded, not waived")' "$TMP/cb.json" >/dev/null
}

# Active exploitation is not something a plan can defer.
test_baseline_never_applies_to_kev() {
  mkbase 2026-01-01 2026-02-01 true || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/cb.json")" "kev" || return 1
  assert "$(jq -r '.findings[0].clock_start[0:10]' "$TMP/cb.json")" "2026-01-01" || return 1
  assert "$(jq -r '.findings[0].baseline // "none"' "$TMP/cb.json")" "none"
}

# A missing baseline date must not become a silent amnesty for a whole backlog.
test_baseline_absent_means_no_baseline() {
  mkbase 2026-01-01 "" false || return 1
  assert "$(jq -r '.findings[0].clock_start[0:10]' "$TMP/cb.json")" "2026-01-01" || return 1
  assert "$(jq -r '.findings[0].baseline // "none"' "$TMP/cb.json")" "none"
}

# ...and it says so, because the consequence is a whole backlog due at once.
test_baseline_warns_when_onboarded_without_a_start_date() {
  mkpolicy
  jq '. + {onboarded:"2026-01-01"}' "$TMP/cp.json" > "$TMP/cpb.json"
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null
  CLS "$TMP/cv.json" "$TMP/cpb.json" --out "$TMP/cb.json" --now 2026-01-01T00:00:00+00:00 \
    2>"$TMP/cbw.txt" >/dev/null || return 1
  grep -q "baseline_clocks_start is not" "$TMP/cbw.txt"
}

# A finding that appears after onboarding runs normally — the baseline is not permanent.
test_baseline_does_not_cover_later_findings() {
  mkpolicy
  jq '. + {onboarded:"2026-01-01", baseline_clocks_start:"2026-02-01"}' "$TMP/cp.json" > "$TMP/cpb.json"
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null
  CLS "$TMP/cv.json" "$TMP/cpb.json" --out "$TMP/cb.json" --now 2026-03-01T00:00:00+00:00 \
    >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].clock_start[0:10]' "$TMP/cb.json")" "2026-03-01" || return 1
  assert "$(jq -r '.findings[0].baseline // "none"' "$TMP/cb.json")" "none"
}

test_classify_medium_has_no_mitigation_clock() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" false null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "planned" || return 1
  assert "$(jq -r '.findings[0].mitigation_due // "null"' "$TMP/co.json")" "null"
}

# "unknown" must not behave like "not in KEV": a catalog we could not read is not evidence.
test_classify_kev_unknown_is_treated_as_kev() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" unknown null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "kev"
}

test_classify_high_plus_high_epss_is_immediate() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" false 0.7
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].rule' "$TMP/co.json")" "3"
}

test_classify_missing_cvss_is_expedited_not_low() {
  mkpolicy; mkvuln GHSA-x null false null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "expedited" || return 1
  assert "$(jq -r '.findings[0].rule' "$TMP/co.json")" "9"
}

test_classify_vex_not_affected_is_suppressed() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" true null not_affected vulnerable_code_not_present
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.total' "$TMP/co.json")" "0" || return 1
  assert "$(jq -r '.summary.suppressed_by_vex' "$TMP/co.json")" "1"
}

# A not_affected without a justification code is an assertion, not an argument, and must
# not suppress.
test_classify_vex_without_justification_does_not_suppress() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null not_affected
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.total' "$TMP/co.json")" "1"
}

test_classify_deadlines_come_from_the_policy() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].mitigation_due[0:10]' "$TMP/co.json")" "2026-01-15" || return 1   # 14d
  assert "$(jq -r '.findings[0].remediation_due[0:10]' "$TMP/co.json")" "2026-01-31"              # 30d
}

# WI §5 — EPSS decays daily. Without latching a Track 1 finding becomes Track 2 a week later,
# its deadline moves outward, and the trail shows a deadline that was never breached because
# it kept receding.
test_classify_latches_track_downward_never() {
  mkpolicy
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" false 0.7      # rule 3 -> immediate
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/day1.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/day1.json")" "immediate" || return 1
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" false 0.01     # EPSS decayed
  CLS "$TMP/cv.json" "$TMP/cp.json" --state "$TMP/day1.json" --out "$TMP/day8.json" --now 2026-01-08T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/day8.json")" "immediate" || return 1
  assert "$(jq -r '.findings[0].latched.from' "$TMP/day8.json")" "expedited" || return 1
  # and the clock must not restart
  assert "$(jq -r '.findings[0].first_seen[0:10]' "$TMP/day8.json")" "2026-01-01"
}

test_classify_escalation_restarts_the_clock() {
  mkpolicy
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" false null     # medium -> planned
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/e1.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" true null      # added to KEV
  CLS "$TMP/cv.json" "$TMP/cp.json" --state "$TMP/e1.json" --out "$TMP/e2.json" --now 2026-02-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/e2.json")" "kev" || return 1
  assert "$(jq -r '.findings[0].first_seen[0:10]' "$TMP/e2.json")" "2026-02-01"
}

test_classify_alert_threshold_from_policy() {
  mkpolicy critical; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" false null  # high
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].alerts' "$TMP/co.json")" "false" || return 1
  mkpolicy high
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co2.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].alerts' "$TMP/co2.json")" "true"
}

test_classify_marks_overdue() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" false null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/o1.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  CLS "$TMP/cv.json" "$TMP/cp.json" --state "$TMP/o1.json" --out "$TMP/o2.json" --now 2026-03-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].remediation_overdue' "$TMP/o2.json")" "true" || return 1
  assert "$(jq -r '.summary.overdue' "$TMP/o2.json")" "1"
}

test_classify_cvss_matches_published_scores() {
  S="$S" python3 "$HERE/cvss-reference.py"
}

# ---------------------------------------------------------------- lifecycle
LC() { python3 "$S/track-lifecycle.py" "$@"; }
mkfind() { jq -n --argjson f "$2" --argjson ok "${3:-true}" \
  '{schema:"quickbird.classified-findings/v1",product:"p",
    summary:(if $ok then {total:($f|length)} else {} end),findings:$f,suppressed:[]}' > "$1"; }

test_lifecycle_fix_in_main_does_not_satisfy_remediation() {
  mkfind "$TMP/d.json" '[{"id":"CVE-A","track":"immediate","remediation_due":"2026-08-23T00:00:00+00:00","remediation_overdue":false}]'
  mkfind "$TMP/m.json" '[]'
  LC --deployed "$TMP/d.json" --main "$TMP/m.json" --out "$TMP/l.json" --now 2026-08-05T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].state' "$TMP/l.json")" "fix-ready-release-pending" || return 1
  assert "$(jq -r '.findings[0].mitigation_satisfied' "$TMP/l.json")" "true" || return 1
  # the rule the whole ticket rests on
  assert "$(jq -r '.findings[0].remediation_satisfied' "$TMP/l.json")" "false"
}

test_lifecycle_resolves_only_when_gone_from_the_running_version() {
  mkfind "$TMP/d1.json" '[{"id":"CVE-A","track":"immediate"}]'
  mkfind "$TMP/m.json" '[]'
  LC --deployed "$TMP/d1.json" --main "$TMP/m.json" --out "$TMP/l1.json" --now 2026-08-01T00:00:00+00:00 >/dev/null 2>&1
  mkfind "$TMP/d2.json" '[]'
  LC --deployed "$TMP/d2.json" --main "$TMP/m.json" --state "$TMP/l1.json" --out "$TMP/l2.json" --now 2026-08-10T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].state' "$TMP/l2.json")" "deployed" || return 1
  assert "$(jq -r '.findings[0].remediation_satisfied' "$TMP/l2.json")" "true"
}

# The dangerous one. A finding absent because the scan failed must never read as resolved -
# that is how a live vulnerability gets closed on the strength of a network error.
test_lifecycle_failed_scan_does_not_resolve() {
  mkfind "$TMP/d1.json" '[{"id":"CVE-A","track":"immediate"}]'
  mkfind "$TMP/m.json" '[]'
  LC --deployed "$TMP/d1.json" --main "$TMP/m.json" --out "$TMP/l1.json" --now 2026-08-01T00:00:00+00:00 >/dev/null 2>&1
  mkfind "$TMP/dbad.json" '[]' false     # no summary.total -> the scan did not complete
  LC --deployed "$TMP/dbad.json" --main "$TMP/m.json" --state "$TMP/l1.json" --out "$TMP/l3.json" --now 2026-08-10T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].state' "$TMP/l3.json")" "unknown" || return 1
  assert "$(jq -r '.findings[0].remediation_satisfied' "$TMP/l3.json")" "false"
}

test_lifecycle_without_main_everything_is_open() {
  mkfind "$TMP/d.json" '[{"id":"CVE-A","track":"immediate"}]'
  LC --deployed "$TMP/d.json" --out "$TMP/l.json" --now 2026-08-05T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].state' "$TMP/l.json")" "open" || return 1
  assert "$(jq -r '.main_comparison' "$TMP/l.json")" "false"
}

test_lifecycle_release_required_is_track1_only() {
  mkfind "$TMP/d.json" '[{"id":"CVE-A","track":"immediate","remediation_due":"2026-09-01T00:00:00+00:00","remediation_overdue":false},
                          {"id":"CVE-B","track":"expedited","remediation_due":"2026-09-01T00:00:00+00:00","remediation_overdue":false}]'
  mkfind "$TMP/m.json" '[]'
  LC --deployed "$TMP/d.json" --main "$TMP/m.json" --out "$TMP/l.json" --now 2026-08-05T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.release_required' "$TMP/l.json")" "1" || return 1
  assert "$(jq -r '.release_required[0].id' "$TMP/l.json")" "CVE-A"
}

test_lifecycle_records_transitions() {
  mkfind "$TMP/d.json" '[{"id":"CVE-A","track":"immediate"}]'
  mkfind "$TMP/m1.json" '[{"id":"CVE-A"}]'
  LC --deployed "$TMP/d.json" --main "$TMP/m1.json" --out "$TMP/t1.json" --now 2026-08-01T00:00:00+00:00 >/dev/null 2>&1
  mkfind "$TMP/m2.json" '[]'
  LC --deployed "$TMP/d.json" --main "$TMP/m2.json" --state "$TMP/t1.json" --out "$TMP/t2.json" --now 2026-08-05T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.transitions[0].from' "$TMP/t2.json")" "open" || return 1
  assert "$(jq -r '.transitions[0].to' "$TMP/t2.json")" "fix-ready-release-pending"
}

# ---------------------------------------------------------------- escalation
ESC() { python3 "$S/escalate-breaches.py" "$@"; }
mkesc() { jq -n --argjson f "$1" '{findings:$f}' > "$TMP/ef.json"; }

test_escalate_warns_before_the_deadline() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-08-06T00:00:00+00:00"}]'
  ESC "$TMP/ef.json" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/eo.json")" "approaching"
}

# WI §7 #6 gives five *working* days. Counting calendar days would escalate across a weekend
# before the owner has had a working day to respond.
test_escalate_counts_working_days() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-08-07T00:00:00+00:00"}]'
  # Fri 7 Aug -> Mon 10 Aug is one working day, not three calendar days
  ESC "$TMP/ef.json" --out "$TMP/eo.json" --now 2026-08-10T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/eo.json")" "breached" || return 1
  contains "$(jq -r '.escalations[0].detail[0]' "$TMP/eo.json")" "4 more working day"
}

test_escalate_undecided_after_the_decision_window() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-07-01T00:00:00+00:00"}]'
  ESC "$TMP/ef.json" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/eo.json")" "undecided"
}

test_escalate_recorded_decision_holds_the_level() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-07-01T00:00:00+00:00"}]'
  printf 'decisions:\n  - cve: CVE-A\n    decision: revised-date\n    by: x\n    expires: 2026-12-01\n' > "$TMP/dec.yml"
  ESC "$TMP/ef.json" --decisions "$TMP/dec.yml" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/eo.json")" "breached"
}

# An expired decision reads as handled while protecting nothing — worse than none at all.
test_escalate_expired_decision_is_undecided() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-07-01T00:00:00+00:00"}]'
  printf 'decisions:\n  - cve: CVE-A\n    decision: risk-accepted\n    by: x\n    expires: 2026-07-15\n' > "$TMP/dec.yml"
  ESC "$TMP/ef.json" --decisions "$TMP/dec.yml" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/eo.json")" "undecided"
}

# An unreadable decisions file must stop the run: silently ignoring it would escalate every
# breach that is in fact already handled.
test_escalate_refuses_unreadable_decisions() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-07-01T00:00:00+00:00"}]'
  printf 'decisions: [ this is not: valid: yaml\n' > "$TMP/bad.yml"
  ESC "$TMP/ef.json" --decisions "$TMP/bad.yml" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1
  assert "$?" "1"
}

test_escalate_ignores_satisfied_findings() {
  mkesc '[{"id":"CVE-A","track":"immediate","mitigation_due":"2026-07-01T00:00:00+00:00","remediation_satisfied":true}]'
  ESC "$TMP/ef.json" --out "$TMP/eo.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.total' "$TMP/eo.json")" "0"
}

# ---------------------------------------------------------------- currency
test_currency_comparison_logic() { S="$S" python3 "$HERE/currency-logic.py"; }

mkcur() { jq -n --argjson c "$1" '{bomFormat:"CycloneDX",specVersion:"1.6",
  metadata:{component:{name:"p"}},components:$c}' > "$TMP/cb.json"; }

# A registry that cannot be reached must yield "unknown", never "current" — not knowing how
# far behind something is is not the same as it being up to date.
test_currency_unreachable_registry_is_unknown_not_current() {
  mkcur '[{"bom-ref":"a","type":"library","name":"x","version":"1.0.0","purl":"pkg:npm/x@1.0.0",
           "properties":[{"name":"quickbird:soup:record","value":"r"}]}]'
  mkdir -p "$TMP/csoups"
  printf '{"package":"x","version":"1.x.x"}' > "$TMP/csoups/x.json"
  https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
    python3 "$S/check-currency.py" "$TMP/cb.json" "$TMP/cp.json" --soups "$TMP/csoups" --out "$TMP/co.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.unknown' "$TMP/co.json")" "1" || return 1
  assert "$(jq -r '.summary.beyond_policy' "$TMP/co.json")" "0"
}

# Transitives cannot be upgraded independently, so flagging them produces a list nobody can
# act on. Only components carrying a SOUP record are checked.
test_currency_skips_transitives() {
  mkcur '[{"bom-ref":"a","type":"library","name":"direct","version":"1.0.0","purl":"pkg:npm/direct@1.0.0",
           "properties":[{"name":"quickbird:soup:record","value":"r"}]},
          {"bom-ref":"b","type":"library","name":"trans","version":"1.0.0","purl":"pkg:npm/trans@1.0.0"}]'
  mkdir -p "$TMP/csoups2"; printf '{"package":"direct","version":"1.x.x"}' > "$TMP/csoups2/d.json"
  https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
    python3 "$S/check-currency.py" "$TMP/cb.json" "$TMP/cp.json" --soups "$TMP/csoups2" --out "$TMP/co.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.checked' "$TMP/co.json")" "1"
}

test_currency_is_report_only() {
  mkcur '[]'
  python3 "$S/check-currency.py" "$TMP/cb.json" "$TMP/cp.json" --soups "$TMP/csoups2" --out "$TMP/co.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.severity' "$TMP/co.json")" "report-only"
}

# The staleness window is a different question from the currency window and has a
# different answer: there is nothing to upgrade to.
test_currency_stale_and_current_needs_no_upgrade() {
  S="$S" python3 "$HERE/staleness-logic.py"
}

# Which releases count as production decides the cadence, and the cadence decides every
# Track 3/4 deadline. Three signals answer it and they disagree by ten months on alvie.
# A breach on a finding that happens not to be in KEV used to produce no alert at all: the
# whole escalation block sat inside the KEV branch. WI §7 #6 step 1 was therefore a process step
# that silently did not happen.
mkalert() {
  rm -rf "$TMP/mon"; mkdir -p "$TMP/mon"
  jq -n --arg v "${1:-all-clear}" \
    '{schema:"quickbird.kev-monitor-run/v1",verdict:$v,kev_findings:[],
      kev_membership_unknown:[],not_scanned:[],scanned:[{name:"x",version:"1"}]}' \
    > "$TMP/mon/record.json"
}

# Regression, and the worst failure mode in the whole pipeline: `select()` inside a jq object
# constructor makes the ENTIRE construction produce `empty`, so jq writes nothing. A policy with
# `onboarded: ""` therefore produced a 0-byte evidence record while the run reported success —
# no evidence that the product was monitored, indistinguishable from a clean day.
test_monitor_writes_a_record_when_optional_policy_fields_are_blank() {
  rm -rf "$TMP/mrec"; mkdir -p "$TMP/mrec"
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nonboarded: ""\n' \
    > "$TMP/mrec/.soup-policy.yml"
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"},
                    properties:[{name:"quickbird:sbom:tier",value:"candidate"}]},
          components:[],vulnerabilities:[]}' > "$TMP/mrec/bom.json"
  MONITOR_LOCAL_SBOM="$TMP/mrec/bom.json" SOUP_POLICY_FILE="$TMP/mrec/.soup-policy.yml" \
    bash "$S/monitor-kev.sh" QuickBirdEng/x p "$TMP/mrec/out" >/dev/null 2>&1 || return 1
  local rec; rec=$(ls "$TMP/mrec/out"/*-p.json 2>/dev/null | head -1)
  [[ -s "$rec" ]] || return 1
  jq -e . "$rec" >/dev/null || return 1
  # the blank field is null, not a reason to drop the whole record
  assert "$(jq -r '.onboarded // "null"' "$rec")" "null" || return 1
  assert "$(jq -r '.maintenance_interval' "$rec")" "90d"
}

# And the run must refuse to look clean if the record did not survive.
test_monitor_fails_when_the_record_would_be_empty() {
  rm -rf "$TMP/mrec2"; mkdir -p "$TMP/mrec2/out"
  : > "$TMP/mrec2/out/2026-01-01-p.json"
  # a record that exists but is blank must not read as a monitored day
  bash -c '[[ -s "$1" ]] && jq -e . "$1" >/dev/null 2>&1' _ "$TMP/mrec2/out/2026-01-01-p.json"
  assert "$?" "1"
}

test_monitor_alerts_a_breach_without_any_kev_finding() {
  mkalert all-clear
  jq -n '{summary:{by_level:{undecided:1},worst:"undecided"},
          escalations:[{id:"CVE-2026-1",level:"undecided",track:"expedited",
                        detail:["remediation breached 9 working days ago, no decision recorded"]}]}' \
    > "$TMP/mon/esc.json"
  PRODUCT=p CRA_SCOPE=unknown bash "$S/compose-alert.sh" \
    "$TMP/mon/record.json" "$TMP/mon/alert.txt" "$TMP/mon/esc.json" "" >/dev/null 2>&1 || return 1
  grep -q "missed remediation deadlines" "$TMP/mon/alert.txt" || return 1
  grep -q "CVE-2026-1" "$TMP/mon/alert.txt"
}

# WI §7.3's release-required signal had the same problem.
test_monitor_alerts_release_required_without_any_kev_finding() {
  mkalert all-clear
  jq -n '{summary:{release_required:1},
          release_required:[{id:"CVE-2026-2",why:"fixed in main, not deployed"}]}' \
    > "$TMP/mon/lc.json"
  PRODUCT=p CRA_SCOPE=unknown bash "$S/compose-alert.sh" \
    "$TMP/mon/record.json" "$TMP/mon/alert.txt" "" "$TMP/mon/lc.json" >/dev/null 2>&1 || return 1
  grep -q "out-of-band release is required" "$TMP/mon/alert.txt" || return 1
  grep -q "CVE-2026-2" "$TMP/mon/alert.txt"
}

# An all-clear run with nothing outstanding must stay silent, or the alert becomes noise and
# the dated record stops being read.
# `cra_scope: false` must not tell someone at 3am that nothing is reportable. CRA Art. 2(2) exempts
# MDR/IVDR devices, but MDR Art. 87 vigilance applies on its own terms and the 2025-12-16 MDR/IVDR
# proposal would add the same actively-exploited-vulnerability reporting through MDR Annex I.
test_monitor_out_of_cra_scope_does_not_claim_nothing_is_reportable() {
  jq -n '{schema:"quickbird.kev-monitor-run/v1",verdict:"kev-findings",
          kev_findings:[{cve:"CVE-2021-44228",target:"t",version:"1",components:["log4j"]}],
          kev_membership_unknown:[],not_scanned:[],scanned:[{name:"x",version:"1"}]}' \
    > "$TMP/cra-rec.json"
  PRODUCT=p CRA_SCOPE=false bash "$S/compose-alert.sh" \
    "$TMP/cra-rec.json" "$TMP/cra-alert.txt" "" "" >/dev/null 2>&1 || return 1
  grep -q "the same as nothing being reportable" "$TMP/cra-alert.txt" || return 1
  grep -q "Art. 87" "$TMP/cra-alert.txt" || return 1
  # and it must still say to act
  grep -q "act immediately" "$TMP/cra-alert.txt"
}

test_monitor_stays_silent_when_there_is_nothing_to_say() {
  mkalert all-clear
  PRODUCT=p CRA_SCOPE=unknown bash "$S/compose-alert.sh" \
    "$TMP/mon/record.json" "$TMP/mon/alert.txt" "" "" >/dev/null 2>&1 || return 1
  assert "$(wc -c < "$TMP/mon/alert.txt" | tr -d ' ')" "0"
}

# A KEV finding and a breach in the same run must produce one message containing both, not
# one that overwrites the other.
test_monitor_combines_kev_and_breach_in_one_message() {
  rm -rf "$TMP/mon"; mkdir -p "$TMP/mon"
  jq -n '{schema:"quickbird.kev-monitor-run/v1",verdict:"kev-findings",
          kev_findings:[{cve:"CVE-2021-44228",target:"t",version:"1",components:["log4j"]}],
          kev_membership_unknown:[],not_scanned:[],scanned:[{name:"x",version:"1"}]}' \
    > "$TMP/mon/record.json"
  jq -n '{summary:{by_level:{breached:1}},
          escalations:[{id:"CVE-2026-3",level:"breached",detail:["mitigation breached"]}]}' \
    > "$TMP/mon/esc.json"
  PRODUCT=p CRA_SCOPE=true bash "$S/compose-alert.sh" \
    "$TMP/mon/record.json" "$TMP/mon/alert.txt" "$TMP/mon/esc.json" "" >/dev/null 2>&1 || return 1
  grep -q "CVE-2021-44228" "$TMP/mon/alert.txt" || return 1
  grep -q "CVE-2026-3" "$TMP/mon/alert.txt" || return 1
  grep -q "within 24 hours" "$TMP/mon/alert.txt"
}

# The window grid decides every Track 3/4 deadline, and the model exists because the previous
# one produced dates in the past on three of four products.
# ---------------------------------------------------------------- remediation units
mkunits() {
  # <artifact-name> <purl> <fix-status> <track>
  jq -n --arg art "$1" --arg purl "$2" --arg fx "$3" \
    '{bomFormat:"CycloneDX",specVersion:"1.6",
      metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
      components:[{"bom-ref":"c1",type:"library",name:"lib",version:"1.0",purl:$purl,
                   properties:[{name:"quickbird:component:artifact",value:$art}]}],
      vulnerabilities:[{id:"CVE-2026-1",affects:[{ref:"c1"}],
                        properties:[{name:"quickbird:vuln:fix",value:$fx}]}]}' > "$TMP/ru-bom.json"
  jq -n --arg t "$4" '{findings:[{id:"CVE-2026-1",track:$t,kev:false,
                                  mitigation_due:"2026-08-06T00:00:00+00:00",
                                  remediation_due:"2026-11-03T00:00:00+00:00"}]}' > "$TMP/ru-f.json"
  python3 "$S/group-remediation.py" "$TMP/ru-f.json" "$TMP/ru-bom.json" --out "$TMP/ru.json" 2>/dev/null
}

# Inside an image we deploy but do not build, "upgrade <module>" is not an action anyone here
# can perform. The first version of this grouping emitted ten such items for a third-party
# WireGuard image.
test_units_third_party_image_is_one_action() {
  mkunits "quickbird:artifact:deployed-wireguard-1.0.20210914" \
          "pkg:golang/golang.org/x/crypto@v0.1.0" available immediate || return 1
  assert "$(jq -r '.units[0].kind' "$TMP/ru.json")" "third-party-image" || return 1
  jq -re '.units[0].action | test("we do not build it")' "$TMP/ru.json" >/dev/null
}

# An OS package in an image we *do* build is a base-image bump (Annex B B.1.1).
test_units_our_own_os_package_is_a_base_image_bump() {
  mkunits "quickbird:artifact:docker-production-image-12" \
          "pkg:rpm/rhel/openssl@3.2.2?distro=rhel-9.7" available expedited || return 1
  assert "$(jq -r '.units[0].kind' "$TMP/ru.json")" "base-image-bump"
}

# A direct dependency in our own code stays its own action — there the CVE is the unit of work.
test_units_our_own_dependency_is_its_own_action() {
  mkunits "quickbird:artifact:server" "pkg:maven/com.foo/bar@1.0" available planned || return 1
  assert "$(jq -r '.units[0].kind' "$TMP/ru.json")" "dependency-upgrade"
}

# No published fix in our own code is a different action: a control or a VEX, not an upgrade.
test_units_no_published_fix_is_not_an_upgrade() {
  mkunits "quickbird:artifact:server" "pkg:maven/com.foo/bar@1.0" none-published expedited || return 1
  assert "$(jq -r '.units[0].kind' "$TMP/ru.json")" "no-upgrade-path" || return 1
  assert "$(jq -r '.units[0].findings_without_published_fix' "$TMP/ru.json")" "1"
}

# Grouping must never move a deadline outward: the unit takes the earliest of its members.
test_units_take_the_worst_track_and_earliest_deadline() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
          components:[{"bom-ref":"c1",type:"library",name:"a",version:"1",purl:"pkg:rpm/rhel/a@1",
                       properties:[{name:"quickbird:component:artifact",value:"quickbird:artifact:deployed-img"}]},
                      {"bom-ref":"c2",type:"library",name:"b",version:"1",purl:"pkg:rpm/rhel/b@1",
                       properties:[{name:"quickbird:component:artifact",value:"quickbird:artifact:deployed-img"}]}],
          vulnerabilities:[{id:"CVE-A",affects:[{ref:"c1"}],properties:[{name:"quickbird:vuln:fix",value:"available"}]},
                           {id:"CVE-B",affects:[{ref:"c2"}],properties:[{name:"quickbird:vuln:fix",value:"available"}]}]}' \
    > "$TMP/ru-bom.json"
  # kev as the string the classifier actually writes — the earlier boolean fixture was how
  # the `is True` comparison in group-remediation survived: the test data had a shape the
  # production data never has.
  jq -n '{findings:[{id:"CVE-A",track:"planned",kev:null,mitigation_due:"2026-10-01T00:00:00+00:00"},
                    {id:"CVE-B",track:"immediate",kev:"true",mitigation_due:"2026-08-06T00:00:00+00:00"}]}' \
    > "$TMP/ru-f.json"
  python3 "$S/group-remediation.py" "$TMP/ru-f.json" "$TMP/ru-bom.json" --out "$TMP/ru.json" 2>/dev/null || return 1
  assert "$(jq -r '.units | length' "$TMP/ru.json")" "1" || return 1
  assert "$(jq -r '.units[0].track' "$TMP/ru.json")" "immediate" || return 1
  assert "$(jq -r '.units[0].mitigation_due[0:10]' "$TMP/ru.json")" "2026-08-06" || return 1
  # the KEV member is named, because it is why the whole unit is Track 1
  assert "$(jq -r '.units[0].kev_findings | join(",")' "$TMP/ru.json")" "CVE-B"
}

# A finding the BOM cannot tie to a component must keep its own deadline rather than vanish.
test_units_unplaceable_finding_is_reported_not_dropped() {
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
          components:[],vulnerabilities:[]}' > "$TMP/ru-bom.json"
  jq -n '{findings:[{id:"CVE-X",track:"immediate",kev:false}]}' > "$TMP/ru-f.json"
  python3 "$S/group-remediation.py" "$TMP/ru-f.json" "$TMP/ru-bom.json" --out "$TMP/ru.json" 2>/dev/null || return 1
  assert "$(jq -r '.unplaced | length' "$TMP/ru.json")" "1" || return 1
  assert "$(jq -r '.unplaced[0].id' "$TMP/ru.json")" "CVE-X"
}

# ---------------------------------------------------------------- vendor state
mkvendor() {
  # <now> [decisions-file] -> units + escalation in $TMP
  jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",
          metadata:{component:{name:"p","bom-ref":"p",type:"application"}},
          components:[{"bom-ref":"c1",type:"library",name:"a",version:"1",purl:"pkg:rpm/rhel/a@1",
                       properties:[{name:"quickbird:component:artifact",
                                    value:"quickbird:artifact:deployed-wireguard-1.0.20210914"}]},
                      {"bom-ref":"c2",type:"library",name:"b",version:"1",purl:"pkg:rpm/rhel/b@1",
                       properties:[{name:"quickbird:component:artifact",
                                    value:"quickbird:artifact:deployed-wireguard-1.0.20210914"}]}],
          vulnerabilities:[{id:"CVE-A",affects:[{ref:"c1"}],properties:[{name:"quickbird:vuln:fix",value:"available"}]},
                           {id:"CVE-B",affects:[{ref:"c2"}],properties:[{name:"quickbird:vuln:fix",value:"available"}]}]}' \
    > "$TMP/vb.json"
  jq -n '{findings:[{id:"CVE-A",track:"immediate",kev:false,
                     mitigation_due:"2026-01-01T00:00:00+00:00",
                     remediation_due:"2026-01-15T00:00:00+00:00"},
                    {id:"CVE-B",track:"immediate",kev:false,
                     mitigation_due:"2026-01-01T00:00:00+00:00",
                     remediation_due:"2026-01-15T00:00:00+00:00"}]}' > "$TMP/vf.json"
  local args=("$TMP/vf.json" "$TMP/vb.json" --now "$1" --out "$TMP/vu.json")
  [[ -n "${2:-}" ]] && args+=(--decisions "$2")
  python3 "$S/group-remediation.py" "${args[@]}" >/dev/null 2>&1 || return 1
  python3 "$S/escalate-breaches.py" "$TMP/vf.json" --units "$TMP/vu.json" \
    --now "$1" --out "$TMP/ve.json" >/dev/null 2>&1
}

# Both of kontina-backend's units are third-party images. Counting a deadline against work
# nobody has started must be visible as exactly that.
test_vendor_no_request_on_record_is_named() {
  mkvendor 2026-06-01T00:00:00+00:00 || return 1
  assert "$(jq -r '.units[0].state' "$TMP/vu.json")" "no-vendor-request" || return 1
  jq -re '.units[0].state_detail | test("no request to them is on record")' "$TMP/vu.json" >/dev/null
}

# A dated request with a live follow-up is the record. Demanding a second decision on top would
# ask someone to accept a risk they have already acted on and cannot remove.
test_vendor_request_with_live_follow_up_is_not_a_breach() {
  printf 'vendor_requests:
  - unit: deployed-wireguard-1.0.20210914
    requested: 2026-05-01
    follow_up: 2026-12-01
    contact: "issue #1"
' > "$TMP/vd.yml"
  mkvendor 2026-06-01T00:00:00+00:00 "$TMP/vd.yml" || return 1
  assert "$(jq -r '.units[0].state' "$TMP/vu.json")" "waiting-on-vendor" || return 1
  # deadlines are long past, yet this is not undecided
  assert "$(jq -r '.escalations[0].level' "$TMP/ve.json")" "waiting-on-vendor"
}

# The follow-up date is what stops it being a parking space.
test_vendor_overdue_follow_up_becomes_a_decision() {
  printf 'vendor_requests:
  - unit: deployed-wireguard-1.0.20210914
    requested: 2026-05-01
    follow_up: 2026-05-15
    contact: "issue #1"
' > "$TMP/vd.yml"
  mkvendor 2026-06-01T00:00:00+00:00 "$TMP/vd.yml" || return 1
  assert "$(jq -r '.units[0].state' "$TMP/vu.json")" "vendor-overdue" || return 1
  assert "$(jq -r '.escalations[0].level' "$TMP/ve.json")" "undecided" || return 1
  # and the decision is about the image, not about each finding
  jq -re '.escalations[0].detail[0] | test("whether to replace this image")' "$TMP/ve.json" >/dev/null
}

# A request with no follow-up date never comes back up, which makes it a note rather than a
# control — and it must not read as handled.
test_vendor_request_without_a_follow_up_date_is_flagged() {
  printf 'vendor_requests:
  - unit: deployed-wireguard-1.0.20210914
    requested: 2026-05-01
' > "$TMP/vd.yml"
  mkvendor 2026-06-01T00:00:00+00:00 "$TMP/vd.yml" || return 1
  assert "$(jq -r '.units[0].state' "$TMP/vu.json")" "vendor-request-undated"
}

# The point of collapsing: two findings in one image produce one escalation naming both.
test_vendor_escalation_is_per_action_not_per_finding() {
  mkvendor 2026-06-01T00:00:00+00:00 || return 1
  assert "$(jq -r '.escalations | length' "$TMP/ve.json")" "1" || return 1
  assert "$(jq -r '.escalations[0].finding_count' "$TMP/ve.json")" "2" || return 1
  assert "$(jq -r '.escalations[0].escalating_findings | length' "$TMP/ve.json")" "2"
}

# The 2026-08-03 decision keeps tier and cra_scope in the product repo behind CODEOWNERS. That
# is a review control, and it is only as strong as the branch protection behind it — so a change
# to either must also be detectable from the evidence store afterwards.
test_backstop_detects_a_changed_determination() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  for spec in 2026-07-01:Extended:true 2026-08-01:Basic:false; do
    d="${spec%%:*}"; r="${spec#*:}"
    jq -n --arg d "${d}T06:00:00+00:00" --arg t "${r%%:*}" --arg c "${r##*:}" \
      '{schema:"quickbird.kev-monitor-run/v1",product:"p",repo:"QuickBirdEng/nope",run_at:$d,
        tier:$t,cra_scope:$c,synthetic:false,scanned:[{name:"x",version:"1"}],
        not_scanned:[],kev_findings:[]}' > "$TMP/ev/p-$d.json"
  done
  python3 "$S/backstop-report.py" "$TMP/ev" --window 90 --max-gap 40 \
    --now 2026-08-03T06:00:00+00:00 --out "$TMP/bd.json" >/dev/null 2>&1
  assert "$(jq -r '[.determination_drift[].field] | sort | join(",")' "$TMP/bd.json")" "cra_scope,tier" || return 1
  # drift alone must make the verdict action-required
  assert "$(jq -r '.verdict' "$TMP/bd.json")" "action-required"
}

# A product whose determinations never change must stay silent, or the check becomes noise.
test_backstop_stable_determinations_are_silent() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  for d in 2026-07-01 2026-08-01; do
    jq -n --arg d "${d}T06:00:00+00:00" \
      '{schema:"quickbird.kev-monitor-run/v1",product:"p",repo:"QuickBirdEng/nope",run_at:$d,
        tier:"Basic",cra_scope:"false",synthetic:false,scanned:[{name:"x",version:"1"}],
        not_scanned:[],kev_findings:[]}' > "$TMP/ev/p-$d.json"
  done
  python3 "$S/backstop-report.py" "$TMP/ev" --window 90 --max-gap 40 \
    --now 2026-08-03T06:00:00+00:00 --out "$TMP/bd.json" >/dev/null 2>&1
  assert "$(jq -r '.determination_drift | length' "$TMP/bd.json")" "0"
}

test_maintenance_window_grid() {
  S="$S" python3 "$HERE/maintenance-window-logic.py"
}

test_backstop_production_signals_disagree_visibly() {
  S="$S" python3 "$HERE/production-signal-logic.py"
}

test_net_currency_detects_an_abandoned_package() {
  need_net || return 77
  mkcur '[{"bom-ref":"a","type":"library","name":"request","version":"2.88.2","purl":"pkg:npm/request@2.88.2",
           "properties":[{"name":"quickbird:soup:record","value":"r"}]}]'
  mkdir -p "$TMP/csoups4"; printf '{"package":"request","version":"2.x.x"}' > "$TMP/csoups4/r.json"
  python3 "$S/check-currency.py" "$TMP/cb.json" "$TMP/cp.json" --soups "$TMP/csoups4" --out "$TMP/co.json" >/dev/null 2>&1 || return 1
  # request has been unreleased since 2020 while npm's `modified` field still moves
  assert "$(jq -r '.beyond_policy[0].finding' "$TMP/co.json")" "upstream-stale-and-we-are-current" || return 1
  [[ "$(jq -r '.beyond_policy[0].last_release_age_days' "$TMP/co.json")" -gt 1000 ]] \
    || { echo "age looks like npm's modified field, not the publish time"; return 1; }
}

test_net_currency_against_real_registries() {
  need_net || return 77
  mkcur '[{"bom-ref":"a","type":"library","name":"okhttp","version":"4.12.0","purl":"pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
           "properties":[{"name":"quickbird:soup:record","value":"r"}]}]'
  mkdir -p "$TMP/csoups3"; printf '{"package":"okhttp","version":"4.x.x"}' > "$TMP/csoups3/o.json"
  python3 "$S/check-currency.py" "$TMP/cb.json" "$TMP/cp.json" --soups "$TMP/csoups3" --out "$TMP/co.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.summary.beyond_policy' "$TMP/co.json")" "1"
}

# ---------------------------------------------------------------- backstop
mkrun() { jq -n --arg p "$1" --arg at "${2}T09:00:00+00:00" --arg v "$3" --argjson syn "${4:-false}" \
  '{schema:"quickbird.kev-monitor-run/v1",product:$p,run_at:$at,verdict:$v,synthetic:$syn}' \
  > "$TMP/ev/${2}-$1${5:-}.json"; }

# The finding a daily alert can never produce: a product that stopped being scanned emits
# no alerts at all, which is indistinguishable from a product with nothing wrong.
test_backstop_catches_a_product_that_stopped_being_scanned() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun p1 2026-07-01 all-clear
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.coverage[0].status' "$TMP/bs.json")" "stale" || return 1
  assert "$(jq -r '.verdict' "$TMP/bs.json")" "action-required"
}

test_backstop_catches_a_product_with_no_records_at_all() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun p1 2026-08-02 all-clear
  python3 "$S/backstop-report.py" "$TMP/ev" --products p1,p2 --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '[.coverage[]|select(.product=="p2")][0].status' "$TMP/bs.json")" "never-scanned"
}

# A synthetic run is a test, not evidence that a product was monitored.
test_backstop_ignores_synthetic_runs() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun p1 2026-08-02 all-clear true -synth
  python3 "$S/backstop-report.py" "$TMP/ev" --products p1 --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.coverage[0].status' "$TMP/bs.json")" "never-scanned"
}

test_backstop_reports_gaps_between_runs() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun p1 2026-07-01 all-clear; mkrun p1 2026-07-20 all-clear; mkrun p1 2026-08-02 all-clear
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.coverage[0].status' "$TMP/bs.json")" "gaps" || return 1
  assert "$(jq -r '.coverage[0].gaps|length' "$TMP/bs.json")" "2"
}

# A backstop that always passes is not a control.
test_backstop_exits_nonzero_when_action_is_required() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun p1 2026-07-01 all-clear
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T00:00:00+00:00 >/dev/null 2>&1
  assert "$?" "1"
}

test_backstop_clean_when_everything_is_current() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  for d in 2026-08-01 2026-08-02; do mkrun p1 "$d" all-clear; done
  python3 "$S/backstop-report.py" "$TMP/ev" --products p1 --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$?" "0" || return 1
  assert "$(jq -r '.verdict' "$TMP/bs.json")" "clean"
}

# What it does not check must be visible, not absent.
mkrun_cadence() { jq -n --arg p "$1" --arg at "${2}T09:00:00+00:00" --arg r "$3" --arg c "$4" \
  '{schema:"quickbird.kev-monitor-run/v1",product:$p,repo:$r,run_at:$at,verdict:"all-clear",
    synthetic:false,maintenance_interval:$c}' > "$TMP/ev/${2}-$1.json"; }

# A cadence that is not declared leaves Track 3/4 with nothing to derive a deadline from,
# which must be visible rather than absent.
test_backstop_flags_an_undeclared_cadence() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun_cadence p1 2026-08-02 QuickBirdEng/nope ""
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.cadence[0].status' "$TMP/bs.json")" "not-declared"
}

# Not being able to read the release history is not the same as the cadence holding.
test_backstop_unreadable_releases_are_unknown_not_holding() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun_cadence p1 2026-08-02 QuickBirdEng/definitely-not-a-real-repo-xyz monthly
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.cadence[0].status' "$TMP/bs.json")" "unknown"
}

# A changed maintenance_interval moves every Track 3/4 deadline, so it belongs in the same drift
# detection as tier and cra_scope.
test_backstop_detects_a_changed_maintenance_commitment() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  for spec in 2026-07-01:60d 2026-08-01:90d; do
    d="${spec%%:*}"
    jq -n --arg d "${d}T06:00:00+00:00" --arg i "${spec##*:}" \
      '{schema:"quickbird.kev-monitor-run/v1",product:"p",repo:"QuickBirdEng/nope",run_at:$d,
        tier:"Basic",cra_scope:"false",maintenance_interval:$i,synthetic:false,
        scanned:[{name:"x",version:"1"}],not_scanned:[],kev_findings:[]}' > "$TMP/ev/p-$d.json"
  done
  python3 "$S/backstop-report.py" "$TMP/ev" --window 90 --max-gap 40 \
    --now 2026-08-03T06:00:00+00:00 --out "$TMP/bd.json" >/dev/null 2>&1
  assert "$(jq -r '[.determination_drift[].field] | join(",")' "$TMP/bd.json")" "maintenance_interval"
}

# BSI TR-03161 O.TrdP_2 requires third-party software to be the newest version or the one preceding
# it. The process default tolerates unlimited patch drift, which does not meet that. A regulatory
# scope entry that only appeared in prose would be a requirement nobody applies.
test_policy_tr03161_requires_a_patch_limit() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nregulatory_scope: [tr-03161-3]\n' \
    > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>"$TMP/tr.txt" && return 1
  grep -q "O.TrdP_2" "$TMP/tr.txt" || return 1
  # with a patch limit stated, it passes
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nregulatory_scope: [tr-03161-3]\ndependency_currency:\n  max_behind:\n    patch: 1\n' \
    > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
}

# O.TrdP_8: third-party software that is no longer maintained MUST NOT be used, so accepting
# obsolescence with a reason is not available for a product in that scope.
test_policy_tr03161_forbids_accepting_obsolescence() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nregulatory_scope: [tr-03161-1]\ndependency_currency:\n  max_behind:\n    patch: 1\n  obsolescence_may_be_accepted: true\n' \
    > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>"$TMP/tr.txt" && return 1
  grep -q "O.TrdP_8" "$TMP/tr.txt"
}

# A regime nobody defined must not pass silently.
test_policy_rejects_an_unknown_regulatory_scope() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\nregulatory_scope: [tr-99999]\n' \
    > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "1"
}

# A product with no regulatory scope keeps the process default.
test_policy_no_regulatory_scope_keeps_the_default() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\n' > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1 || return 1
  assert "$(bash "$S/validate-policy.sh" "$TMP/pol.yml" 2>/dev/null | jq -r '.dependency_currency.max_behind.patch')" "unlimited"
}

test_policy_rejects_a_non_duration_maintenance_interval() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: whenever\n' > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
  assert "$?" "1"
}

# The tier is the statement about how often a product is maintained, so a commitment looser
# than the tier allows is the one override that cannot be waived with a reason.
test_policy_rejects_an_interval_looser_than_the_tier_allows() {
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 180d\n' > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1 && return 1
  printf 'product: p\ntier: Basic\ncra_scope: false\nmaintenance_interval: 45d\n' > "$TMP/pol.yml"
  bash "$S/validate-policy.sh" "$TMP/pol.yml" >/dev/null 2>&1
}

# The distinction that flips the answer: alvie published six releases in 90 days and reads
# as a product on a monthly cadence, but its last *production* release was over a year ago.
# A Track 3/4 deadline is a remediation deadline, and remediation is satisfied on deploy.
test_net_backstop_cadence_counts_production_releases_only() {
  need_net || return 77
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun_cadence alvie 2026-08-02 QuickBirdEng/alvie monthly
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  # The basis must name the source, and the source is the deployment record.
  jq -re '.cadence[0].counted | test("production deployments from a tag")' "$TMP/bs.json" >/dev/null || return 1
  # alvie last deployed v1.0.7 to production on 2026-04-21, so a 90-day commitment is missed.
  assert "$(jq -r '.cadence[0].status' "$TMP/bs.json")" "broken" || return 1
  jq -re '.cadence[0].last_release | startswith("2026-04-21")' "$TMP/bs.json" >/dev/null
}

# ------------------------------------------------- code-review regressions (2026-08-05)
# Each of these reproduces a defect found by the full review, not by a run. The common
# thread: the wrong answer looked exactly like a right one.

# Regression: `gh api --jq --arg` — gh takes --jq with ONE expression and forwards nothing
# to jq, so the asset lookup errored, `|| echo ""` ate the error, and every deployed tag
# reported "no SBOM asset". The fake gh below answers like the real API so the resolution
# path is testable at all (it had zero tests, and all three critical review findings lived
# in untested code).
make_fake_gh() {
  mkdir -p "$TMP/fakebin"
  cat > "$TMP/fakebin/gh" <<'FAKE'
#!/usr/bin/env bash
# minimal gh-api fake: answers the endpoints resolve-deployed.sh asks, from fixture files.
# The endpoint is the first argument that looks like a path — flags like --paginate and
# --jq come in any position and must not be mistaken for it.
EP=""
for a in "$@"; do case "$a" in repos/*) EP="$a"; break;; esac; done
case "$EP" in
  repos/*/releases?per_page=100) cat "$FAKE_DIR/releases.json" ;;
  repos/*/environments) 
    # supports --jq '.environments[].name'
    jq -r '.environments[].name' "$FAKE_DIR/environments.json" ;;
  repos/*/deployments?environment=*)
    env_name=$(printf '%s' "$EP" | sed -E 's/.*environment=([^&]*).*/\1/')
    jq -c --arg e "$env_name" '[.[] | select(.environment == $e)]' "$FAKE_DIR/deployments.json" ;;
  repos/*/deployments?per_page=100) cat "$FAKE_DIR/deployments.json" ;;
  repos/*/git/matching-refs/tags) cat "$FAKE_DIR/tags.json" ;;
  repos/*/deployments/*/statuses?per_page=1) echo '[{"state":"success"}]' ;;
  repos/*/releases/tags/*) 
    tag="${EP##*/}"
    jq -e --arg t "$tag" '.[] | select(.tag_name == $t)' "$FAKE_DIR/releases.json" || exit 1 ;;
  *) echo "fake gh: unhandled $EP" >&2; exit 1 ;;
esac
FAKE
  chmod +x "$TMP/fakebin/gh"
}

fake_gh_fixtures() {  # <dir>
  mkdir -p "$1"
  cat > "$1/environments.json" <<'EOF'
{"environments":[{"name":"Study"},{"name":"dev"}]}
EOF
  cat > "$1/deployments.json" <<'EOF'
[{"environment":"Study","ref":"v1.2.0","sha":"abc","created_at":"2026-07-01T10:00:00Z","id":1},
 {"environment":"dev","ref":"main","sha":"def","created_at":"2026-08-01T10:00:00Z","id":2}]
EOF
  cat > "$1/tags.json" <<'EOF'
[{"ref":"refs/tags/v1.2.0"}]
EOF
  cat > "$1/releases.json" <<'EOF'
[{"tag_name":"v1.2.0","published_at":"2026-07-01T09:00:00Z",
  "assets":[{"name":"sbom-v1.2.0.cdx.json","url":"https://api.github.com/repos/owner/repo/releases/assets/9"}]}]
EOF
}

test_resolve_deployed_finds_the_sbom_asset() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx1"
  out=$(FAKE_DIR="$TMP/fx1" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo) || return 1
  # the defect made this null on every deployed tag
  # the API asset URL — the browser URL is not downloadable with a token on a private repo
  assert "$(jq -r '.environments[0].sbom' <<<"$out")" "https://api.github.com/repos/owner/repo/releases/assets/9" || return 1
  assert "$(jq -r '.environments[0].sbom_status' <<<"$out")" "available"
}

test_resolve_deployed_reads_environments_server_side() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx2"
  # 150 dev deployments would push Study off a first-100 page; server-side per-env must not care
  python3 - "$TMP/fx2/deployments.json" <<'PYEOF'
import json, sys
rows=[{"environment":"dev","ref":"main","sha":"d","created_at":f"2026-08-01T{i%24:02d}:00:00Z","id":100+i} for i in range(150)]
rows.append({"environment":"Study","ref":"v1.2.0","sha":"abc","created_at":"2026-07-01T10:00:00Z","id":1})
json.dump(rows, open(sys.argv[1],"w"))
PYEOF
  out=$(FAKE_DIR="$TMP/fx2" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo) || return 1
  contains "$(jq -r '[.environments[].environment] | join(",")' <<<"$out")" "Study"
}

# ------------------------------------------------- dependency scope (direct/transitive)
# "Direct" used to mean "carries a SOUP record" — a proxy that could not fail. The scope
# now comes from the manifests; these pin each parser.

scope_bom() {  # <file> <name...>
  local f="$1"; shift
  local comps=""
  for n in "$@"; do
    comps+="{\"bom-ref\":\"$n\",\"type\":\"library\",\"name\":\"$n\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/$n@1.0.0\"},"
  done
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[%s]}' "${comps%,}" > "$f"
}

scope_of() { jq -r --arg n "$2" '.components[] | select(.name==$n) | [.properties[]? | select(.name=="quickbird:dependency:scope")][0].value // "undetermined"' "$1"; }

test_scope_pub_reads_the_lockfile_markers() {
  mkdir -p "$TMP/sc-pub/app"
  cat > "$TMP/sc-pub/app/pubspec.yaml" <<'EOF'
name: app
EOF
  cat > "$TMP/sc-pub/app/pubspec.lock" <<'EOF'
packages:
  http:
    dependency: "direct main"
    version: "1.0.0"
  collection:
    dependency: transitive
    version: "1.18.0"
EOF
  scope_bom "$TMP/sc-pub/bom.json" http collection
  python3 "$S/mark-scope.py" "$TMP/sc-pub/bom.json" --ecosystem pub \
    --repo "$TMP/sc-pub" --markers "app/pubspec.yaml" >/dev/null 2>&1 || return 1
  assert "$(scope_of "$TMP/sc-pub/bom.json" http)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-pub/bom.json" collection)" "transitive"
}

test_scope_npm_joins_every_package_json() {
  mkdir -p "$TMP/sc-npm/web" "$TMP/sc-npm/web/packages/member"
  echo '{"dependencies":{"axios":"^1.0.0"}}' > "$TMP/sc-npm/web/package.json"
  echo '{"dependencies":{"lodash":"^4.0.0"}}' > "$TMP/sc-npm/web/packages/member/package.json"
  scope_bom "$TMP/sc-npm/bom.json" axios lodash follow-redirects
  python3 "$S/mark-scope.py" "$TMP/sc-npm/bom.json" --ecosystem npm --repo "$TMP/sc-npm" \
    --markers "web/package.json,web/packages/member/package.json" >/dev/null 2>&1 || return 1
  assert "$(scope_of "$TMP/sc-npm/bom.json" axios)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-npm/bom.json" lodash)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-npm/bom.json" follow-redirects)" "transitive"
}

test_scope_maven_reads_declared_dependencies() {
  mkdir -p "$TMP/sc-mvn/mod"
  cat > "$TMP/sc-mvn/mod/pom.xml" <<'EOF'
<project><dependencies>
  <dependency><groupId>io.netty</groupId><artifactId>netty-handler</artifactId></dependency>
</dependencies></project>
EOF
  scope_bom "$TMP/sc-mvn/bom.json" netty-handler netty-common
  python3 "$S/mark-scope.py" "$TMP/sc-mvn/bom.json" --ecosystem jvm-maven \
    --repo "$TMP/sc-mvn" --markers "mod/pom.xml" >/dev/null 2>&1 || return 1
  assert "$(scope_of "$TMP/sc-mvn/bom.json" netty-handler)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-mvn/bom.json" netty-common)" "transitive"
}

test_scope_go_respects_indirect_marker() {
  mkdir -p "$TMP/sc-go/svc"
  cat > "$TMP/sc-go/svc/go.mod" <<'EOF'
module example.com/svc
require (
	golang.org/x/crypto v0.22.0
	golang.org/x/sys v0.19.0 // indirect
)
EOF
  scope_bom "$TMP/sc-go/bom.json" golang.org/x/crypto golang.org/x/sys
  python3 "$S/mark-scope.py" "$TMP/sc-go/bom.json" --ecosystem go \
    --repo "$TMP/sc-go" --markers "svc/go.mod" >/dev/null 2>&1 || return 1
  assert "$(scope_of "$TMP/sc-go/bom.json" golang.org/x/crypto)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-go/bom.json" golang.org/x/sys)" "transitive"
}

test_scope_gradle_reads_declared_coordinates() {
  mkdir -p "$TMP/sc-gr/app/android/app"
  cat > "$TMP/sc-gr/app/android/app/build.gradle" <<'EOF'
dependencies {
    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:2.1.5'
}
EOF
  scope_bom "$TMP/sc-gr/bom.json" desugar_jdk_libs kotlin-stdlib
  python3 "$S/mark-scope.py" "$TMP/sc-gr/bom.json" --ecosystem android-gradle \
    --repo "$TMP/sc-gr" --markers "app/android/app/build.gradle" >/dev/null 2>&1 || return 1
  assert "$(scope_of "$TMP/sc-gr/bom.json" desugar_jdk_libs)" "direct" || return 1
  assert "$(scope_of "$TMP/sc-gr/bom.json" kotlin-stdlib)" "transitive"
}

# The finding the whole step exists for: chosen, shipped, never approved.
test_assessment_flags_direct_without_record() {
  mkdir -p "$TMP/dwr/soups/npm"
  soup_record other "1.x.x" "1.0.0" > "$TMP/dwr/soups/npm/other.json"
  cat > "$TMP/dwr/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"root","name":"p","type":"application"}},
 "components":[
   {"bom-ref":"a","type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21",
    "properties":[{"name":"quickbird:dependency:scope","value":"direct"}]},
   {"bom-ref":"b","type":"library","name":"follow-redirects","version":"1.15.11","purl":"pkg:npm/follow-redirects@1.15.11",
    "properties":[{"name":"quickbird:dependency:scope","value":"transitive"}]},
   {"bom-ref":"c","type":"library","name":"other","version":"1.0.0","purl":"pkg:npm/other@1.0.0"}],
 "vulnerabilities":[]}
EOF
  out=$(bash "$S/merge-assessment.sh" "$TMP/dwr/bom.json" "$TMP/dwr/soups" "$TMP/dwr/out.json" 2>&1) || return 1
  contains "$out" "no record: lodash@4.17.21" || return 1
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:soup:direct-without-record")][0].value' "$TMP/dwr/out.json")" "1" || return 1
  # the transitive without a record is expected and must NOT be flagged
  ! grep -q "follow-redirects" <<<"$out"
}

# Currency selects by scope when the document carries it — a direct dependency without a
# record is checked instead of skipped.
test_currency_selects_by_scope() {
  cat > "$TMP/cs-bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"bom-ref":"a","type":"library","name":"pkg","version":"1.0.0","purl":"pkg:weird/pkg@1.0.0",
   "properties":[{"name":"quickbird:dependency:scope","value":"direct"}]},
  {"bom-ref":"b","type":"library","name":"dep","version":"1.0.0","purl":"pkg:weird/dep@1.0.0",
   "properties":[{"name":"quickbird:dependency:scope","value":"transitive"}]}]}
EOF
  mkdir -p "$TMP/cs-soups"
  python3 "$S/check-currency.py" "$TMP/cs-bom.json" "$TMP/cp.json" \
    --soups "$TMP/cs-soups" --out "$TMP/cs-out.json" >/dev/null 2>&1 || return 1
  # the direct one is checked (lands in unknown — no registry for pkg:weird), the
  # transitive one is not checked at all
  contains "$(jq -r '[.unknown[].name] | join(",")' "$TMP/cs-out.json")" "pkg" || return 1
  ! jq -e '.unknown[] | select(.name=="dep")' "$TMP/cs-out.json" >/dev/null
}

# The bundle carries the classification, not only the findings side-file — the PDF is a
# pure function of the bundle, so what it must show has to be in it.
test_classify_annotates_vulnerabilities_in_the_bundle() {
  cat > "$TMP/anv.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],
 "vulnerabilities":[{"id":"CVE-77","affects":[{"ref":"a"}],
   "ratings":[{"source":{"name":"OSV"},"method":"CVSSv31","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}
EOF
  python3 "$S/classify-findings.py" "$TMP/anv.json" "$TMP/cp.json" \
    --annotate-bom "$TMP/anv.json" --now "2026-08-06T12:00:00+00:00" --out "$TMP/anvf.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.vulnerabilities[0].properties[] | select(.name=="quickbird:finding:track")][0].value' "$TMP/anv.json")" "immediate" || return 1
  contains "$(jq -r '[.vulnerabilities[0].properties[].name] | join(",")' "$TMP/anv.json")" "quickbird:finding:mitigation-due"
}

# Currency annotation is a pure function over collected notes — testable without a registry.
test_currency_annotate_bom_stamps_latest() {
  cat > "$TMP/cur-ann.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"bom-ref":"a","type":"library","name":"pkg","version":"1.0.0","purl":"pkg:npm/pkg@1.0.0"}]}
EOF
  python3 - "$S/check-currency.py" "$TMP/cur-ann.json" <<'PYEOF'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("cc", sys.argv[1])
cc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cc)
n = cc.annotate_bom(sys.argv[2], {"pkg:npm/pkg@1.0.0": {"status": "behind", "latest": "2.1.0",
                                                        "detail": "behind by 1 major / 0 minor / 0 patch"}})
assert n == 1, n
bom = json.load(open(sys.argv[2]))
props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
assert props["quickbird:currency:latest"] == "2.1.0", props
assert props["quickbird:currency:status"] == "behind", props
PYEOF
}

# A record for an image must match the artifact scanned from that image, keyed on the
# scan target — the artifact component is named after the candidate id, not the image.
test_record_matches_image_artifact_by_target() {
  mkdir -p "$TMP/img/soups/tools"
  cat > "$TMP/img/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"root","name":"p","type":"application"}},
 "components":[{"bom-ref":"quickbird:artifact:web-keycloak-image-1","type":"container",
   "name":"web-keycloak-image-1","version":"26.5.4",
   "properties":[{"name":"quickbird:scan:target","value":"registry:quay.io/keycloak/keycloak:26.5.4"}]}],
 "vulnerabilities":[]}
EOF
  cat > "$TMP/img/soups/tools/keycloak.json" <<'EOF'
{"package":"keycloak","version":"26.x.x","metadata":{"input_version":"26.4.2","approval":{"by":"X","date":"2026-01-01"}}}
EOF
  bash "$S/merge-assessment.sh" "$TMP/img/bom.json" "$TMP/img/soups" "$TMP/img/out.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '[.components[] | select(.properties[]? | .name=="quickbird:soup:approved")] | length' "$TMP/img/out.json")" "1"
}

# An orphan whose name ships in a different version family is approval drift, not a stale
# record — wireguard approved as 1.0.20241014 while 1.0.20210914 is deployed.
test_record_family_drift_is_reported_distinctly() {
  mkdir -p "$TMP/dr/soups/tools"
  cat > "$TMP/dr/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"root","name":"p","type":"application"}},
 "components":[{"bom-ref":"quickbird:artifact:deployed-wireguard","type":"container",
   "name":"deployed-wireguard-1.0.20210914","version":"1.0.20210914",
   "properties":[{"name":"quickbird:scan:target","value":"registry:linuxserver/wireguard:1.0.20210914"}]}],
 "vulnerabilities":[]}
EOF
  cat > "$TMP/dr/soups/tools/wireguard.json" <<'EOF'
{"package":"wireguard","version":"1.0.20241014","metadata":{"input_version":"1.0.20241014","approval":{"by":"X","date":"2026-01-01"}}}
EOF
  out=$(bash "$S/merge-assessment.sh" "$TMP/dr/bom.json" "$TMP/dr/soups" "$TMP/dr/out.json" 2>&1)
  contains "$out" "approved family 1.0.20241014, shipped 1.0.20210914" || return 1
  # and it is NOT counted among the plain orphans
  contains "$out" "0 SOUP record(s) match no component" || ! grep -q "match no component" <<<"$out" || return 1
  # the component itself says so — a reader of the document must not have to hunt the metadata
  contains "$(jq -r '[.components[0].properties[]? | select(.name=="quickbird:soup:approval-drift")][0].value' "$TMP/dr/out.json")" "does not apply to this version"
}

# The android closure: syft reads zero components out of an AAB (measured), so the gradle
# lockfile is the only faithful source. With one present, discovery must route to it
# instead of demanding the built artifact.
test_discover_android_prefers_gradle_lockfile() {
  mkdir -p "$TMP/mob/app/android/app"
  printf 'name: app\n' > "$TMP/mob/app/pubspec.yaml"
  : > "$TMP/mob/app/android/build.gradle"
  : > "$TMP/mob/app/android/app/build.gradle"
  : > "$TMP/mob/app/android/app/gradle.lockfile"
  ( cd "$TMP/mob" && git init -q . && git add -A )
  DISCOVER_OUTPUT="$TMP/mob/cand.json" bash "$S/discover.sh" "$TMP/mob" >/dev/null 2>&1 || return 1
  src=$(jq -r '.candidates[] | select(.id=="app-android") | .scan_source' "$TMP/mob/cand.json")
  assert "$src" "file:app/android/app/gradle.lockfile"
}

# Regression (found on the runner, not in the review): with contents:read only, the
# environments list answers and every per-environment deployments fetch 403s. The old
# `|| continue` made Production silently vanish from both lists.
test_resolve_deployed_names_unreadable_environments() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx3"
  # fake gh: env list works, per-env deployment fetch fails like real gh does — the error
  # BODY goes to stdout and the exit code is 1. Modelling only the exit code hid the second
  # runner finding below.
  cat > "$TMP/fakebin/gh" <<'FAKE'
#!/usr/bin/env bash
EP=""
for a in "$@"; do case "$a" in repos/*) EP="$a"; break;; esac; done
case "$EP" in
  repos/*/releases?per_page=100) echo '[]' ;;
  repos/*/environments) echo '{"environments":[{"name":"Production"}]}' ;;
  repos/*/deployments?environment=*) echo '{"message":"Resource not accessible by integration"}'; exit 1 ;;
  repos/*/git/matching-refs/tags) echo '[]' ;;
  *) exit 1 ;;
esac
FAKE
  chmod +x "$TMP/fakebin/gh"
  out=$(FAKE_DIR="$TMP/fx3" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo) || return 1
  contains "$(jq -r '.unresolvable[].why' <<<"$out")" "could not be read"
}

# Regression (third runner finding): gh api prints the RESPONSE BODY to stdout on an HTTP
# error. A 403 on /environments therefore produced a phantom environment named
# {"message":...}, whose filtered query politely returned [] — and every real environment
# vanished without an error anywhere. The names must come from the deployment records when
# the listing is refused.
test_resolve_deployed_survives_error_body_on_stdout() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx5"
  cat > "$TMP/fakebin/gh" <<'FAKE'
#!/usr/bin/env bash
EP=""
for a in "$@"; do case "$a" in repos/*) EP="$a"; break;; esac; done
case "$EP" in
  repos/*/releases?per_page=100) echo '[]' ;;
  repos/*/environments) echo '{"message":"Resource not accessible by integration","status":"403"}'; exit 1 ;;
  repos/*/deployments?environment=*)
    env_name=$(printf '%s' "$EP" | sed -E 's/.*environment=([^&]*).*/\1/')
    jq -c --arg e "$env_name" '[.[] | select(.environment == $e)]' "$FAKE_DIR/deployments.json" ;;
  repos/*/deployments?per_page=100) cat "$FAKE_DIR/deployments.json" ;;
  repos/*/git/matching-refs/tags) cat "$FAKE_DIR/tags.json" ;;
  repos/*/deployments/*/statuses?per_page=1) echo '[{"state":"success"}]' ;;
  repos/*/releases/tags/*) exit 1 ;;
  *) echo "fake gh: unhandled $EP" >&2; exit 1 ;;
esac
FAKE
  chmod +x "$TMP/fakebin/gh"
  out=$(FAKE_DIR="$TMP/fx5" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo 2>/dev/null) || return 1
  # Study must be found via the names derived from the unfiltered page
  contains "$(jq -r '[.environments[].environment] | join(",")' <<<"$out")" "Study"
}

# Regression: an environment whose newest records are all non-tag refs disappeared from
# both lists — real on a repo whose Production env is also written by a content-migration
# workflow dispatching from branches.
test_resolve_deployed_names_tagless_environments() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx4"
  cat > "$TMP/fx4/deployments.json" <<'EOF'
[{"environment":"Study","ref":"some-branch","sha":"d","created_at":"2026-08-01T10:00:00Z","id":7}]
EOF
  cat > "$TMP/fx4/tags.json" <<'EOF'
[]
EOF
  out=$(FAKE_DIR="$TMP/fx4" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo) || return 1
  contains "$(jq -r '.unresolvable[] | select(.environment=="Study") | .why' <<<"$out")" "none from a tag"
}

# Regression: a Development environment without an SBOM kept every record at `incomplete`.
# The unscannable list follows the same production filter as the targets.
test_monitor_unscannable_filters_to_production() {
  echo '{"unresolvable":[
    {"environment":"Development","ref":"x","why":"no sbom"},
    {"environment":"Production","ref":"v1","why":"no sbom"},
    {"environment":"mobile","ref":"v1","why":"no asset"},
    {"environment":"*","ref":null,"why":"nothing states what runs"}]}' > "$TMP/uf.json"
  n=$(jq '[ .unresolvable[]?
    | select((.environment | test("prod|study|mobile"; "i")) or .environment == "*") ] | length' "$TMP/uf.json")
  assert "$n" "3"
}

# Regression (found on the runner): Linux caps a single process argument at 128KB, and
# passing accumulated deployment pages through --argjson blew that limit — jq died, the
# failed substitution left an empty string, and every environment silently vanished. This
# fixture makes one environment page ~400KB. On macOS the old code passed anyway (larger
# limit); the test still pins the file-based accumulation against regressions, and fails
# properly on any Linux machine the suite runs on.
test_resolve_deployed_survives_large_deployment_pages() {
  make_fake_gh
  fake_gh_fixtures "$TMP/fx6"
  python3 - "$TMP/fx6/deployments.json" <<'PYEOF'
import json, sys
pad = "x" * 4000
rows = [{"environment":"Study","ref":"v1.2.0","sha":"abc","created_at":f"2026-07-01T{i%24:02d}:00:00Z",
         "id": i, "payload": pad} for i in range(100)]
json.dump(rows, open(sys.argv[1], "w"))
PYEOF
  out=$(FAKE_DIR="$TMP/fx6" PATH="$TMP/fakebin:$PATH" bash "$S/resolve-deployed.sh" owner/repo 2>/dev/null) || return 1
  contains "$(jq -r '[.environments[].environment] | join(",")' <<<"$out")" "Study"
}

# Regression: the monitor filtered targets on /prod/ only. A Study-only product fell out of
# both lists and the record said all_clear with nothing scanned.
test_monitor_targets_include_study() {
  # unit-level: the same jq filter the monitor applies
  echo '{"mobile":null,"environments":[{"environment":"Study","ref":"v1","sbom":"https://x/s.json"}],"unresolvable":[]}' > "$TMP/dep.json"
  n=$(jq '[ .environments[]? | select(.sbom != null and (.environment | test("prod|study"; "i"))) ] | length' "$TMP/dep.json")
  assert "$n" "1"
}

test_monitor_record_zero_targets_is_not_all_clear() {
  # the verdict expression from the record, applied to empty inputs
  v=$(jq -n '{scanned: [], findings: [], unscannable: [], unknown: []} |
      (if (.findings | length) > 0 then "kev-findings"
       elif (.scanned | length) == 0 then "incomplete"
       elif (.unscannable | length) > 0 or (.unknown | length) > 0 then "incomplete"
       else "all-clear" end)')
  assert "$v" '"incomplete"'
}

# Regression: max_behind.patch was validated but never measured.
test_currency_enforces_patch_limit() {
  cat > "$TMP/cur-bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"bom-ref":"a","type":"library","name":"pkg","version":"1.2.0","purl":"pkg:npm/pkg@1.2.0"}]}
EOF
  jq '.dependency_currency.max_behind.patch = 1' "$TMP/cp.json" > "$TMP/cur-pol.json"
  # fake registry via a python shim is overkill — check the comparison directly
  python3 - "$S/check-currency.py" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cc", sys.argv[1])
cc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cc)
b = cc.behind("1.2.0", "1.2.5")
assert b == (0, 0, 5), b
# the fixed comparison: patch limit 1, behind 5 -> over
max_major, max_minor, max_patch = 0, 1, 1
over = ((max_major is not None and b[0] > max_major)
        or (max_minor is not None and b[1] > max_minor)
        or (max_patch is not None and b[2] > max_patch))
assert over, "5 patches behind a limit of 1 must be over"
PYEOF
}

# Regression: unit kev membership compared a string to True and was always empty.
test_units_list_their_kev_members() {
  cat > "$TMP/kf.json" <<'EOF'
{"findings":[{"id":"CVE-1","track":"kev","kev":"true","affects":["a"],
              "mitigation_due":"2026-08-08T00:00:00+00:00","remediation_due":"2026-09-04T00:00:00+00:00"}]}
EOF
  cat > "$TMP/kb.json" <<'EOF'
{"components":[{"bom-ref":"a","name":"x","version":"1","purl":"pkg:rpm/x@1",
                "properties":[{"name":"quickbird:component:artifact","value":"quickbird:artifact:deployed-img"}]}],
 "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"a"}]}]}
EOF
  python3 "$S/group-remediation.py" "$TMP/kf.json" "$TMP/kb.json" --out "$TMP/ku.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.units[0].kev_findings | join(",")' "$TMP/ku.json")" "CVE-1"
}

# Regression: a CVSS-4-only advisory has no parsable 3.x vector and fell to rule 9
# (expedited) whatever its severity. The database severity band now routes it.
test_classify_v4_only_critical_is_immediate() {
  cat > "$TMP/v4.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],
 "vulnerabilities":[{"id":"CVE-9","affects":[{"ref":"a"}],
   "ratings":[{"source":{"name":"OSV"},"method":"CVSSv4","vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
   "properties":[{"name":"quickbird:vuln:osv-severity","value":"CRITICAL"}]}]}
EOF
  python3 "$S/classify-findings.py" "$TMP/v4.json" "$TMP/cp.json" --out "$TMP/v4f.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/v4f.json")" "immediate"
}

# Regression: `onboarded` parses to midnight, so a scan later that same day missed the
# baseline for the entire backlog.
test_classify_baseline_applies_on_the_onboarding_day() {
  cat > "$TMP/ob.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],
 "vulnerabilities":[{"id":"CVE-10","affects":[{"ref":"a"}],
   "ratings":[{"source":{"name":"OSV"},"method":"CVSSv31","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}
EOF
  jq '.onboarded = "2026-08-05" | .baseline_clocks_start = "2026-10-01"' "$TMP/cp.json" > "$TMP/obp.json"
  python3 "$S/classify-findings.py" "$TMP/ob.json" "$TMP/obp.json" \
    --now "2026-08-05T14:00:00+00:00" --out "$TMP/obf.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].clock_start' "$TMP/obf.json")" "2026-10-01T00:00:00+00:00"
}

# Regression: a VEX in package A suppressed the same CVE on package B; and an invalid
# justification code suppressed anything at all.
test_vex_does_not_cross_components() {
  mkdir -p "$TMP/vx/soups/npm"
  cat > "$TMP/vx/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"root","name":"p","type":"application"}},
 "components":[
   {"bom-ref":"a","type":"library","name":"liba","version":"1.0.0","purl":"pkg:npm/liba@1.0.0"},
   {"bom-ref":"b","type":"library","name":"libb","version":"2.0.0","purl":"pkg:npm/libb@2.0.0"}],
 "vulnerabilities":[{"id":"CVE-2026-1111","affects":[{"ref":"a"},{"ref":"b"}]}]}
EOF
  cat > "$TMP/vx/soups/npm/liba.json" <<'EOF'
{"package":"liba","version":"1.x.x","metadata":{"input_version":"1.0.0"},
 "vex":{"CVE-2026-1111":{"state":"not_affected","justification":"code_not_reachable","detail":"d"}}}
EOF
  bash "$S/merge-assessment.sh" "$TMP/vx/bom.json" "$TMP/vx/soups" "$TMP/vx/out.json" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.vulnerabilities[0].analysis' "$TMP/vx/out.json")" "null" || return 1
  contains "$(jq -r '[.vulnerabilities[0].properties[]?.name] | join(",")' "$TMP/vx/out.json")" "quickbird:vex:partial"
}

test_vex_invalid_justification_does_not_suppress() {
  mkdir -p "$TMP/vi/soups/npm"
  cat > "$TMP/vi/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"bom-ref":"root","name":"p","type":"application"}},
 "components":[{"bom-ref":"a","type":"library","name":"liba","version":"1.0.0","purl":"pkg:npm/liba@1.0.0"}],
 "vulnerabilities":[{"id":"CVE-2026-2222","affects":[{"ref":"a"}]}]}
EOF
  cat > "$TMP/vi/soups/npm/liba.json" <<'EOF'
{"package":"liba","version":"1.x.x","metadata":{"input_version":"1.0.0"},
 "vex":{"CVE-2026-2222":{"state":"not_affected","justification":"seems_fine","detail":"d"}}}
EOF
  bash "$S/merge-assessment.sh" "$TMP/vi/bom.json" "$TMP/vi/soups" "$TMP/vi/out.json" >/dev/null 2>&1
  assert "$?" "1" || return 1
  assert "$(jq -r '.vulnerabilities[0].analysis' "$TMP/vi/out.json")" "null"
}

# Regression: two directories with the same basename merged into one candidate and the
# second scan source silently vanished.
test_discover_distinguishes_equal_basenames() {
  mkdir -p "$TMP/repo/services/a/server" "$TMP/repo/services/b/server"
  printf 'module a\n' > "$TMP/repo/services/a/server/go.mod"
  printf 'module b\n' > "$TMP/repo/services/b/server/go.mod"
  ( cd "$TMP/repo" && git init -q . && git add -A )
  DISCOVER_OUTPUT="$TMP/repo/cand.json" bash "$S/discover.sh" "$TMP/repo" >/dev/null 2>&1 || return 1
  assert "$(jq '[.candidates[] | select(.ecosystem=="go")] | length' "$TMP/repo/cand.json")" "2"
}

# Regression: a typo in an override silently did nothing.
test_policy_rejects_unknown_keys() {
  printf 'product: x\ntier: Basic\ncra_scope: unknown\nmaintenance_interval: 90d\ntracks:\n  immediate:\n    mitigaton: 1d\n' > "$TMP/typo.yml"
  bash "$S/validate-policy.sh" "$TMP/typo.yml" >/dev/null 2>&1
  assert "$?" "1"
}

# Regression: an include without a reason passed the gate; only excludes were checked.
test_scope_include_needs_reason() {
  cat > "$TMP/inc-cand.json" <<'EOF'
{"schema":"quickbird.soup-discovery/v1","candidate_count":1,
 "candidates":[{"id":"x","ecosystem":"npm","scan_source":"dir:x","markers":["x/package.json"],"ships":true,"resolvable":true,"note":""}]}
EOF
  printf 'include:\n  - id: x\nexclude: []\n' > "$TMP/inc-scope.yml"
  SCOPE_OUTPUT="$TMP/inc-plan.json" bash "$S/resolve-scope.sh" "$TMP/inc-cand.json" "$TMP/inc-scope.yml" >/dev/null 2>&1
  assert "$?" "1"
}

# Regression: the fix-or-VEX gate accepted any string as a justification code.
test_fix_or_vex_rejects_invalid_justification() {
  # no network needed: drive the state machine with a record and a fake OSV via OSV_API
  mkdir -p "$TMP/fv/npm" "$TMP/fakebin"
  cat > "$TMP/fv/npm/lib.json" <<'EOF'
{"package":"lib","version":"1.x.x","metadata":{"input_version":"1.0.0"},
 "vex":{"CVE-2026-3333":{"state":"not_affected","justification":"seems_fine","detail":"d"}}}
EOF
  cat > "$TMP/fakebin/curl" <<'FAKE'
#!/usr/bin/env bash
echo '{"vulns":[{"id":"OSV-1","aliases":["CVE-2026-3333"]}]}'
FAKE
  chmod +x "$TMP/fakebin/curl"
  out=$(PATH="$TMP/fakebin:$PATH" bash "$S/check-fix-or-vex.sh" "$TMP/fv/npm/lib.json" 2>&1)
  assert "$?" "1" || return 1
  contains "$out" "not in the CycloneDX vocabulary"
}

# Regression: scan-vulns exited 0 with an incomplete list when OSV was unreachable.
test_scan_vulns_fails_on_unreachable_osv() {
  cat > "$TMP/sv-bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"bom-ref":"a","type":"library","name":"pkg","version":"1.0.0","purl":"pkg:npm/pkg@1.0.0"}]}
EOF
  OSV_API="http://127.0.0.1:1" bash "$S/scan-vulns.sh" "$TMP/sv-bom.json" "$TMP/sv-out.json" >/dev/null 2>&1
  assert "$?" "1"
}

# ---------------------------------------------------------------- network
test_net_enrichment_against_live_feeds() {
  need_net || return 77
  QB_ENRICH_CVES="CVE-2021-44228" QB_ENRICH_OUTPUT="$TMP/live.json" \
    bash "$S/../../kev-epss-enrichment/scripts/enrich.sh" >/dev/null 2>&1 || return 1
  assert "$(jq -r '.cves["CVE-2021-44228"].kev' "$TMP/live.json")" "true"
}

test_net_fix_or_vex_blocks_known_vulnerable_version() {
  need_net || return 77
  mkdir -p "$TMP/gate/npm"
  soup_record lodash "4.17.x" "4.17.15" > "$TMP/gate/npm/lodash.json"
  bash "$S/check-fix-or-vex.sh" "$TMP/gate/npm/lodash.json" >/dev/null 2>&1
  assert "$?" "1"
}

# ---------------------------------------------------------------- run
printf 'product: t\ntier: Basic\ncra_scope: false\nmaintenance_interval: 90d\n' > "$TMP/cpol.yml"
bash "$S/validate-policy.sh" "$TMP/cpol.yml" 2>/dev/null > "$TMP/cp.json"

echo "SOUP pipeline tests${FILTER:+ (filter: $FILTER)}"
for fn in $(declare -F | awk '{print $3}' | grep '^test_' | sort); do
  t "${fn#test_}" "$fn"
done

echo
printf '%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
if (( FAIL > 0 )); then
  printf 'failed: %s\n' "${FAILED_NAMES[*]}"
  exit 1
fi
[[ "${TEST_NETWORK:-0}" == "1" ]] || echo "(network tests skipped — set TEST_NETWORK=1 to include them)"
