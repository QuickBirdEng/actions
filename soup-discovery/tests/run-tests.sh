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
  assert "$(jq -r '[.metadata.properties[]|select(.name=="quickbird:soup:records-orphaned")][0].value' "$TMP/ao2.json")" "1"
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
pol() { printf 'product: p\ntier: Basic\ncra_scope: %s\nrelease_cadence: monthly\n%s' "$1" "${2:-}" > "$TMP/pol.yml"; }

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
  assert "$(jq -r '.planned_remediation_ceiling' <<<"$out")" "90d"
}

# ---------------------------------------------------------------- classifier
CLS() { python3 "$S/classify-findings.py" "$@"; }

mkpolicy() { printf 'product: p\ntier: Basic\ncra_scope: false\nrelease_cadence: monthly\nalerts:\n  threshold: %s\n' "${1:-high}" > "$TMP/cp.yml"
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

test_classify_kev_is_immediate_regardless_of_cvss() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" true null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "immediate" || return 1
  assert "$(jq -r '.findings[0].rule' "$TMP/co.json")" "1"
}

# "unknown" must not behave like "not in KEV": a catalog we could not read is not evidence.
test_classify_kev_unknown_is_treated_as_kev() {
  mkpolicy; mkvuln CVE-1 "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" unknown null
  CLS "$TMP/cv.json" "$TMP/cp.json" --out "$TMP/co.json" --now 2026-01-01T00:00:00+00:00 >/dev/null 2>&1 || return 1
  assert "$(jq -r '.findings[0].track' "$TMP/co.json")" "immediate"
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
  assert "$(jq -r '.findings[0].mitigation_due[0:10]' "$TMP/co.json")" "2026-01-04" || return 1   # 72h
  assert "$(jq -r '.findings[0].remediation_due[0:10]' "$TMP/co.json")" "2026-01-22"              # 21d
}

# §2.2 — EPSS decays daily. Without latching a Track 1 finding becomes Track 2 a week later,
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
  assert "$(jq -r '.findings[0].track' "$TMP/e2.json")" "immediate" || return 1
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

# §3.3 gives five *working* days. Counting calendar days would escalate across a weekend
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
    synthetic:false,release_cadence:$c}' > "$TMP/ev/${2}-$1.json"; }

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

test_backstop_rejects_an_unmeasurable_cadence_word() {
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun_cadence p1 2026-08-02 QuickBirdEng/mindnet "whenever-we-feel-like-it"
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  assert "$(jq -r '.cadence[0].status' "$TMP/bs.json")" "unknown"
}

# The distinction that flips the answer: alvie published six releases in 90 days and reads
# as a product on a monthly cadence, but its last *production* release was over a year ago.
# A Track 3/4 deadline is a remediation deadline, and remediation is satisfied on deploy.
test_net_backstop_cadence_counts_production_releases_only() {
  need_net || return 77
  rm -rf "$TMP/ev"; mkdir -p "$TMP/ev"
  mkrun_cadence alvie 2026-08-02 QuickBirdEng/alvie monthly
  python3 "$S/backstop-report.py" "$TMP/ev" --out "$TMP/bs.json" --now 2026-08-02T18:00:00+00:00 >/dev/null 2>&1
  # The basis must name which signal was used, because on this repo the three disagree.
  jq -re '.cadence[0].counted | test("production releases \\(by tag_pattern\\)")' "$TMP/bs.json" >/dev/null || return 1
  assert "$(jq -r '.cadence[0].status' "$TMP/bs.json")" "broken" || return 1
  # alvie is the live case where the signals disagree — the report must say so rather than
  # presenting one of the three answers as the measurement.
  jq -re '.cadence[0].signal_disagreement.latest_by_signal | length == 3' "$TMP/bs.json" >/dev/null
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
printf 'product: t\ntier: Basic\ncra_scope: false\nrelease_cadence: monthly\n' > "$TMP/cpol.yml"
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
