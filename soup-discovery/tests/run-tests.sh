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
