#!/usr/bin/env python3
"""Mark each component of a per-target BOM as a direct or transitive dependency.

Until now "direct" meant "carries a SOUP record", which is a proxy with a blind spot in
both directions: a direct dependency WITHOUT a record was indistinguishable from a
transitive, so the coverage figure (direct libraries with an approved SOUP) could never
fail — and a record for something no longer chosen inflated it. The truth about
directness has been sitting in the manifests all along; this reads it and stamps

    quickbird:dependency:scope = direct | dev | transitive

onto every component it can decide. Components it cannot decide carry no property —
undetermined must stay distinguishable from decided. `dev` is build- and test-tooling:
deliberately chosen, present in the lockfile and therefore in the inventory, but not
shipped in the product — under WI-006-03 it needs no SOUP record, and the first real run
proved why the distinction matters: without it, 100 babel/eslint/test packages read as
"chosen, shipped, never approved".

Per ecosystem:
  pub             pubspec.lock marks every entry: dependency: "direct main" | "direct
                  dev" | "transitive"
  cocoapods       direct = DEPENDENCIES in Podfile.lock that are not sourced from a local
                  path, which excludes the Flutter plugin pods and the engine
  swift           not classified: Package.resolved is a flat list of pins with no direct or
                  transitive distinction, and the direct set lives in the Xcode project
  npm             dependencies -> direct, devDependencies -> dev, but only for the copy
                  whose version satisfies the declared range, across every
                  package.json that resolves against the scanned lockfile
  jvm-maven       direct = <dependencies> declared in the module pom.xml
  android-gradle  direct = coordinates named by implementation/api/... lines in the
                  module build.gradle files (the lockfile itself mixes both)
  go              direct = require entries in go.mod not marked "// indirect"
  python          a requirements.txt / pyproject dependency list is direct by definition
  container       everything inside an image is transitive; the image itself is the
                  direct choice and is stamped at consolidation

Usage: mark-scope.py <bom.cdx.json> --ecosystem E --repo ROOT [--markers m1,m2,...]
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def load_yaml(path):
    """YAML via yq, like every other consumer here — a missing Python YAML module must
    not silently turn every component undetermined."""
    r = subprocess.run(["yq", "-o=json", ".", str(path)],
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout or "{}") or {}


def direct_set_pub(markers, repo):
    """pubspec.lock: name -> 'direct main' | 'direct dev' | 'transitive'."""
    direct, dev, transitive = set(), set(), set()
    for m in markers:
        lock = Path(repo) / Path(m).parent / "pubspec.lock"
        if not lock.is_file():
            continue
        doc = load_yaml(lock)
        for name, entry in (doc.get("packages") or {}).items():
            dep = str((entry or {}).get("dependency", ""))
            if dep == "direct dev":
                dev.add(name)
            elif dep.startswith("direct"):
                direct.add(name)
            else:
                transitive.add(name)
    return direct, dev, transitive


def _semver(v):
    """(major, minor, patch) or None. Pre-release and build metadata are dropped: they do
    not change which range a version falls in for the purpose here."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", str(v).strip())
    return tuple(int(g) for g in m.groups()) if m else None


def satisfies(version, spec):
    """Does `version` fall inside the npm range `spec`?

    Returns True when it does, False when it provably does not, and None when the spec is
    one this cannot decide. None matters: a name declared with a range nobody here can parse
    must keep the benefit of the doubt, or the fix would demote real direct dependencies.
    Only ^, ~, an exact version and the match-anything forms are decided; unions, hyphen
    ranges, comparators, aliases, git and file specs and dist-tags are left undecided.
    """
    v = _semver(version)
    spec = (spec or "").strip()
    if spec in ("", "*", "x", "X", "latest") or spec.startswith(("workspace:", "npm:")):
        return True
    if v is None or any(ch in spec for ch in "|| ,>=<") or spec.count(" ") or "-" in spec[1:]:
        return None
    if spec.startswith("^"):
        b = _semver(spec[1:])
        if b is None:
            return None
        if b[0] > 0:
            return v >= b and v[0] == b[0]
        if b[1] > 0:                      # ^0.y.z -> >=0.y.z <0.(y+1).0
            return v >= b and v[:2] == b[:2]
        return v == b                     # ^0.0.z is exact
    if spec.startswith("~"):
        b = _semver(spec[1:])
        return None if b is None else (v >= b and v[:2] == b[:2])
    b = _semver(spec)
    return None if b is None else v == b


def direct_set_npm(markers, repo):
    """dependencies -> direct, devDependencies -> dev, over every package.json marker.
    In a workspace the members' choices are direct choices of the product, so all
    markers count — that is exactly why discovery folds members into the root candidate.
    A name in both sets ships: direct wins.

    The declared range is carried, not just the name. npm installs one copy per
    incompatible range, so a name we depend on can appear several times in the lock file at
    versions nobody here chose: web/package.json asks for uuid ^13.0.0, @types/uuid drags in
    uuid * and sockjs uuid ^8.3.2, and matching on the name alone called all three direct.
    That inflated "chosen, shipped, never approved" with components nobody chose, and ran the
    currency check over them.
    """
    direct, dev = {}, {}
    for m in markers:
        pj = Path(repo) / m
        if pj.name != "package.json" or not pj.is_file():
            continue
        try:
            doc = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for field, target in (("dependencies", direct), ("devDependencies", dev)):
            for name, spec in (doc.get(field) or {}).items():
                target.setdefault(name, []).append(spec)
    return direct, {k: v for k, v in dev.items() if k not in direct}


def direct_set_cocoapods(markers, repo):
    """DEPENDENCIES in Podfile.lock, minus everything sourced from a local path.

    A pod written `- name (from `...`)` is not an iOS choice. On a Flutter app almost all of
    them are the iOS half of a Dart package that pubspec.lock already records as direct, and the
    engine pod comes in the same shape. Counting them again here would demand a second SOUP
    record for one choice and run the currency check on it twice, once under pkg:pub and once
    under pkg:cocoapods. Measured on two products, 33 of 34 and 23 of 24 entries are of that
    kind, so this is the rule rather than an edge case, and both leave zero direct pods.

    A real iOS choice carries a version constraint instead: `- IOSSecuritySuite (~> 1.9)`.
    """
    direct = set()
    for m in markers:
        pl = Path(repo) / m
        if pl.name != "Podfile.lock" or not pl.is_file():
            continue
        in_deps = False
        try:
            lines = pl.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if re.match(r"^[A-Z][A-Z ]*:\s*$", line):
                in_deps = line.startswith("DEPENDENCIES:")
                continue
            if not in_deps:
                continue
            entry = re.match(r"^\s+-\s+(\S+)(.*)$", line)
            if entry and "(from " not in entry.group(2):
                direct.add(entry.group(1))
    return direct, set()


def direct_set_maven(markers, repo):
    """artifactIds declared in the module pom(s). Parent-managed versions are still
    declared in the module, which is what makes this readable without resolving."""
    direct = set()
    for m in markers:
        pom = Path(repo) / m
        if pom.name != "pom.xml":
            pom = Path(repo) / Path(m).parent / "pom.xml"
        if not pom.is_file():
            continue
        text = pom.read_text(encoding="utf-8", errors="replace")
        body = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", text, flags=re.S)
        for dep in re.findall(r"<dependency>(.*?)</dependency>", body, flags=re.S):
            a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", dep)
            if not a:
                continue
            scope = re.search(r"<scope>\s*([^<]+?)\s*</scope>", dep)
            if scope and scope.group(1) in ("test", "provided"):
                continue    # does not ship; the provided runtime carries its own record
            direct.add(a.group(1))
    return direct, None


def direct_set_gradle(markers, repo):
    """Coordinates named in the module build.gradle(.kts). The gradle.lockfile lists the
    resolved closure without distinguishing, so the declaration is the direct signal."""
    direct = set()
    rx = re.compile(r"""(?:implementation|api|runtimeOnly|compileOnly|coreLibraryDesugaring|annotationProcessor|kapt)\s*[\( ]\s*['"]([\w.\-]+):([\w.\-]+):""")
    for m in markers:
        bg = Path(repo) / m
        if not bg.is_file():
            continue
        for _g, artifact in rx.findall(bg.read_text(encoding="utf-8", errors="replace")):
            direct.add(artifact)
    return direct, None


def direct_set_go(markers, repo):
    """go.mod: require entries without the '// indirect' marker."""
    direct = set()
    for m in markers:
        gm = Path(repo) / m
        if gm.name != "go.mod" or not gm.is_file():
            continue
        in_block = False
        for line in gm.read_text(encoding="utf-8", errors="replace").splitlines():
            t = line.strip()
            if t.startswith("require ("):
                in_block = True
                continue
            if in_block and t == ")":
                in_block = False
                continue
            mm = re.match(r"(?:require\s+)?([\w./\-]+)\s+v[\w.\-+]+(.*)$", t)
            if mm and (in_block or t.startswith("require ")):
                if "// indirect" not in mm.group(2):
                    direct.add(mm.group(1))
    return direct, None


def in_declared(name, version, declared):
    """`declared` is either a set of names (every ecosystem but npm) or a name -> ranges
    mapping. With ranges, a component counts as declared unless every range it was declared
    under provably excludes its version."""
    if name not in declared:
        return False
    if not isinstance(declared, dict):
        return True
    verdicts = [satisfies(version, spec) for spec in declared[name]]
    return any(x is not False for x in verdicts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--markers", default="")
    args = ap.parse_args()

    markers = [m for m in args.markers.split(",") if m]
    eco = args.ecosystem

    direct, dev, transitive = None, None, None
    all_transitive = False
    all_direct = False
    if eco == "pub":
        direct, dev, transitive = direct_set_pub(markers, args.repo)
    elif eco == "npm":
        direct, dev = direct_set_npm(markers, args.repo)
    elif eco == "cocoapods":
        direct, _ = direct_set_cocoapods(markers, args.repo)
    elif eco == "jvm-maven":
        direct, _ = direct_set_maven(markers, args.repo)
    elif eco in ("android-gradle", "jvm-gradle"):
        direct, _ = direct_set_gradle(markers, args.repo)
    elif eco == "go":
        direct, _ = direct_set_go(markers, args.repo)
    elif eco == "python":
        # a requirements/pyproject dependency list is a set of choices, not a resolution
        all_direct = True
    elif eco == "container":
        # nothing inside an image is an individual choice; the image is, and the
        # consolidated artefact component carries that
        all_transitive = True
    else:
        # terraform and anything unknown: leave undetermined rather than guess
        print(f"scope: ecosystem {eco} not classified — components left undetermined",
              file=sys.stderr)
        return 0

    with open(args.bom, encoding="utf-8") as fh:
        bom = json.load(fh)

    n_dir = n_dev = n_tra = 0
    for c in bom.get("components", []) or []:
        name = c.get("name") or ""
        if all_direct:
            scope = "direct"
        elif all_transitive:
            scope = "transitive"
        elif direct is not None and in_declared(name, c.get("version"), direct):
            scope = "direct"
        elif dev is not None and in_declared(name, c.get("version"), dev):
            scope = "dev"
        elif transitive is not None and name not in transitive:
            # pub knows all three sides; a name in none of them is undetermined
            continue
        elif direct is not None:
            scope = "transitive"
        else:
            continue
        c["properties"] = sorted(
            (c.get("properties") or [])
            + [{"name": "quickbird:dependency:scope", "value": scope}],
            key=lambda x: (x["name"], x.get("value") or ""))
        if scope == "direct":
            n_dir += 1
        elif scope == "dev":
            n_dev += 1
        else:
            n_tra += 1

    with open(args.bom, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")
    print(f"scope: {n_dir} direct, {n_dev} dev, {n_tra} transitive ({eco})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
