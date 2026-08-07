#!/usr/bin/env python3
"""Mark each component of a per-target BOM as a direct or transitive dependency.

Until now "direct" meant "carries a SOUP record", which is a proxy with a blind spot in
both directions: a direct dependency WITHOUT a record was indistinguishable from a
transitive, so the coverage figure (direct libraries with an approved SOUP) could never
fail — and a record for something no longer chosen inflated it. The truth about
directness has been sitting in the manifests all along; this reads it and stamps

    quickbird:dependency:scope = direct | transitive

onto every component it can decide. Components it cannot decide carry no property —
undetermined must stay distinguishable from decided.

Per ecosystem:
  pub             pubspec.lock marks every entry: dependency: "direct main" | "direct
                  dev" | "transitive"
  npm             direct = keys of dependencies/devDependencies across every package.json
                  that resolves against the scanned lockfile (the discovery markers)
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
    direct, transitive = set(), set()
    for m in markers:
        lock = Path(repo) / Path(m).parent / "pubspec.lock"
        if not lock.is_file():
            continue
        doc = load_yaml(lock)
        for name, entry in (doc.get("packages") or {}).items():
            dep = str((entry or {}).get("dependency", ""))
            (direct if dep.startswith("direct") else transitive).add(name)
    return direct, transitive


def direct_set_npm(markers, repo):
    """Union of dependencies/devDependencies over every package.json marker. In a
    workspace the members' choices are direct choices of the product, so all markers
    count — that is exactly why discovery folds members into the root candidate."""
    direct = set()
    for m in markers:
        pj = Path(repo) / m
        if pj.name != "package.json" or not pj.is_file():
            continue
        try:
            doc = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for key in ("dependencies", "devDependencies"):
            direct.update((doc.get(key) or {}).keys())
    return direct, None


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
            if a:
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--markers", default="")
    args = ap.parse_args()

    markers = [m for m in args.markers.split(",") if m]
    eco = args.ecosystem

    direct, transitive = None, None
    all_transitive = False
    all_direct = False
    if eco == "pub":
        direct, transitive = direct_set_pub(markers, args.repo)
    elif eco == "npm":
        direct, _ = direct_set_npm(markers, args.repo)
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

    n_dir = n_tra = 0
    for c in bom.get("components", []) or []:
        name = c.get("name") or ""
        if all_direct:
            scope = "direct"
        elif all_transitive:
            scope = "transitive"
        elif direct is not None and name in direct:
            scope = "direct"
        elif transitive is not None and name not in transitive and name not in direct:
            # pub knows both sides; a name in neither list is undetermined
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
        else:
            n_tra += 1

    with open(args.bom, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")
    print(f"scope: {n_dir} direct, {n_tra} transitive ({eco})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
