#!/usr/bin/env python3
"""Write the dependency graph of an npm target into its BOM.

The lockfiles this pipeline scans are flat resolutions: syft reads them as a list and
emits no edges, so a transitive component cannot answer the one question a reader of the
report asks about it — which direct dependency pulls it in. The graph has been in the
lockfile all along: yarn.lock names every package's dependencies, package-lock.json
nests them. This reads it and writes standard CycloneDX

    dependencies: [ { ref, dependsOn: [ref, ...] } ]

entries onto the per-target BOM, keyed by the components' own bom-refs; consolidation
merges them across targets unchanged. Components whose ecosystem carries no graph in
the lockfile (pub, gradle, go) keep no edges — undetermined must stay distinguishable
from decided, exactly as with the dependency scope.

Operating-system packages inside images already arrive with edges: their package
metadata declares dependencies and syft emits them. This fills the gap for repo-scanned
npm targets.

Usage: mark-graph.py <bom.cdx.json> --ecosystem E --repo ROOT [--markers m1,m2,...]
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def strip_proto(rng):
    """berry ranges carry a protocol ("npm:^1.2.3"); the v1 resolve map does not."""
    return rng.split(":", 1)[1] if rng.startswith(("npm:", "patch:")) else rng


def split_key(key):
    """'"@scope/pkg@^1.0.0"' -> ("@scope/pkg", "^1.0.0")."""
    k = key.strip().strip('"')
    name, _, rng = k.rpartition("@")
    return name, rng


def parse_yarn_v1(text):
    """(name, version) -> [(dep-name, dep-version), ...] via the entry-local resolve map."""
    resolve = {}
    wants = {}
    cur_keys, cur_version, cur_deps, in_deps = [], None, [], False

    def flush():
        if not cur_keys or not cur_version:
            return
        for name, rng in cur_keys:
            resolve[(name, rng)] = cur_version
            resolve[(name, strip_proto(rng))] = cur_version
        wants.setdefault((cur_keys[0][0], cur_version), []).extend(cur_deps)

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            flush()
            cur_keys = [split_key(k) for k in line[:-1].split(", ")]
            cur_version, cur_deps, in_deps = None, [], False
        elif indent == 2:
            if line.startswith("version"):
                cur_version = line.split(None, 1)[1].strip('"')
                in_deps = False
            elif line.rstrip(":") in ("dependencies", "optionalDependencies"):
                in_deps = True
            else:
                in_deps = False
        elif indent >= 4 and in_deps:
            m = re.match(r'"?([^"\s]+)"?\s+"?(.+?)"?$', line)
            if m:
                cur_deps.append((m.group(1), m.group(2)))
    flush()

    edges = {}
    for (name, version), deps in wants.items():
        out = []
        for dn, rng in deps:
            dv = resolve.get((dn, rng)) or resolve.get((dn, strip_proto(rng)))
            if dv:
                out.append((dn, dv))
        if out:
            edges.setdefault((name, version), []).extend(out)
    return edges


def parse_yarn_berry(path):
    """yarn 2+ lockfiles are YAML; parsed via yq like every other YAML consumer here."""
    r = subprocess.run(["yq", "-o=json", ".", str(path)],
                       capture_output=True, text=True, check=True)
    doc = json.loads(r.stdout or "{}") or {}
    resolve = {}
    wants = {}
    for key, entry in doc.items():
        if key == "__metadata" or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if not version:
            continue
        keys = [split_key(k) for k in key.split(", ")]
        for name, rng in keys:
            resolve[(name, rng)] = version
            resolve[(name, strip_proto(rng))] = version
        deps = list((entry.get("dependencies") or {}).items())
        wants.setdefault((keys[0][0], version), []).extend(deps)
    edges = {}
    for (name, version), deps in wants.items():
        out = []
        for dn, rng in deps:
            dv = resolve.get((dn, str(rng))) or resolve.get((dn, strip_proto(str(rng))))
            if dv:
                out.append((dn, dv))
        if out:
            edges.setdefault((name, version), []).extend(out)
    return edges


def parse_package_lock(doc):
    """lockfileVersion 2/3: nested node_modules paths resolve nearest-first, exactly as
    node does. v1 has no `packages` map and is left undetermined."""
    pkgs = doc.get("packages")
    if not isinstance(pkgs, dict):
        return {}
    edges = {}
    for path, info in pkgs.items():
        if not path or "node_modules/" not in path or not isinstance(info, dict):
            continue
        name = path.split("node_modules/")[-1]
        version = info.get("version")
        if not version:
            continue
        deps = {}
        for field in ("dependencies", "optionalDependencies"):
            deps.update(info.get(field) or {})
        out = []
        for dn in deps:
            base = path
            while True:
                cand = (f"{base}/node_modules/{dn}" if base else f"node_modules/{dn}")
                dv = (pkgs.get(cand) or {}).get("version")
                if dv:
                    out.append((dn, dv))
                    break
                if not base:
                    break
                idx = base.rfind("/node_modules/")
                base = base[:idx] if idx != -1 else ""
        if out:
            edges.setdefault((name, version), []).extend(out)
    return edges


def find_lockfiles(markers, repo):
    """The lockfile that resolved a package.json sits in its directory or above it —
    workspaces share one at the root."""
    repo = Path(repo).resolve()
    found = []
    for m in markers:
        d = (repo / m).resolve().parent
        while d == repo or repo in d.parents:
            for lf in ("yarn.lock", "package-lock.json"):
                p = d / lf
                if p.is_file() and p not in found:
                    found.append(p)
            if d == repo:
                break
            d = d.parent
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--markers", default="")
    args = ap.parse_args()

    if args.ecosystem != "npm":
        print(f"graph: ecosystem {args.ecosystem} carries no lockfile graph — "
              f"edges left undetermined", file=sys.stderr)
        return 0

    markers = [m for m in args.markers.split(",") if m]
    edges = {}
    for lock in find_lockfiles(markers, args.repo):
        if lock.name == "yarn.lock":
            text = lock.read_text(encoding="utf-8", errors="replace")
            got = (parse_yarn_berry(lock) if "__metadata:" in text
                   else parse_yarn_v1(text))
        else:
            try:
                got = parse_package_lock(json.loads(lock.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                got = {}
        for k, v in got.items():
            edges.setdefault(k, []).extend(v)

    with open(args.bom, encoding="utf-8") as fh:
        bom = json.load(fh)

    refs_by_nv = {}
    for c in bom.get("components", []) or []:
        purl = c.get("purl") or ""
        if purl.startswith("pkg:npm/"):
            refs_by_nv.setdefault((c.get("name"), c.get("version")), []).append(c.get("bom-ref"))

    existing = {d.get("ref"): set(d.get("dependsOn") or [])
                for d in bom.get("dependencies", []) or []}
    n_new = 0
    for (name, version), deps in edges.items():
        srcs = refs_by_nv.get((name, version)) or []
        tgts = sorted({r for dn, dv in deps for r in (refs_by_nv.get((dn, dv)) or [])})
        if not tgts:
            continue
        for s in srcs:
            cur = existing.setdefault(s, set())
            before = len(cur)
            cur.update(tgts)
            n_new += len(cur) - before
    bom["dependencies"] = [{"ref": r, "dependsOn": sorted(v)}
                           for r, v in sorted(existing.items())]

    with open(args.bom, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")
    print(f"graph: {len(existing)} nodes, {n_new} new edges (npm)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
