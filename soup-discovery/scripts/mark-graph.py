#!/usr/bin/env python3
"""Write the dependency graph of a target into its BOM.

The lockfiles this pipeline scans are flat resolutions: syft reads them as a list and
emits no edges, so a transitive component cannot answer the one question a reader of the
report asks about it — which direct dependency pulls it in. This derives the edges per
ecosystem and writes standard CycloneDX

    dependencies: [ { ref, dependsOn: [ref, ...] } ]

entries onto the per-target BOM, keyed by the components' own bom-refs; consolidation
merges them across targets unchanged.

Per ecosystem:
  npm             yarn.lock (v1 and berry) and package-lock.json (v2/v3, nearest-first
                  resolution exactly as node does) name every package's dependencies —
                  pure file parsing.
  pub             pubspec.lock carries no edges; the registry that resolved it does. One
                  API call per hosted package returns its pubspec, and the dependency
                  names resolve against the locked versions.
  android-gradle  gradle.lockfile is flat; the POM of each locked artifact names its
  jvm-gradle      dependencies (google maven, maven central, flutter storage). Only the
                  names are taken from the POM — every version resolves against the
                  lockfile, which is the actual resolution. Exclusions gradle applied are
                  not visible in the POM, so an edge can name a parent that gradle
                  detached; the via-path is informative, not normative.

Ecosystems whose graph is not derivable (go, python, container contents) keep no edges —
undetermined must stay distinguishable from decided, exactly as with the dependency
scope. Operating-system packages inside images already arrive with edges from syft.

Registry fetches degrade per package: an unavailable pubspec or POM costs that package's
edges, not the run. Total registry unreachability aborts the fetch after a threshold so
a blocked network cannot stall the pipeline.

Usage: mark-graph.py <bom.cdx.json> --ecosystem E --repo ROOT [--markers m1,m2,...]
"""

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

FETCH_WORKERS = 8
# with zero successes, this many failures means the registry is unreachable, not flaky
GIVE_UP_AFTER = 25


# --- npm --------------------------------------------------------------------


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


def npm_edges(markers, repo):
    edges = {}
    for lock in find_lockfiles(markers, repo, ("yarn.lock", "package-lock.json")):
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
    return edges


# --- registry fetching --------------------------------------------------------


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "soup-discovery"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_all(items, fetch_one):
    """items: [(key, args)] -> {key: result}, result None on a per-item failure. Aborts
    once GIVE_UP_AFTER items failed without a single success."""
    results = {}
    failures = 0
    successes = 0

    def run(item):
        key, args = item
        try:
            return key, fetch_one(*args)
        except Exception:
            return key, None

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = [pool.submit(run, item) for item in items]
        for fut in as_completed(futures):
            key, res = fut.result()
            results[key] = res
            if res is None:
                failures += 1
            else:
                successes += 1
            if successes == 0 and failures >= GIVE_UP_AFTER:
                print(f"graph: registry unreachable after {failures} attempts — "
                      f"giving up on the remaining fetches", file=sys.stderr)
                for f in futures:
                    f.cancel()
                break
    return results


# --- pub ----------------------------------------------------------------------


def parse_pubspec_lock(path):
    """name -> {version, host} for hosted packages; sdk/git/path entries carry no host."""
    r = subprocess.run(["yq", "-o=json", ".", str(path)],
                       capture_output=True, text=True, check=True)
    doc = json.loads(r.stdout or "{}") or {}
    out = {}
    for name, entry in (doc.get("packages") or {}).items():
        e = entry or {}
        desc = e.get("description")
        host = desc.get("url") if isinstance(desc, dict) else None
        out[name] = {"version": str(e.get("version") or ""),
                     "host": host if e.get("source") == "hosted" else None}
    return out


def fetch_pubspec_deps(name, version, host):
    """Dependency names of one hosted package version, from the registry that resolved it."""
    base = (host or "https://pub.dev").rstrip("/")
    url = f"{base}/api/packages/{urllib.parse.quote(name)}/versions/{urllib.parse.quote(version)}"
    doc = json.loads(http_get(url))
    return sorted(((doc.get("pubspec") or {}).get("dependencies") or {}).keys())


def pub_edges(markers, repo, fetch=None):
    locked = {}
    for lock in find_lockfiles(markers, repo, ("pubspec.lock",)):
        locked.update(parse_pubspec_lock(lock))
    hosted = [(name, (name, e["version"], e["host"]))
              for name, e in sorted(locked.items()) if e["host"] and e["version"]]
    fetched = fetch_all(hosted, fetch or fetch_pubspec_deps)
    edges = {}
    misses = sum(1 for v in fetched.values() if v is None)
    for name, deps in fetched.items():
        if not deps:
            continue
        version = locked[name]["version"]
        out = [(dn, locked[dn]["version"]) for dn in deps
               if dn in locked and locked[dn]["version"]]
        if out:
            edges.setdefault((name, version), []).extend(out)
    if misses:
        print(f"graph: {misses} of {len(hosted)} pubspecs unavailable — "
              f"their edges stay undetermined", file=sys.stderr)
    return edges


# --- gradle / maven -------------------------------------------------------------


def parse_gradle_lockfile(path):
    """(group, artifact) -> version."""
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        coord = line.split("=", 1)[0]
        parts = coord.split(":")
        if len(parts) == 3:
            out[(parts[0], parts[1])] = parts[2]
    return out


def pom_urls(group, artifact, version):
    path = f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
    google = f"https://dl.google.com/android/maven2/{path}"
    central = f"https://repo1.maven.org/maven2/{path}"
    flutter = f"https://storage.googleapis.com/download.flutter.io/{path}"
    if group.startswith("io.flutter"):
        return [flutter, google, central]
    if group.startswith(("androidx", "com.android", "com.google")):
        return [google, central]
    return [central, google]


def pom_dep_names(text):
    """(group, artifact) pairs a POM declares for runtime — test/provided/optional do not
    ship. Versions are deliberately ignored: the lockfile is the resolution."""
    m = re.search(r"<groupId>\s*([^<$]+?)\s*</groupId>", text)
    self_group = m.group(1) if m else ""
    body = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", text, flags=re.S)
    out = []
    for dep in re.findall(r"<dependency>(.*?)</dependency>", body, flags=re.S):
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", dep)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", dep)
        if not g or not a:
            continue
        scope = re.search(r"<scope>\s*([^<]+?)\s*</scope>", dep)
        if scope and scope.group(1) in ("test", "provided"):
            continue
        if re.search(r"<optional>\s*true\s*</optional>", dep):
            continue
        gv = g.group(1)
        if gv in ("${project.groupId}", "${pom.groupId}", "${parent.groupId}"):
            gv = self_group
        if "${" in gv or "${" in a.group(1):
            continue
        out.append((gv, a.group(1)))
    return out


def fetch_pom_deps(group, artifact, version):
    last_err = None
    for url in pom_urls(group, artifact, version):
        try:
            return pom_dep_names(http_get(url))
        except urllib.error.HTTPError as e:
            last_err = e     # 404 here is normal: try the next repository
        except Exception as e:
            last_err = e
    raise last_err if last_err else RuntimeError("no repository answered")


def maven_edges(markers, repo, fetch=None):
    locked = {}
    for lock in find_lockfiles(markers, repo, ("gradle.lockfile",)):
        locked.update(parse_gradle_lockfile(lock))
    items = [((g, a), (g, a, v)) for (g, a), v in sorted(locked.items())]
    fetched = fetch_all(items, fetch or fetch_pom_deps)
    edges = {}
    misses = sum(1 for v in fetched.values() if v is None)
    for (g, a), deps in fetched.items():
        if not deps:
            continue
        version = locked[(g, a)]
        out = [(dg, da, locked[(dg, da)]) for dg, da in deps if (dg, da) in locked]
        if out:
            edges.setdefault((g, a, version), []).extend(out)
    if misses:
        print(f"graph: {misses} of {len(items)} POMs unavailable — "
              f"their edges stay undetermined", file=sys.stderr)
    return edges


# --- shared -------------------------------------------------------------------


def find_lockfiles(markers, repo, names):
    """The lockfile that resolved a manifest sits in its directory or above it —
    workspaces share one at the root."""
    repo = Path(repo).resolve()
    found = []
    for m in markers:
        d = (repo / m).resolve().parent
        while d == repo or repo in d.parents:
            for lf in names:
                p = d / lf
                if p.is_file() and p not in found:
                    found.append(p)
            if d == repo:
                break
            d = d.parent
    return found


def maven_key(c):
    purl = c.get("purl") or ""
    if not purl.startswith("pkg:maven/"):
        return None
    body = purl[len("pkg:maven/"):].split("?", 1)[0]
    coord, _, version = body.partition("@")
    group, _, artifact = coord.partition("/")
    if not (group and artifact and version):
        return None
    return (urllib.parse.unquote(group), urllib.parse.unquote(artifact),
            urllib.parse.unquote(version))


def nv_key(prefix):
    def key(c):
        purl = c.get("purl") or ""
        if not purl.startswith(prefix):
            return None
        return (c.get("name"), c.get("version"))
    return key


def apply_edges(bom, edges, key_of):
    """Merge the derived edges into the BOM's dependencies, keyed by bom-ref. Returns the
    number of edges that were not already present."""
    refs = {}
    for c in bom.get("components", []) or []:
        k = key_of(c)
        if k:
            refs.setdefault(k, []).append(c.get("bom-ref"))
    existing = {d.get("ref"): set(d.get("dependsOn") or [])
                for d in bom.get("dependencies", []) or []}
    n_new = 0
    for src_key, deps in edges.items():
        tgts = sorted({r for dk in deps for r in (refs.get(dk) or [])})
        if not tgts:
            continue
        for s in refs.get(src_key) or []:
            cur = existing.setdefault(s, set())
            before = len(cur)
            cur.update(tgts)
            n_new += len(cur) - before
    bom["dependencies"] = [{"ref": r, "dependsOn": sorted(v)}
                           for r, v in sorted(existing.items())]
    return n_new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--markers", default="")
    args = ap.parse_args()

    markers = [m for m in args.markers.split(",") if m]
    if args.ecosystem == "npm":
        edges, key_of = npm_edges(markers, args.repo), nv_key("pkg:npm/")
    elif args.ecosystem == "pub":
        edges, key_of = pub_edges(markers, args.repo), nv_key("pkg:pub/")
    elif args.ecosystem in ("android-gradle", "jvm-gradle"):
        edges, key_of = maven_edges(markers, args.repo), maven_key
    else:
        print(f"graph: ecosystem {args.ecosystem} carries no derivable graph — "
              f"edges left undetermined", file=sys.stderr)
        return 0

    with open(args.bom, encoding="utf-8") as fh:
        bom = json.load(fh)
    n_new = apply_edges(bom, edges, key_of)
    with open(args.bom, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")
    print(f"graph: {len(bom['dependencies'])} nodes, {n_new} new edges "
          f"({args.ecosystem})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
