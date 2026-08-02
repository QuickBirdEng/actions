#!/usr/bin/env python3
"""Dependency currency (§6): how far behind its latest version a component may be.

Separate from CVEs on purpose. A component with no known vulnerability can still be
unmaintainable, and IEC 81001-5-1 expects components to be kept reasonably current. The
default is 0 major, 1 minor, unlimited patch behind.

Two rules that keep this from becoming noise:

  It is a *report* signal, not an alert. A component that is merely out of date does not
  wake anyone up; it appears in the overview and the backstop report. It becomes urgent
  only when it coincides with an applicable CVE, and that is a fact the caller joins in.

  Only direct dependencies are checked. Transitives move when their parent moves, so
  flagging them produces a list nobody can act on — you cannot upgrade a transitive
  without upgrading what pulled it in. Container base images are one component, not their
  several hundred OS packages (§5.1).

Latest versions come from each ecosystem's own registry. A registry that cannot be reached
yields "unknown", never "current": not knowing how far behind something is must not read
as being up to date.

Usage: check-currency.py <bom.cdx.json> <policy.json> [--soups dir] [--out f]
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}/latest",
    "pypi": "https://pypi.org/pypi/{name}/json",
    "pub": "https://pub.dev/api/packages/{name}",
    # repo1 rather than search.maven.org: the search API took 30-45s and timed out on two
    # of three attempts, which would have made every Maven component permanently "unknown".
    # The repository's own maven-metadata.xml answers immediately and is canonical.
    "maven": "https://repo1.maven.org/maven2/{path}/maven-metadata.xml",
    "golang": "https://proxy.golang.org/{name}/@latest",
}


def fetch_text(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "quickbird-soup-currency"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "quickbird-soup-currency"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def latest_version(purl):
    """(version, error). Returns (None, reason) rather than guessing."""
    m = re.match(r"pkg:([a-z]+)/(.+?)(?:@([^?]+))?(?:\?.*)?$", purl or "")
    if not m:
        return None, "no parsable purl"
    eco, name = m.group(1), m.group(2)
    try:
        if eco == "npm":
            return fetch(REGISTRY["npm"].format(name=name)).get("version"), None
        if eco == "pypi":
            return fetch(REGISTRY["pypi"].format(name=name))["info"]["version"], None
        if eco == "pub":
            return fetch(REGISTRY["pub"].format(name=name))["latest"]["version"], None
        if eco == "golang":
            return fetch(REGISTRY["golang"].format(name=name)).get("Version"), None
        if eco == "maven":
            if "/" not in name:
                return None, "maven purl without a group"
            group, artifact = name.rsplit("/", 1)
            path = group.replace(".", "/") + "/" + artifact
            xml = fetch_text(REGISTRY["maven"].format(path=path))
            # <release> is the newest non-snapshot; <latest> can be a snapshot, which is not
            # something we would ever be expected to upgrade to.
            for tag in ("release", "latest"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", xml)
                if m:
                    return m.group(1), None
            return None, "no <release> in maven-metadata.xml"
        return None, f"no registry configured for {eco}"
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, json.JSONDecodeError, TimeoutError) as e:
        return None, f"registry lookup failed: {type(e).__name__}"


def semver(v):
    m = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v or ""))
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def behind(current, latest):
    """(major, minor, patch) behind, or None if either version is unparsable."""
    c, l = semver(current), semver(latest)
    if not c or not l:
        return None
    if l <= c:
        return (0, 0, 0)
    if l[0] > c[0]:
        return (l[0] - c[0], 0, 0)
    if l[1] > c[1]:
        return (0, l[1] - c[1], 0)
    return (0, 0, max(0, l[2] - c[2]))


def load_soup_reasons(soups_dir):
    """package -> reason, for the per-SOUP override the policy allows (§6)."""
    import glob
    import os
    out = {}
    for f in glob.glob(os.path.join(soups_dir or "", "**", "*.json"), recursive=True):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            r = d.get("currency_reason") or d.get("reason")
            if d.get("package") and r:
                out[d["package"]] = r
        except (OSError, json.JSONDecodeError):
            continue
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("policy")
    ap.add_argument("--soups")
    ap.add_argument("--out", default="-")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    bom = json.load(open(args.bom, encoding="utf-8"))
    policy = json.load(open(args.policy, encoding="utf-8"))
    limits = policy.get("dependency_currency", {}).get("max_behind", {})
    max_major = limits.get("major", 0)
    max_minor = limits.get("minor", 1)
    reasons = load_soup_reasons(args.soups) if args.soups else {}

    # Direct dependencies only. A component is direct if a SOUP record exists for it — that
    # is what "we chose this" means here — falling back to the whole set when no records
    # are given, with a warning, because checking everything is noisy rather than wrong.
    direct = []
    for c in bom.get("components", []) or []:
        p = {q["name"]: q["value"] for q in (c.get("properties") or [])}
        if p.get("quickbird:soup:record") or (not reasons and args.soups is None):
            direct.append(c)
    if args.soups is None:
        print("::warning::no SOUP records given — checking every component, including "
              "transitives, which cannot be upgraded independently", file=sys.stderr)

    direct = [c for c in direct if c.get("purl")]
    print(f"checking {len(direct)} component(s) against their registries", file=sys.stderr)

    def check(c):
        latest, err = latest_version(c["purl"])
        return c, latest, err

    results, unknown = [], []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for c, latest, err in ex.map(check, direct):
            name, cur = c.get("name"), c.get("version")
            if latest is None:
                unknown.append({"name": name, "version": cur, "purl": c.get("purl"),
                                "why": err or "no latest version returned"})
                continue
            b = behind(cur, latest)
            if b is None:
                unknown.append({"name": name, "version": cur, "latest": latest,
                                "why": "version is not semver-comparable"})
                continue
            over = (b[0] > max_major) or (b[1] > max_minor and max_minor != "unlimited")
            if not over:
                continue
            entry = {"name": name, "current": cur, "latest": latest,
                     "behind": {"major": b[0], "minor": b[1], "patch": b[2]},
                     "purl": c.get("purl")}
            if name in reasons:
                entry["justified"] = True
                entry["reason"] = reasons[name]
            results.append(entry)

    flagged = [r for r in results if not r.get("justified")]
    justified = [r for r in results if r.get("justified")]

    doc = {
        "schema": "quickbird.dependency-currency/v1",
        "policy": {"max_behind": limits},
        "summary": {
            "checked": len(direct),
            "beyond_policy": len(flagged),
            "justified": len(justified),
            "unknown": len(unknown),
        },
        # Report signal, not an alert. Named in the output so a caller cannot mistake it.
        "severity": "report-only",
        "beyond_policy": sorted(flagged, key=lambda r: (-r["behind"]["major"], -r["behind"]["minor"])),
        "justified": justified,
        "unknown": unknown,
    }

    text = json.dumps(doc, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    s = doc["summary"]
    print(f"currency: {s['beyond_policy']} beyond policy, {s['justified']} justified, "
          f"{s['unknown']} could not be determined", file=sys.stderr)
    if unknown:
        print("::warning::a component whose latest version could not be determined is "
              "reported as unknown, not as current", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
