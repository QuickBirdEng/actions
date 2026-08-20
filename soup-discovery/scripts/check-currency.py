#!/usr/bin/env python3
"""Dependency currency and staleness (WI-006-09-02: Currency and obsolescence).

Two different questions, deliberately answered separately because they call for different
actions:

  behind   we are not keeping up — 0 major / 1 minor / unlimited patch behind the latest.
           The fix is an upgrade.
  stale    *upstream* is not keeping up — no release in the staleness window. An upgrade
           is not available, so the answer is replace, fork, or accept with a reason. A
           component can be perfectly current and stale at the same time, and that
           combination is the one worth seeing: it means we are on the last version there
           will ever be.

The staleness window defaults to 12 months to match the analysis period the SOUP records
already use in `grq-3` ("Is maintained and support is available", 12 months, min. releases
expected). Reusing that rather than inventing a second definition of "maintained".

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
  several hundred OS packages (Annex B B.1.1).

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
from datetime import datetime, timezone

REGISTRY = {
    # The *full* document, not the abbreviated one. The abbreviated form carries only
    # `modified`, which changes on any metadata edit — a deprecation flag, an ownership
    # change, a tarball re-sign. npm reported `request` as modified three weeks ago when
    # its last actual release was 2020-02-11, and `left-pad` as 2024 when its last release
    # was 2018. Staleness read off `modified` would let exactly the abandoned packages
    # through as fresh. The full document costs more bytes and answers the right question.
    "npm": "https://registry.npmjs.org/{name}",
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


def fetch(url, timeout=20, accept=None):
    h = {"User-Agent": "quickbird-soup-currency"}
    if accept:
        h["Accept"] = accept
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def latest_version(purl, meta=None):
    """(version, published_iso, error). Returns None rather than guessing.

    `meta`, when given a dict, is filled with what the same registry document carries for
    free: supplier, license, and the registry deprecation flag. One request answers four
    questions — the report columns must not cost a second round trip."""
    m = re.match(r"pkg:([a-z]+)/(.+?)(?:@([^?]+))?(?:\?.*)?$", purl or "")
    if not m:
        return None, None, "no parsable purl"
    eco, name = m.group(1), m.group(2)
    try:
        if eco == "npm":
            d = fetch(REGISTRY["npm"].format(name=name))
            v = (d.get("dist-tags") or {}).get("latest")
            if meta is not None:
                author = d.get("author")
                if isinstance(author, dict):
                    author = author.get("name")
                if not author:
                    maints = d.get("maintainers") or []
                    author = maints[0].get("name") if maints else None
                if author:
                    meta["supplier"] = str(author)
                lic = d.get("license")
                if isinstance(lic, dict):
                    lic = lic.get("type")
                if lic:
                    meta["license"] = str(lic)
                dep = ((d.get("versions") or {}).get(v) or {}).get("deprecated")
                if dep:
                    meta["deprecated"] = str(dep) if isinstance(dep, str) else "deprecated"
            times = d.get("time") or {}
            # the publish time of the latest version, never `modified`
            t = times.get(v)
            if not t:
                return v, None, "npm returned no publish time for the latest version"
            return v, t, None
        if eco == "pypi":
            d = fetch(REGISTRY["pypi"].format(name=name))
            v = d["info"]["version"]
            if meta is not None:
                info = d.get("info") or {}
                who = info.get("author") or info.get("maintainer")
                if who:
                    meta["supplier"] = str(who)
                if info.get("license"):
                    meta["license"] = str(info["license"])[:60]
                if info.get("yanked"):
                    meta["deprecated"] = "yanked"
            urls = d.get("urls") or []
            t = urls[0].get("upload_time_iso_8601") if urls else None
            return v, t, None
        if eco == "pub":
            full = fetch(REGISTRY["pub"].format(name=name))
            d = full["latest"]
            if meta is not None and full.get("isDiscontinued"):
                meta["deprecated"] = "discontinued" + (
                    f" (replaced by {full.get('replacedBy')})" if full.get("replacedBy") else "")
            return d["version"], d.get("published"), None
        if eco == "golang":
            d = fetch(REGISTRY["golang"].format(name=name))
            return d.get("Version"), d.get("Time"), None
        if eco == "maven":
            if "/" not in name:
                return None, None, "maven purl without a group"
            group, artifact = name.rsplit("/", 1)
            path = group.replace(".", "/") + "/" + artifact
            xml = fetch_text(REGISTRY["maven"].format(path=path))
            # lastUpdated is yyyyMMddHHmmss
            lu = re.search(r"<lastUpdated>(\d{14})</lastUpdated>", xml)
            t = (f"{lu.group(1)[0:4]}-{lu.group(1)[4:6]}-{lu.group(1)[6:8]}T"
                 f"{lu.group(1)[8:10]}:{lu.group(1)[10:12]}:{lu.group(1)[12:14]}+00:00") if lu else None
            # <release> is the newest non-snapshot; <latest> can be a snapshot, which is not
            # something we would ever be expected to upgrade to.
            for tag in ("release", "latest"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", xml)
                if m:
                    return m.group(1), t, None
            return None, None, "no <release> in maven-metadata.xml"
        return None, None, f"no registry configured for {eco}"
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, json.JSONDecodeError, TimeoutError) as e:
        return None, None, f"registry lookup failed: {type(e).__name__}"


def parse_window(s, default_months=12):
    """'12m' / '18months' / '540d' -> days."""
    m = re.match(r"(\d+)\s*(m|month|months|d|day|days|y|year|years)?$", str(s or "").strip())
    if not m:
        return default_months * 30
    n, unit = int(m.group(1)), (m.group(2) or "m")[0]
    return n * (30 if unit == "m" else 365 if unit == "y" else 1)


def age_days(iso, now):
    if not iso:
        return None
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return (now - d).days
    except ValueError:
        return None


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


def annotate_bom(path, notes):
    """Stamp currency facts onto the components of a bundle, keyed by purl.

    notes: purl -> {latest, published, status, detail}. Written in place, same reasoning as
    the classifier annotation: the PDF is a pure function of the bundle, so anything it is
    expected to show — here the latest available version next to the shipped one — has to
    live in the bundle rather than in a side file.
    """
    with open(path, encoding="utf-8") as fh:
        bom = json.load(fh)
    hit = 0
    for c in bom.get("components", []) or []:
        n = notes.get(c.get("purl") or "")
        if not n:
            continue
        extra = [{"name": "quickbird:currency:status", "value": n["status"]}]
        if n.get("latest"):
            extra.append({"name": "quickbird:currency:latest", "value": str(n["latest"])})
        if n.get("detail"):
            extra.append({"name": "quickbird:currency:detail", "value": n["detail"]})
        if n.get("deprecated"):
            extra.append({"name": "quickbird:currency:deprecated", "value": n["deprecated"][:200]})
        # supplier and license go into the CycloneDX standard fields — that is where every
        # other consumer expects them; nothing is overwritten that the scanner already knew
        if n.get("supplier") and not c.get("supplier"):
            c["supplier"] = {"name": n["supplier"]}
        if n.get("license") and not c.get("licenses"):
            c["licenses"] = [{"license": {"name": n["license"]}}]
        c["properties"] = sorted((c.get("properties") or []) + extra,
                                 key=lambda x: (x["name"], x.get("value") or ""))
        hit += 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")
    return hit


def load_soup_reasons(soups_dir):
    """package -> reason, for the per-SOUP override the policy allows (WI-006-09-02: Currency and obsolescence)."""
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
    ap.add_argument("--annotate-bom", help="stamp latest/status per component into this bundle")
    ap.add_argument("--out", default="-")
    # Every other script in the pipeline takes --now for the same reason: an age check without a
    # fixed clock cannot be tested deterministically, and the expected values would drift.
    ap.add_argument("--now", help="ISO timestamp, for reproducible tests")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    bom = json.load(open(args.bom, encoding="utf-8"))
    policy = json.load(open(args.policy, encoding="utf-8"))
    cur_policy = policy.get("dependency_currency", {})
    limits = cur_policy.get("max_behind", {})

    def limit(key, default):
        """A max_behind value as an int, or None for 'unlimited'. Robust against the two
        shapes YAML produces (int and string), because a limit that raises a TypeError in
        the comparison would take the whole currency check down with it."""
        v = limits.get(key, default)
        if v is None or str(v).strip().lower() == "unlimited":
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            print(f"::warning::max_behind.{key} is {v!r}, not a number or 'unlimited' — "
                  f"using the default {default}", file=sys.stderr)
            return None if str(default).lower() == "unlimited" else int(default)

    max_major = limit("major", 0)
    max_minor = limit("minor", 1)
    # The patch limit was validated by validate-policy.sh (TR-03161 O.TrdP_2 requires one)
    # and then never measured: the comparison below only looked at major and minor, so a
    # component five patches behind a limit of one was not reported. Found by the review,
    # not by a run — the default is unlimited, so no default-configured product could show it.
    max_patch = limit("patch", "unlimited")
    stale_days = parse_window(cur_policy.get("stale_after", "12m"))
    if args.now:
        now = datetime.fromisoformat(str(args.now).replace("Z", "+00:00"))
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
    else:
        now = datetime.now(timezone.utc)
    reasons = load_soup_reasons(args.soups) if args.soups else {}

    # Direct dependencies only. The manifests decide (quickbird:dependency:scope, written
    # by mark-scope.py); components carrying a SOUP record are included as well, because
    # an approval implies a choice even where a manifest could not be read. The old
    # record-only rule was a proxy that made a direct dependency without a record
    # invisible here. Fallback when the document carries no scope information at all:
    # the previous behaviour.
    has_scope = any(
        q.get("name") == "quickbird:dependency:scope"
        for c in (bom.get("components") or [])
        for q in (c.get("properties") or []))
    direct = []
    for c in bom.get("components", []) or []:
        p = {q["name"]: q["value"] for q in (c.get("properties") or [])}
        if has_scope:
            if p.get("quickbird:dependency:scope") == "direct" or p.get("quickbird:soup:record"):
                direct.append(c)
        elif p.get("quickbird:soup:record") or (not reasons and args.soups is None):
            direct.append(c)
    if not has_scope and args.soups is None:
        print("::warning::no scope information and no SOUP records — checking every "
              "component, including transitives, which cannot be upgraded independently",
              file=sys.stderr)

    # Operating-system packages are excluded unconditionally. Under Annex B B.1.1 the base image is the
    # SOUP and its OS packages are transitive, so they are not individually subject to the
    # currency policy: the remediation is to update the image. Including them also has no
    # registry to query, so every one of them came back as "unknown" — on one backend product that
    # was 343 of 386 unknowns, which buried the 55 real findings.
    OS_PKG_TYPES = ("rpm", "deb", "apk")
    def is_os_pkg(c):
        purl = c.get("purl") or ""
        return any(purl.startswith(f"pkg:{t}/") for t in OS_PKG_TYPES)

    # Container images are checked separately. They have no purl and no registry that answers
    # "what is the latest version", but they carry a build date, so the obsolescence test applies
    # to them directly. This is where Annex B B.1.1 lands: the image is the SOUP, so the currency policy
    # applies to the image rather than to the packages inside it. Excluding the OS packages
    # without checking the image would have removed the signal altogether.
    images = []
    for c in bom.get("components", []) or []:
        cp = {q["name"]: q["value"] for q in (c.get("properties") or [])}
        if cp.get("quickbird:scan:image-created"):
            images.append((c, cp))

    skipped_os = sum(1 for c in direct if is_os_pkg(c))
    direct = [c for c in direct if c.get("purl") and not is_os_pkg(c)]
    if skipped_os:
        print(f"skipping {skipped_os} operating-system package(s): the base image is the SOUP "
              f"and its packages are updated with it (Annex B B.1.1)", file=sys.stderr)
    print(f"checking {len(direct)} component(s) against their registries", file=sys.stderr)

    def check(c):
        meta = {}
        latest, published, err = latest_version(c["purl"], meta)
        return c, latest, published, err, meta

    results, unknown = [], []
    notes = {}
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for c, latest, published, err, meta in ex.map(check, direct):
            name, cur = c.get("name"), c.get("version")
            if latest is None:
                unknown.append({"name": name, "version": cur, "purl": c.get("purl"),
                                "why": err or "no latest version returned"})
                notes[c.get("purl") or ""] = {"status": "unknown",
                                              "detail": err or "no latest version returned"}
                continue

            age = age_days(published, now)
            is_stale = age is not None and age > stale_days
            b = behind(cur, latest)
            if b is None:
                unknown.append({"name": name, "version": cur, "latest": latest,
                                "why": "version is not semver-comparable"})
                notes[c.get("purl") or ""] = {"status": "unknown", "latest": latest,
                                              "detail": "version is not semver-comparable"}
                continue
            over = ((max_major is not None and b[0] > max_major)
                    or (max_minor is not None and b[1] > max_minor)
                    or (max_patch is not None and b[2] > max_patch))

            # "current" means current: an available update inside the limits is its own
            # state, because the report lists it — white, but listed.
            status = ("stale-and-behind" if (is_stale and over)
                      else "stale" if is_stale
                      else "behind" if over
                      else "update-available" if b != (0, 0, 0) else "current")
            note = {"status": status, "latest": latest}
            note.update({k: v for k, v in meta.items()})
            if meta.get("deprecated"):
                note["status"] = "deprecated"
                note["detail"] = f"declared deprecated by the registry: {meta['deprecated'][:120]}"
            if over:
                note["detail"] = f"behind by {b[0]} major / {b[1]} minor / {b[2]} patch"
            elif is_stale:
                note["detail"] = f"no upstream release in {age} days"
            notes[c.get("purl") or ""] = note

            if not over and not is_stale:
                continue

            entry = {"name": name, "current": cur, "latest": latest,
                     "behind": {"major": b[0], "minor": b[1], "patch": b[2]},
                     "purl": c.get("purl"),
                     "last_release": published,
                     "last_release_age_days": age,
                     "beyond_max_behind": over,
                     "stale": is_stale}

            # The distinction that decides what anyone can do about it. Being behind has an
            # upgrade as its answer; being stale while already current does not — there is
            # no newer version to move to, so it is a replace, fork or accept decision, and
            # WI-006-03 already discourages taking on a SOUP that is no longer maintained.
            if is_stale and not over:
                entry["finding"] = "upstream-stale-and-we-are-current"
                entry["action"] = (f"no upgrade available: we are on the latest version and "
                                   f"upstream has not released in {age} days. Replace, fork, "
                                   f"or accept with a recorded reason.")
            elif is_stale and over:
                entry["finding"] = "upstream-stale-and-we-are-behind"
                entry["action"] = (f"upgrade to {latest} is possible but upstream stalled "
                                   f"{age} days ago — upgrading buys less than it looks.")
            else:
                entry["finding"] = "behind"
                entry["action"] = f"upgrade to {latest}"

            if name in reasons:
                entry["justified"] = True
                entry["reason"] = reasons[name]
            results.append(entry)

    # --- image obsolescence ---------------------------------------------------
    # An image is a component in its own right and ages like any other. Annex B B.1.1 makes the image the
    # SOUP, so the currency policy applies to the image rather than to the packages inside it.
    # Excluding the OS packages without checking the image would have removed the signal entirely.
    stale_images = []
    for c, cp in images:
        built = cp["quickbird:scan:image-created"]
        age = age_days(built, now)
        if age is None:
            unknown.append({"name": c.get("name"), "version": c.get("version"),
                            "why": f"image build date {built!r} could not be parsed"})
            continue
        if age > stale_days:
            stale_images.append({
                "name": c.get("name"), "version": c.get("version"),
                "kind": "container-image",
                "image_digest": cp.get("quickbird:scan:image-digest", ""),
                "built": built, "age_days": age,
                "finding": "image not rebuilt within the staleness window",
                "action": ("Rebuild or replace the image. This finding is about the image, not "
                           "about the version of the software packaged in it. Those are separate "
                           "questions: linuxserver/wireguard:1.0.20210914 is rebuilt regularly, "
                           "and the 2021 in its tag is the WireGuard version inside it."),
            })

    flagged = [r for r in results if not r.get("justified")]
    justified = [r for r in results if r.get("justified")]

    doc = {
        "schema": "quickbird.dependency-currency/v1",
        "policy": {"max_behind": limits, "stale_after_days": stale_days},
        "summary": {
            "checked": len(direct),
            "beyond_policy": len([r for r in flagged if r["beyond_max_behind"]]),
            "stale": len([r for r in flagged if r["stale"]]),
            "stale_with_no_upgrade": len([r for r in flagged
                                          if r["finding"] == "upstream-stale-and-we-are-current"]),
            "justified": len(justified),
            "stale_images": len(stale_images),
            "unknown": len(unknown),
        },
        # Report signal, not an alert. Named in the output so a caller cannot mistake it.
        "severity": "report-only",
        "beyond_policy": sorted(flagged, key=lambda r: (-r["behind"]["major"], -r["behind"]["minor"])),
        "justified": justified,
        "stale_images": stale_images,
        "unknown": unknown,
    }

    if args.annotate_bom:
        try:
            n = annotate_bom(args.annotate_bom, notes)
            print(f"currency: annotated {n} component(s) in the bundle", file=sys.stderr)
        except (OSError, json.JSONDecodeError) as e:
            print(f"::warning::could not annotate {args.annotate_bom}: {e}", file=sys.stderr)

    for purl, n in notes.items():
        if n.get("status") == "deprecated":
            print(f"::warning::{purl.split('@')[0]}: declared deprecated by its registry — "
                  f"{n.get('deprecated', '')[:120]}", file=sys.stderr)

    for e in stale_images:
        print(f"::warning::{e['name']} {e['version']}: image last built {e['built'][:10]}, "
              f"{e['age_days']} days ago. {e['action']}", file=sys.stderr)

    text = json.dumps(doc, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    s = doc["summary"]
    print(f"currency: {s['beyond_policy']} beyond policy, {s['stale']} stale "
          f"({s['stale_with_no_upgrade']} of them with no upgrade available), "
          f"{s['justified']} justified, {s['unknown']} could not be determined", file=sys.stderr)
    for r in flagged:
        if r["finding"] == "upstream-stale-and-we-are-current":
            print(f"::warning::{r['name']} {r['current']}: {r['action']}", file=sys.stderr)
    if unknown:
        print("::warning::a component whose latest version could not be determined is "
              "reported as unknown, not as current", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
