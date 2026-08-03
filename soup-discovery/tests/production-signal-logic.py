#!/usr/bin/env python3
"""Offline checks of "what reached production" (§3.4).

Read from the pipeline rather than guessed: a tag push triggers the *staging* workflow — both
`v1.0.15` and `v1.0.15-qa4` — and production is a manual `workflow_dispatch` of a separate
workflow behind a named allow-list. So a tag never means production, and the authoritative record
is the GitHub deployment with a production environment.

Three signals were tried before this and all three were wrong. On alvie they said 2025-10-01
(tag pattern), 2026-05-04 (prerelease flag) and 2025-06-23 (release asset). The production
deployment record says v1.0.7 went live on 2026-04-21 — six months after that tag was published,
because a release date is not a deploy date.
"""
import importlib.util, json, os, subprocess, sys

spec = importlib.util.spec_from_file_location(
    "bs", os.path.join(os.environ.get("S", "../scripts"), "backstop-report.py"))
bs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bs)

bad = []
def eq(label, got, want):
    if got != want:
        bad.append(f"{label}: expected {want}, got {got}")

def with_api(responses):
    """Stub `gh api` by matching a substring of the endpoint."""
    real = subprocess.run
    def fake(argv, **k):
        endpoint = argv[2] if len(argv) > 2 else ""
        for needle, rows in responses.items():
            if needle in endpoint:
                if rows is None:
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(
                    argv, 0, "\n".join(json.dumps(r) for r in rows), "")
        return subprocess.CompletedProcess(argv, 0, "", "")
    subprocess.run = fake
    try:
        return bs.production_deploys("QuickBirdEng/x")
    finally:
        subprocess.run = real

ENVS = [{"name": "Development"}, {"name": "Staging"}, {"name": "Production"}]

# The straightforward case: production deploys exist and the newest came from a tag.
dates, basis, envs = with_api({
    "/environments": ENVS,
    "environment=Production": [
        {"at": "2026-04-21T10:00:00Z", "env": "Production", "ref": "v1.0.7"},
        {"at": "2025-06-23T10:00:00Z", "env": "Production", "ref": "v1.0.4"},
    ],
})
eq("newest production deploy", dates[0], "2026-04-21T10:00:00Z")
eq("basis names the source", "production deployments from a tag" in basis, True)

# mindnet's newest production record is a branch ref from a content-migration workflow. Counting
# it would date the maintenance grid from a database migration.
dates, basis, envs = with_api({
    "/environments": ENVS,
    "environment=Production": [
        {"at": "2026-07-29T10:00:00Z", "env": "Production", "ref": "temp-disable-cms-transfer"},
        {"at": "2026-07-27T10:00:00Z", "env": "Production", "ref": "v1.0.15"},
    ],
})
eq("non-tag production refs are skipped", dates[0], "2026-07-27T10:00:00Z")
eq("and the count of skipped ones is stated", "1 non-tag" in basis, True)

# A production environment with nothing but branch refs must not read as "never deployed".
dates, basis, envs = with_api({
    "/environments": ENVS,
    "environment=Production": [
        {"at": "2026-07-29T10:00:00Z", "env": "Production", "ref": "main"},
    ],
})
eq("no tagged production deploy", dates, [])
eq("and the reason names the ref", "'main'" in basis, True)

# osteocoach defines no Production environment — it deploys to `Study`. That is a product this
# check cannot see, not a product that never maintains itself.
dates, basis, envs = with_api({
    "/environments": [{"name": "Development"}, {"name": "Staging"}, {"name": "Study"}],
})
eq("no production environment", dates, [])
eq("the environments it does define are named", "Study" in basis, True)

# Unreadable records are not the same as an absence of records, and must not read as one.
dates, basis, envs = with_api({"/environments": None, "/deployments": None})
eq("unreadable stays unknown", dates, None)

# Regression: `--jq .environments[].name` emits bare strings, which are not JSON per line. The
# parser returned None, the code fell into its fallback path, and products with hundreds of
# production deploys were reported as having none. The env list must survive the round trip.
dates, basis, envs = with_api({
    "/environments": ENVS,
    "environment=Production": [{"at": "2026-04-21T10:00:00Z", "env": "Production", "ref": "v1.0.7"}],
})
eq("environment names parsed", envs, ["Development", "Production", "Staging"])

# Tag-shaped refs that actually occur in these repos.
for ref, want in [("v1.0.15", True), ("v1.0.8-qa30", True), ("1.0.7", True),
                  ("v1.0.2.0.1", True), ("main", False), ("temp-disable-x", False),
                  ("release/v1", False)]:
    eq(f"tag ref {ref!r}", bool(bs.TAG_REF_RX.match(ref)), want)

for b in bad:
    print("  " + b)
sys.exit(1 if bad else 0)
