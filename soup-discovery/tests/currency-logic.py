#!/usr/bin/env python3
"""Offline checks of the currency comparison itself.

The registry lookups need the network; the policy decision does not, and it is the part
that decides whether something gets flagged. Kept separate so the rule is covered even when
the suite runs offline.
"""
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location(
    "cc", os.path.join(os.environ.get("S", "../scripts"), "check-currency.py"))
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

bad = []

def eq(label, got, want):
    if got != want:
        bad.append(f"{label}: expected {want}, got {got}")

# behind() reports distance at the highest differing level only: something two majors
# behind is not also "n minors behind", because the minor line does not survive a major.
eq("same version",        cc.behind("1.2.3", "1.2.3"), (0, 0, 0))
eq("newer than latest",   cc.behind("2.0.0", "1.9.9"), (0, 0, 0))
eq("patch behind",        cc.behind("1.2.3", "1.2.9"), (0, 0, 6))
eq("minor behind",        cc.behind("1.2.3", "1.5.0"), (0, 3, 0))
eq("major behind",        cc.behind("1.2.3", "3.0.0"), (2, 0, 0))
eq("v prefix",            cc.behind("v1.0.0", "v1.1.0"), (0, 1, 0))
eq("partial version",     cc.behind("1", "1.2.0"), (0, 2, 0))
eq("unparsable current",  cc.behind("not-a-version", "1.0.0"), None)
eq("unparsable latest",   cc.behind("1.0.0", "latest"), None)

# purl parsing feeds the registry choice; a wrong ecosystem means a wrong or no answer.
# latest_version returns (version, published, error) — the middle slot is the publish time
# that staleness needs, so the error is the third.
eq("unparsable purl", cc.latest_version("not-a-purl")[0], None)
eq("unparsable purl reason", cc.latest_version("not-a-purl")[2], "no parsable purl")
eq("no registry", cc.latest_version("pkg:cargo/serde@1.0.0")[2], "no registry configured for cargo")

for b in bad:
    print("  " + b)
sys.exit(1 if bad else 0)
