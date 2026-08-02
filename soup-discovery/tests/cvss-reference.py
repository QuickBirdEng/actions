#!/usr/bin/env python3
"""Check the CVSS 3.1 implementation against published NVD base scores.

Kept as its own file rather than inline in the harness: these are reference values from
outside the codebase, and they are the only thing standing between a scoring bug and a
whole severity band being wrong. The existing action-scripts/cvss-3-1-severity.sh omits
Roundup and the scope-changed impact correction, which puts 164 of the 2592 possible base
vectors in a lower band than the specification gives — so "close enough" is not enough here.
"""
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location(
    "cf", os.path.join(os.environ.get("S", "../scripts"), "classify-findings.py"))
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)

CASES = [
    ("CVE-2021-44228 Log4Shell", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVE-2019-0708 BlueKeep",   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  9.8),
    ("CVE-2021-45046",           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",  9.0),
    ("CVE-2014-0160 Heartbleed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    ("band boundary, roundup",   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L",  7.0),
    ("CVE-2020-8203 lodash",     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",  5.9),
    ("scope changed, low",       "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",  5.6),
    ("no impact",                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  0.0),
]

bad = 0
for label, vector, expected in CASES:
    got = cf.cvss31_base(vector)
    if got is None or abs(got - expected) >= 0.05:
        print(f"  {label}: expected {expected}, got {got}")
        bad += 1
sys.exit(1 if bad else 0)
