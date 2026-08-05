#!/usr/bin/env python3
"""
Filters raw TruffleHog JSONL output against acknowledged_findings from
.qb/security/trufflehog-ignores.yaml, emits GitHub annotations, and
exits non-zero when unacknowledged findings remain and fail-on-found is true.

Environment variables (set by action.yml):
  INPUT_FINDINGS_FILE  - path to raw TruffleHog JSONL output
  INPUT_SCAN_OUTCOME   - 'success' or 'failure' (from the scan step)
  INPUT_FAIL_ON_FOUND  - 'true' or 'false'
"""
import json
import os
import sys


def load_acknowledged_findings():
    """Return set of (commit, path) tuples from .qb/security/trufflehog-ignores.yaml."""
    findings = set()
    try:
        import yaml
        workspace = os.environ.get('GITHUB_WORKSPACE', '')
        consumer_file = os.path.join(workspace, '.qb/security/trufflehog-ignores.yaml')
        with open(consumer_file) as f:
            data = yaml.safe_load(f) or {}
        for af in (data.get('acknowledged_findings') or []):
            commit = af.get('commit')
            path = af.get('path')
            if commit is not None and path is not None:
                findings.add((str(commit), path))
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Warning: failed to read .qb/security/trufflehog-ignores.yaml: {e}")
    return findings


def find_git_metadata(node):
    if isinstance(node, dict):
        if 'file' in node or 'File' in node:
            return node
        for v in node.values():
            r = find_git_metadata(v)
            if r:
                return r
    return {}


def _set_output(name, value):
    output_file = os.environ.get('GITHUB_OUTPUT', '')
    if output_file:
        with open(output_file, 'a') as f:
            f.write(f'{name}={value}\n')


def main():
    findings_file = os.environ.get('INPUT_FINDINGS_FILE', '')
    scan_outcome = os.environ.get('INPUT_SCAN_OUTCOME', 'success')
    fail_on_found = os.environ.get('INPUT_FAIL_ON_FOUND', 'true').lower() == 'true'

    if not findings_file or not os.path.exists(findings_file):
        if scan_outcome == 'failure':
            print('::error::TruffleHog scan failed without producing findings output. Check the scan step logs.')
            sys.exit(1)
        _set_output('count', '0')
        sys.exit(0)

    seen = set()
    records = []
    with open(findings_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                git = find_git_metadata(d.get('SourceMetadata', {}))
                path = git.get('file', git.get('File', ''))
                lineno = git.get('line', git.get('Line', 1)) or 1
                commit = git.get('commit', git.get('Commit', ''))
                detector = d.get('DetectorName', 'Unknown')
                key = (path, lineno, detector)
                if path and key not in seen:
                    seen.add(key)
                    records.append({'path': path, 'line': lineno, 'commit': commit, 'detector': detector})
            except Exception:
                pass

    acknowledged = load_acknowledged_findings()
    if acknowledged:
        before = len(records)
        records = [r for r in records if (str(r['commit']), r['path']) not in acknowledged]
        suppressed = before - len(records)
        if suppressed:
            print(f"Suppressed {suppressed} acknowledged finding(s) based on .qb/security/trufflehog-ignores.yaml")

    _set_output('count', str(len(records)))

    for r in records:
        print(f"::error file={r['path']},line={r['line']}::TruffleHog [{r['detector']}]: verified secret detected (commit {r['commit']})")

    sys.exit(1 if records and fail_on_found else 0)


if __name__ == '__main__':
    main()
