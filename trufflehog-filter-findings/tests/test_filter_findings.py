"""Tests for filter_findings.py."""
import json
import os
import sys
import tempfile
import textwrap
import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'filter_findings.py')


def _load_module(consumer_yaml=None, workspace=None):
    """Load filter_findings module with optional .qb/security/trufflehog-ignores.yaml content."""
    tmpdir = workspace or tempfile.mkdtemp()

    if consumer_yaml is not None:
        qb_dir = os.path.join(tmpdir, '.qb', 'security')
        os.makedirs(qb_dir, exist_ok=True)
        with open(os.path.join(qb_dir, 'trufflehog-ignores.yaml'), 'w') as f:
            f.write(textwrap.dedent(consumer_yaml))

    os.environ['GITHUB_WORKSPACE'] = tmpdir

    with open(SCRIPT) as f:
        source = f.read()

    ns = {'os': os, 'sys': sys, 'json': json, '__name__': '__not_main__'}
    exec(compile(source, SCRIPT, 'exec'), ns)
    return ns, tmpdir


def _make_finding(path, line, commit, detector='GitHub'):
    return json.dumps({
        'DetectorName': detector,
        'SourceMetadata': {
            'Data': {
                'Git': {
                    'file': path,
                    'line': line,
                    'commit': commit,
                }
            }
        }
    })


def _write_findings(tmpdir, findings):
    p = os.path.join(str(tmpdir), 'findings.json')
    with open(p, 'w') as f:
        for finding in findings:
            f.write(finding + '\n')
    return p


def _run_main(ns):
    try:
        ns['main']()
        return 0
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0


# ── load_acknowledged_findings ────────────────────────────────────────────────

def test_load_acknowledged_findings_from_consumer_file():
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: "abc123", path: src/secrets.ts }
    """)
    result = ns['load_acknowledged_findings']()
    assert result == {('abc123', 'src/secrets.ts')}


def test_load_acknowledged_findings_absent_file_returns_empty():
    ns, _ = _load_module()
    result = ns['load_acknowledged_findings']()
    assert result == set()


def test_load_acknowledged_findings_missing_commit_or_path_skipped():
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: "abc123" }
          - { path: "some/file.ts" }
          - { commit: "def456", path: "valid.ts" }
    """)
    result = ns['load_acknowledged_findings']()
    assert result == {('def456', 'valid.ts')}


def test_load_acknowledged_findings_commit_coerced_to_string():
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: 1234567890, path: src/file.ts }
    """)
    result = ns['load_acknowledged_findings']()
    assert ('1234567890', 'src/file.ts') in result


# ── find_git_metadata ─────────────────────────────────────────────────────────

def test_find_git_metadata_extracts_nested_file_key():
    ns, _ = _load_module()
    meta = {'Data': {'Git': {'file': 'src/main.ts', 'line': 42, 'commit': 'abc123'}}}
    result = ns['find_git_metadata'](meta)
    assert result['file'] == 'src/main.ts'


def test_find_git_metadata_returns_empty_dict_for_no_match():
    ns, _ = _load_module()
    result = ns['find_git_metadata']({'a': {'b': {'c': 'x'}}})
    assert result == {}


# ── main ──────────────────────────────────────────────────────────────────────

def test_main_no_findings_file_scan_success_exits_zero(tmp_path):
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = str(tmp_path / 'nonexistent.json')
    os.environ['INPUT_SCAN_OUTCOME'] = 'success'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 0


def test_main_no_findings_file_scan_failure_exits_nonzero(tmp_path, capsys):
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = str(tmp_path / 'nonexistent.json')
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ.pop('GITHUB_OUTPUT', None)
    assert _run_main(ns) == 1
    assert '::error::' in capsys.readouterr().out


def test_main_empty_findings_exits_zero(tmp_path):
    findings_file = _write_findings(tmp_path, [])
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'success'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 0


def test_main_unacknowledged_finding_emits_annotation_and_exits_one(tmp_path, capsys):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/secret.ts', 10, 'deadbeef'),
    ])
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 1
    assert '::error file=src/secret.ts,line=10::' in capsys.readouterr().out


def test_main_acknowledged_finding_is_suppressed(tmp_path, capsys):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/secret.ts', 10, 'deadbeef'),
    ])
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: "deadbeef", path: src/secret.ts }
    """)
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 0
    out = capsys.readouterr().out
    assert '::error' not in out
    assert 'Suppressed 1' in out


def test_main_same_commit_different_path_not_suppressed(tmp_path, capsys):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/other.ts', 5, 'deadbeef'),
    ])
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: "deadbeef", path: src/secret.ts }
    """)
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 1
    assert '::error file=src/other.ts' in capsys.readouterr().out


def test_main_same_path_different_commit_not_suppressed(tmp_path):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/secret.ts', 10, 'cafebabe'),
    ])
    ns, _ = _load_module(consumer_yaml="""
        acknowledged_findings:
          - { commit: "deadbeef", path: src/secret.ts }
    """)
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'true'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 1


def test_main_fail_on_found_false_exits_zero_despite_findings(tmp_path):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/secret.ts', 10, 'deadbeef'),
    ])
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'false'
    os.environ['GITHUB_OUTPUT'] = str(tmp_path / 'output')
    assert _run_main(ns) == 0


def test_main_count_output_written(tmp_path):
    findings_file = _write_findings(tmp_path, [
        _make_finding('src/secret.ts', 10, 'deadbeef'),
        _make_finding('src/other.ts', 5, 'cafebabe'),
    ])
    output_file = str(tmp_path / 'output')
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'false'
    os.environ['GITHUB_OUTPUT'] = output_file
    _run_main(ns)
    with open(output_file) as f:
        assert 'count=2' in f.read()


def test_main_duplicate_findings_deduplicated(tmp_path):
    finding = _make_finding('src/secret.ts', 10, 'deadbeef')
    findings_file = _write_findings(tmp_path, [finding, finding])
    output_file = str(tmp_path / 'output')
    ns, _ = _load_module()
    os.environ['INPUT_FINDINGS_FILE'] = findings_file
    os.environ['INPUT_SCAN_OUTCOME'] = 'failure'
    os.environ['INPUT_FAIL_ON_FOUND'] = 'false'
    os.environ['GITHUB_OUTPUT'] = output_file
    _run_main(ns)
    with open(output_file) as f:
        assert 'count=1' in f.read()
