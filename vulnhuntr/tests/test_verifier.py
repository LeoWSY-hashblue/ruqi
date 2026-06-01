"""
Tests for vulnhuntr.verifier — all tests use mocked docker exec calls,
no real Docker daemon required.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from vulnhuntr.candidate import Candidate
from vulnhuntr import verifier as verifier_mod
from vulnhuntr.verifier import VerifyResult, verify


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_rce_candidate(**kwargs) -> Candidate:
    defaults = dict(
        file="crazy_functions/latex_fns/latex_toolbox.py",
        line=599,
        sink_type="rce",
        semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        code_snippet="subprocess.Popen(command, shell=True, ...)",
        enclosing_symbol="compile_latex_with_timeout",
        enclosing_source="def compile_latex_with_timeout(command, cwd, timeout=60):\n    ...",
    )
    defaults.update(kwargs)
    return Candidate(**defaults)


def _make_exec_results(*return_values):
    """
    Return a side_effect list for _docker_exec mock.
    Each element is (returncode, stdout, stderr).
    """
    return list(return_values)


CANARY_CONTENT = "VULNHUNTR_CANARY_UNTOUCHED"


# ---------------------------------------------------------------------------
# test_verify_confirmed_by_deletion
#   PoC deletes the canary → status = confirmed
# ---------------------------------------------------------------------------

def test_verify_confirmed_by_deletion(monkeypatch):
    canary_path = "/tmp/canary_abc123"

    # Sequence of _docker_exec calls:
    #   1. plant canary (sh -c echo ... > canary && chmod 444 canary)  → rc=0
    #   2. read canary before PoC (cat)                                → rc=0, content
    #   3. execute PoC                                                 → rc=0
    #   4. read canary after PoC (cat)                                 → rc=1, ""  (deleted)
    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc exec
        (1, "", "No such file"),              # read after (deleted)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))

    # Force a deterministic canary path
    monkeypatch.setattr(verifier_mod.uuid, "uuid4", lambda: SimpleNamespace(hex="abc123"))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "rm $CANARY_PATH")

    assert result.status == "confirmed"
    assert "deleted" in result.evidence
    assert result.canary_path == canary_path


# ---------------------------------------------------------------------------
# test_verify_confirmed_by_modification
#   PoC modifies canary content → status = confirmed
# ---------------------------------------------------------------------------

def test_verify_confirmed_by_modification(monkeypatch):
    canary_path = "/tmp/canary_def456"

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc exec
        (0, "PWNED\n", ""),                   # read after (modified)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))
    monkeypatch.setattr(verifier_mod.uuid, "uuid4", lambda: SimpleNamespace(hex="def456"))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "echo PWNED > $CANARY_PATH")

    assert result.status == "confirmed"
    assert "modified" in result.evidence


# ---------------------------------------------------------------------------
# test_verify_false_positive_on_poc_error
#   PoC exits non-zero and canary unchanged → false_positive
# ---------------------------------------------------------------------------

def test_verify_false_positive_on_poc_error(monkeypatch):
    canary_path = "/tmp/canary_ghi789"

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (1, "", "command not found"),          # poc fails
        (0, CANARY_CONTENT + "\n", ""),       # read after (unchanged)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))
    monkeypatch.setattr(verifier_mod.uuid, "uuid4", lambda: SimpleNamespace(hex="ghi789"))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "bad_command $CANARY_PATH")

    assert result.status == "false_positive"
    assert "command not found" in result.evidence or "code 1" in result.evidence


# ---------------------------------------------------------------------------
# test_verify_suspected_when_poc_runs_but_canary_unchanged
#   PoC exits 0 but canary untouched → suspected
# ---------------------------------------------------------------------------

def test_verify_suspected_when_poc_runs_but_canary_unchanged(monkeypatch):
    canary_path = "/tmp/canary_jkl012"

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc runs OK
        (0, CANARY_CONTENT + "\n", ""),       # read after (unchanged)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))
    monkeypatch.setattr(verifier_mod.uuid, "uuid4", lambda: SimpleNamespace(hex="jkl012"))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "echo hello")   # doesn't touch canary

    assert result.status == "suspected"
    assert "not modified" in result.evidence


# ---------------------------------------------------------------------------
# test_verify_rejects_non_rce_sink_type
# ---------------------------------------------------------------------------

def test_verify_rejects_non_rce_sink_type():
    candidate = _make_rce_candidate(sink_type="ssrf")

    with pytest.raises(NotImplementedError, match="sink_type='rce'"):
        verify(candidate, "fake_container", "some_poc")


# ---------------------------------------------------------------------------
# test_canary_path_is_unique_per_call
#   Two calls should use different canary paths (no shared state).
# ---------------------------------------------------------------------------

def test_canary_path_is_unique_per_call(monkeypatch):
    paths_seen = []
    call_counter = [0]

    def fake_exec(cid, cmd):
        # Track plant calls to capture canary paths
        c = " ".join(cmd)
        if "VULNHUNTR_CANARY" in c and "echo" in c:
            import re
            m = re.search(r"/tmp/canary_\w+", c)
            if m:
                paths_seen.append(m.group(0))
        if "cat" in c:
            call_counter[0] += 1
            # Alternating: first read returns content, second read returns deleted
            return (0, CANARY_CONTENT + "\n", "") if call_counter[0] % 2 == 1 else (1, "", "")
        return (0, "", "")

    monkeypatch.setattr(verifier_mod, "_docker_exec", fake_exec)

    candidate = _make_rce_candidate()
    r1 = verify(candidate, "c1", "rm $CANARY_PATH")
    r2 = verify(candidate, "c1", "rm $CANARY_PATH")

    assert r1.canary_path != r2.canary_path
