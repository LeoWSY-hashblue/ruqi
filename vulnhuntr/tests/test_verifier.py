"""
Tests for vulnhuntr.verifier. All tests use mocked docker exec calls,
so no real Docker daemon is required.
"""

import re
from types import SimpleNamespace

import pytest

from vulnhuntr import verifier as verifier_mod
from vulnhuntr.candidate import Candidate
from vulnhuntr.verifier import verify


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


CANARY_CONTENT = "VULNHUNTR_CANARY_UNTOUCHED"


def _patch_uuid(monkeypatch, value: str) -> str:
    monkeypatch.setattr(verifier_mod.uuid, "uuid4", lambda: SimpleNamespace(hex=value))
    return f"/tmp/vulnhuntr_canary_{value}/canary"


# ---------------------------------------------------------------------------
# test_verify_confirmed_by_deletion
#   PoC deletes the canary -> status = confirmed
# ---------------------------------------------------------------------------

def test_verify_confirmed_by_deletion(monkeypatch):
    canary_path = _patch_uuid(monkeypatch, "abc123")
    calls = []

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc exec
        (42, "", "No such file"),             # read after (deleted)
    ]
    call_iter = iter(exec_results)

    def fake_exec(cid, cmd):
        calls.append((cid, cmd))
        return next(call_iter)

    monkeypatch.setattr(verifier_mod, "_docker_exec", fake_exec)

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "rm $CANARY_PATH")

    plant_cmd = calls[0][1][2]
    assert "chmod 444" not in plant_cmd
    assert "chmod 777 /tmp/vulnhuntr_canary_abc123" in plant_cmd
    assert "chmod 666 /tmp/vulnhuntr_canary_abc123/canary" in plant_cmd
    assert result.status == "confirmed"
    assert "deleted" in result.evidence
    assert result.canary_path == canary_path


# ---------------------------------------------------------------------------
# test_verify_confirmed_by_modification
#   PoC modifies canary content -> status = confirmed
# ---------------------------------------------------------------------------

def test_verify_confirmed_by_modification(monkeypatch):
    _patch_uuid(monkeypatch, "def456")

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc exec
        (0, "PWNED\n", ""),                   # read after (modified)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "echo PWNED > $CANARY_PATH")

    assert result.status == "confirmed"
    assert "modified" in result.evidence


# ---------------------------------------------------------------------------
# test_verify_false_positive_on_poc_error
#   PoC exits non-zero and canary unchanged -> false_positive
# ---------------------------------------------------------------------------

def test_verify_false_positive_on_poc_error(monkeypatch):
    _patch_uuid(monkeypatch, "ghi789")

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (1, "", "command not found"),         # poc fails
        (0, CANARY_CONTENT + "\n", ""),       # read after (unchanged)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "bad_command $CANARY_PATH")

    assert result.status == "false_positive"
    assert "command not found" in result.evidence or "code 1" in result.evidence


# ---------------------------------------------------------------------------
# test_verify_suspected_when_poc_runs_but_canary_unchanged
#   PoC exits 0 but canary untouched -> suspected
# ---------------------------------------------------------------------------

def test_verify_suspected_when_poc_runs_but_canary_unchanged(monkeypatch):
    _patch_uuid(monkeypatch, "jkl012")

    exec_results = [
        (0, "", ""),                          # plant
        (0, CANARY_CONTENT + "\n", ""),       # read before
        (0, "", ""),                          # poc runs OK
        (0, CANARY_CONTENT + "\n", ""),       # read after (unchanged)
    ]
    call_iter = iter(exec_results)
    monkeypatch.setattr(verifier_mod, "_docker_exec", lambda cid, cmd: next(call_iter))

    candidate = _make_rce_candidate()
    result = verify(candidate, "fake_container", "echo hello")

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
        command = " ".join(cmd)
        if "VULNHUNTR_CANARY" in command and "printf" in command:
            match = re.search(r"/tmp/vulnhuntr_canary_\w+/canary", command)
            if match:
                paths_seen.append(match.group(0))
        if "cat" in command:
            call_counter[0] += 1
            # Alternating: first read returns content, second read returns deleted.
            return (0, CANARY_CONTENT + "\n", "") if call_counter[0] % 2 == 1 else (42, "", "")
        return (0, "", "")

    monkeypatch.setattr(verifier_mod, "_docker_exec", fake_exec)

    candidate = _make_rce_candidate()
    r1 = verify(candidate, "c1", "rm $CANARY_PATH")
    r2 = verify(candidate, "c1", "rm $CANARY_PATH")

    assert r1.canary_path != r2.canary_path
    assert paths_seen == [r1.canary_path, r2.canary_path]
