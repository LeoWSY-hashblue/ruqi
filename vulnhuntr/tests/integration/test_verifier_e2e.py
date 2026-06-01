"""
End-to-end verifier tests using the vulnerable_flask_app fixture.

Requires a running Docker daemon. Skipped automatically if Docker is unavailable.

Flow:
    1. Build vulnerable_flask_app image (cached after first run).
    2. Start container (detached, --rm).
    3. Wait for Flask /health to respond.
    4. Run verify() with a real canary + real PoC.
    5. Assert verdict; tear down container.
"""

import subprocess
import time
from pathlib import Path

import pytest

from vulnhuntr.candidate import Candidate
from vulnhuntr.verifier import verify

_FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app"
_IMAGE_TAG = "vulnhuntr-test-flask-rce:latest"
_FLASK_URL = "http://127.0.0.1:5000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _exec_in(container_id: str, cmd: list[str]) -> tuple[int, str]:
    r = subprocess.run(
        ["docker", "exec", container_id, *cmd],
        capture_output=True, text=True, timeout=15,
    )
    return r.returncode, r.stdout + r.stderr


def _wait_for_flask(container_id: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, _ = _exec_in(container_id, ["curl", "-sf", f"{_FLASK_URL}/health"])
        if rc == 0:
            return True
        time.sleep(0.4)
    return False


def _rce_candidate() -> Candidate:
    return Candidate(
        file="app.py",
        line=17,  # subprocess.run line
        sink_type="rce",
        semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        code_snippet='subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)',
        enclosing_symbol="compile_latex",
        enclosing_source=(
            'def compile_latex():\n'
            '    cmd = request.args.get("cmd", "echo noop")\n'
            '    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)\n'
            '    return result.stdout or result.stderr'
        ),
    )


# ---------------------------------------------------------------------------
# Module-scoped fixture: one container for all tests in this file
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flask_rce_container():
    if not _docker_available():
        pytest.skip("Docker daemon not reachable — skipping verifier e2e tests")

    # Build (cached by Docker layer hash; fast on repeat runs)
    subprocess.run(
        ["docker", "build", "-t", _IMAGE_TAG, str(_FIXTURE_DIR)],
        check=True, capture_output=True,
    )

    # Start container
    r = subprocess.run(
        ["docker", "run", "-d", "--rm", _IMAGE_TAG],
        check=True, capture_output=True, text=True,
    )
    container_id = r.stdout.strip()

    if not _wait_for_flask(container_id):
        subprocess.run(["docker", "stop", container_id], capture_output=True)
        pytest.fail("Flask app did not become ready within 20 s")

    yield container_id

    subprocess.run(["docker", "stop", container_id], capture_output=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rce_confirmed_canary_deleted(flask_rce_container):
    """
    PoC routes cmd=rm $CANARY_PATH through the vulnerable /compile endpoint.
    Flask runs it via subprocess(shell=True).
    Verifier detects canary deletion → confirmed.
    """
    poc = (
        f'curl -s --get --data-urlencode "cmd=rm ${{CANARY_PATH}}"'
        f' {_FLASK_URL}/compile'
    )
    result = verify(_rce_candidate(), flask_rce_container, poc)

    assert result.status == "confirmed", (
        f"Expected confirmed but got {result.status!r}: {result.evidence}"
    )
    assert "deleted" in result.evidence


def test_rce_canary_modified_via_write(flask_rce_container):
    """
    PoC writes a new value into the canary file instead of deleting it.
    Verifier detects content change → confirmed.
    """
    poc = (
        f'curl -s --get --data-urlencode "cmd=echo PWNED > ${{CANARY_PATH}}"'
        f' {_FLASK_URL}/compile'
    )
    result = verify(_rce_candidate(), flask_rce_container, poc)

    assert result.status == "confirmed", (
        f"Expected confirmed but got {result.status!r}: {result.evidence}"
    )
    assert "modified" in result.evidence


def test_safe_poc_yields_suspected(flask_rce_container):
    """
    PoC reaches the server but asks it to run 'echo noop' — canary untouched.
    Verifier returns suspected (PoC ran OK, no evidence of exploitation).
    """
    poc = f'curl -s "{_FLASK_URL}/compile?cmd=echo+noop"'
    result = verify(_rce_candidate(), flask_rce_container, poc)

    assert result.status == "suspected", (
        f"Expected suspected but got {result.status!r}: {result.evidence}"
    )


def test_bad_endpoint_yields_false_positive(flask_rce_container):
    """
    PoC hits a non-existent endpoint → curl exits non-zero, canary untouched.
    Verifier returns false_positive.
    """
    poc = f'curl -sf "{_FLASK_URL}/nonexistent_route_404"'
    result = verify(_rce_candidate(), flask_rce_container, poc)

    assert result.status == "false_positive", (
        f"Expected false_positive but got {result.status!r}: {result.evidence}"
    )
