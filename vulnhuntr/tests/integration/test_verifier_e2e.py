"""
End-to-end verifier tests using the vulnerable stdlib HTTP fixture.

Requires a running Docker daemon. Skipped automatically if Docker is unavailable.

Flow:
    1. Build the fixture image (cached after first run).
    2. Start container (detached, --rm).
    3. Wait for /health to respond.
    4. Run verify() with a real canary and real PoC.
    5. Assert verdict; tear down container.
"""

import shlex
import subprocess
import time
from pathlib import Path

import pytest

from vulnhuntr.candidate import Candidate
from vulnhuntr.verifier import verify

_FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app"
_IMAGE_TAG = "vulnhuntr-test-stdlib-rce:latest"
_APP_URL = "http://127.0.0.1:5000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _exec_in(container_id: str, cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        ["docker", "exec", container_id, *cmd],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode, result.stdout + result.stderr


def _urlopen_command(url: str) -> list[str]:
    code = (
        "import urllib.request; "
        f"urllib.request.urlopen({url!r}, timeout=5).read()"
    )
    return ["python", "-c", code]


def _poc_for_compile(command_expr: str) -> str:
    code = (
        "import os, urllib.parse, urllib.request; "
        f"cmd = {command_expr}; "
        f"url = {_APP_URL!r} + '/compile?' + urllib.parse.urlencode({{'cmd': cmd}}); "
        "urllib.request.urlopen(url, timeout=5).read()"
    )
    return "python -c " + shlex.quote(code)


def _bad_endpoint_poc() -> str:
    code = (
        "import urllib.request; "
        f"urllib.request.urlopen({_APP_URL + '/nonexistent_route_404'!r}, timeout=5).read()"
    )
    return "python -c " + shlex.quote(code)


def _wait_for_app(container_id: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, _ = _exec_in(container_id, _urlopen_command(f"{_APP_URL}/health"))
        if rc == 0:
            return True
        time.sleep(0.4)
    return False


def _rce_candidate() -> Candidate:
    return Candidate(
        file="app.py",
        line=24,
        sink_type="rce",
        semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        code_snippet="subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)",
        enclosing_symbol="do_GET",
        enclosing_source=(
            "def do_GET(self):\n"
            "    cmd = parse_qs(parsed.query).get('cmd', ['echo noop'])[0]\n"
            "    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)\n"
            "    self._send(200, result.stdout or result.stderr)"
        ),
    )


# ---------------------------------------------------------------------------
# Module-scoped fixture: one non-root container for all tests in this file
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rce_container():
    if not _docker_available():
        pytest.skip("Docker daemon not reachable - skipping verifier e2e tests")

    subprocess.run(
        ["docker", "build", "-t", _IMAGE_TAG, str(_FIXTURE_DIR)],
        check=True,
        capture_output=True,
    )

    result = subprocess.run(
        ["docker", "run", "-d", "--rm", _IMAGE_TAG],
        check=True,
        capture_output=True,
        text=True,
    )
    container_id = result.stdout.strip()

    if not _wait_for_app(container_id):
        subprocess.run(["docker", "stop", container_id], capture_output=True)
        pytest.fail("Fixture app did not become ready within 20 s")

    yield container_id

    subprocess.run(["docker", "stop", container_id], capture_output=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rce_confirmed_canary_deleted(rce_container):
    """
    PoC routes cmd=rm $CANARY_PATH through /compile.
    The non-root app process deletes the canary, so verifier returns confirmed.
    """
    poc = _poc_for_compile("'rm ' + os.environ['CANARY_PATH']")
    result = verify(_rce_candidate(), rce_container, poc)

    assert result.status == "confirmed", (
        f"Expected confirmed but got {result.status!r}: {result.evidence}"
    )
    assert "deleted" in result.evidence


def test_rce_canary_modified_via_write(rce_container):
    """
    PoC writes a new value into the canary from the non-root app process.
    """
    poc = _poc_for_compile("'echo PWNED > ' + os.environ['CANARY_PATH']")
    result = verify(_rce_candidate(), rce_container, poc)

    assert result.status == "confirmed", (
        f"Expected confirmed but got {result.status!r}: {result.evidence}"
    )
    assert "modified" in result.evidence


def test_safe_poc_yields_suspected(rce_container):
    """
    PoC reaches the server but asks it to run echo noop; canary is untouched.
    """
    poc = _poc_for_compile("'echo noop'")
    result = verify(_rce_candidate(), rce_container, poc)

    assert result.status == "suspected", (
        f"Expected suspected but got {result.status!r}: {result.evidence}"
    )


def test_bad_endpoint_yields_false_positive(rce_container):
    """
    PoC hits a non-existent endpoint; urllib exits non-zero, canary is untouched.
    """
    result = verify(_rce_candidate(), rce_container, _bad_endpoint_poc())

    assert result.status == "false_positive", (
        f"Expected false_positive but got {result.status!r}: {result.evidence}"
    )
