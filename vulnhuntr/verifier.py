"""
Dynamic verification layer - RCE only (v1).

Flow:
  1. Caller creates a Docker container with the target app.
  2. Caller calls verify(candidate, container_id, poc).
  3. verifier pre-plants a canary file inside a world-writable container directory.
  4. verifier executes the PoC (a shell command) inside the container.
  5. Verdict is determined solely by whether the canary was modified/deleted.
     LLM output is NOT used for verdict - only filesystem evidence.

Only RCE sink_type is handled. Other types raise NotImplementedError (v2).
"""

from __future__ import annotations

import shlex
import subprocess
import uuid
from dataclasses import dataclass

from vulnhuntr.candidate import Candidate


# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    status: str          # "confirmed" | "suspected" | "false_positive"
    evidence: str        # human-readable description of what was observed
    canary_path: str     # /tmp/vulnhuntr_canary_<uuid>/canary that was planted


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DOCKER_EXEC_TIMEOUT = 30   # seconds per docker exec call


def _docker_exec(container_id: str, cmd: list[str]) -> tuple[int, str, str]:
    """Run `docker exec <container_id> <cmd>` and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        ["docker", "exec", container_id, *cmd],
        capture_output=True,
        text=True,
        timeout=_DOCKER_EXEC_TIMEOUT,
    )
    return result.returncode, result.stdout, result.stderr


def _plant_canary(container_id: str) -> str:
    """
    Create a world-writable canary file inside the container and return its path.
    The file lives in a world-writable directory so non-root processes can delete
    it, and the file itself is world-writable so non-root processes can modify it.
    """
    canary_dir = f"/tmp/vulnhuntr_canary_{uuid.uuid4().hex}"
    canary_path = f"{canary_dir}/canary"
    sentinel = "VULNHUNTR_CANARY_UNTOUCHED"
    canary_dir_q = shlex.quote(canary_dir)
    canary_path_q = shlex.quote(canary_path)
    sentinel_q = shlex.quote(sentinel)
    plant_cmd = (
        f"mkdir -p {canary_dir_q} && "
        f"chmod 777 {canary_dir_q} && "
        f"printf %s {sentinel_q} > {canary_path_q} && "
        f"chmod 666 {canary_path_q}"
    )
    rc, _, err = _docker_exec(container_id, ["sh", "-c", plant_cmd])
    if rc != 0:
        raise RuntimeError(f"Failed to plant canary in {container_id}: {err.strip()}")
    return canary_path


def _read_canary(container_id: str, canary_path: str) -> tuple[bool, str]:
    """
    Return (exists, content).  content is "" if the file does not exist.
    """
    canary_path_q = shlex.quote(canary_path)
    read_cmd = f"if [ -e {canary_path_q} ]; then cat {canary_path_q}; else exit 42; fi"
    rc, stdout, _ = _docker_exec(container_id, ["sh", "-c", read_cmd])
    if rc != 0:
        return False, ""
    return True, stdout.strip()


def _execute_poc(container_id: str, poc: str) -> tuple[int, str, str]:
    """
    Execute the PoC shell command inside the container.
    Returns (returncode, stdout, stderr).
    """
    return _docker_exec(container_id, ["sh", "-c", poc])


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def _determine_verdict(
    canary_path: str,
    existed_before: bool,
    content_before: str,
    existed_after: bool,
    content_after: str,
    poc_rc: int,
    poc_stderr: str,
) -> VerifyResult:
    """
    Determines verdict from canary state changes only - no LLM involvement.

    confirmed      : canary was deleted OR its content changed
    suspected      : PoC ran without error but canary is unchanged
                     (might need more complex payload)
    false_positive : PoC failed immediately (command not found, permission
                     denied before canary could be touched)
    """
    if not existed_before:
        # Shouldn't happen; treat as infrastructure failure
        return VerifyResult(
            status="false_positive",
            evidence="Canary file was not planted successfully before PoC execution.",
            canary_path=canary_path,
        )

    # Canary deleted - unambiguous RCE evidence
    if not existed_after:
        return VerifyResult(
            status="confirmed",
            evidence=f"Canary file {canary_path} was deleted by PoC execution.",
            canary_path=canary_path,
        )

    # Canary content changed - also strong evidence
    if content_after != content_before:
        return VerifyResult(
            status="confirmed",
            evidence=(
                f"Canary file {canary_path} was modified by PoC execution. "
                f"Before: {content_before!r}  After: {content_after!r}"
            ),
            canary_path=canary_path,
        )

    # PoC exited with error before reaching the sink
    if poc_rc != 0:
        return VerifyResult(
            status="false_positive",
            evidence=(
                f"PoC exited with code {poc_rc} and canary was not modified. "
                f"stderr: {poc_stderr.strip()[:200]}"
            ),
            canary_path=canary_path,
        )

    # PoC ran OK but canary untouched - partial / needs refinement
    return VerifyResult(
        status="suspected",
        evidence=(
            "PoC ran without error but canary was not modified. "
            "The payload may need to be refined or the code path was not reached."
        ),
        canary_path=canary_path,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify(candidate: Candidate, container_id: str, poc: str) -> VerifyResult:
    """
    Verify whether `poc` achieves RCE inside the given Docker container.

    Parameters
    ----------
    candidate     : Candidate object identifying the sink being tested.
    container_id  : Docker container ID or name.  Must already be running.
    poc           : Shell command to execute as the proof-of-concept.
                    The PoC should reach the vulnerable code path and
                    attempt to delete or modify the canary file.
                    The canary path is injected as the env var CANARY_PATH.

    Returns
    -------
    VerifyResult with status one of {"confirmed", "suspected", "false_positive"}.

    Raises
    ------
    NotImplementedError  : If candidate.sink_type is not "rce".
    RuntimeError         : If Docker commands fail unexpectedly.
    """
    if candidate.sink_type != "rce":
        raise NotImplementedError(
            f"verify() currently only supports sink_type='rce', got {candidate.sink_type!r}. "
            "SSRF/SQLi/path_traversal verification planned for v2."
        )

    # Plant canary
    canary_path = _plant_canary(container_id)

    # Read initial state
    existed_before, content_before = _read_canary(container_id, canary_path)

    # Inject canary path into PoC as env var so the PoC can reference it
    poc_with_canary = f"export CANARY_PATH={shlex.quote(canary_path)}; {poc}"
    poc_rc, _poc_stdout, poc_stderr = _execute_poc(container_id, poc_with_canary)

    # Read final state
    existed_after, content_after = _read_canary(container_id, canary_path)

    return _determine_verdict(
        canary_path,
        existed_before, content_before,
        existed_after, content_after,
        poc_rc, poc_stderr,
    )
