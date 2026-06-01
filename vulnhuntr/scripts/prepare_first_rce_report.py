import argparse
import shutil
import subprocess
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnhuntr.candidate import Candidate
from vulnhuntr.semgrep_intake import run_semgrep


def _append_candidate_section(lines: list[str], index: int, candidate: Candidate) -> None:
    lines.extend(
        [
            f"### Candidate {index}",
            "",
            f"- file: `{candidate.file}`",
            f"- line: {candidate.line}",
            f"- sink_type: `{candidate.sink_type}`",
            f"- semgrep_rule_id: `{candidate.semgrep_rule_id}`",
            f"- enclosing_symbol: `{candidate.enclosing_symbol}`",
            "- code_snippet:",
            "",
            "```python",
        ]
    )
    snippet_lines = candidate.code_snippet.strip("\n").splitlines()
    lines.extend(snippet_lines or [""])
    lines.extend(["```", ""])


def get_target_commit(target_repo: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target_repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return completed.stdout.strip()


def cleanup_semgrep_state(target_repo: Path) -> None:
    resolved_target = target_repo.resolve()
    semgrep_dir = resolved_target / ".semgrep"
    if not semgrep_dir.exists():
        return
    if semgrep_dir.parent != resolved_target or semgrep_dir.name != ".semgrep":
        raise ValueError(f"Refusing to remove unexpected Semgrep path: {semgrep_dir}")
    shutil.rmtree(semgrep_dir)


def render_report(
    *,
    target_repo: Path,
    target_commit: str,
    generated_at: str,
    candidates: Iterable[Candidate],
) -> str:
    rce_candidates = [candidate for candidate in candidates if candidate.sink_type == "rce"]
    lines = [
        "# First RCE Candidate Report",
        "",
        "This report is a reproducible candidate inventory. Findings are unconfirmed until verifier execution succeeds.",
        "",
        "## Target",
        "",
        f"- Target repo path: `{target_repo}`",
        f"- Target commit: `{target_commit}`",
        f"- Generated timestamp: `{generated_at}`",
        f"- Candidate count: {len(rce_candidates)}",
        "- Verification Status: Not run",
        "- LLM Call Chain Reconstruction: Not run",
        "",
        "## Candidates",
        "",
    ]

    if not rce_candidates:
        lines.extend(["No RCE candidates were produced by Semgrep intake.", ""])
    for index, candidate in enumerate(rce_candidates, start=1):
        _append_candidate_section(lines, index, candidate)

    lines.extend(
        [
            "## Next Manual Verification Plan",
            "",
            "1. Use an LLM to reconstruct the call chain from HTTP/API/plugin entrypoints to each sink.",
            "2. Draft a PoC for each candidate.",
            "3. Run the verifier in an isolated Docker container.",
            "4. Move only confirmed findings into a CVE report.",
            "",
        ]
    )
    return "\n".join(lines)


def prepare_report(target_repo: Path, output_path: Path) -> None:
    target_repo = target_repo.resolve()
    target_commit = get_target_commit(target_repo)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        candidates = run_semgrep(target_repo)
    finally:
        cleanup_semgrep_state(target_repo)

    report = render_report(
        target_repo=target_repo,
        target_commit=target_commit,
        generated_at=generated_at,
        candidates=candidates,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a first RCE candidate report without LLM or verifier execution.")
    parser.add_argument("--target-repo", type=Path, required=True, help="Path to the target repository")
    parser.add_argument("--output", type=Path, required=True, help="Markdown report output path")
    args = parser.parse_args()

    prepare_report(args.target_repo, args.output)


if __name__ == "__main__":
    main()
