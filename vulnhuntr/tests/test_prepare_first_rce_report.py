from pathlib import Path

from vulnhuntr.candidate import Candidate
from vulnhuntr.scripts.prepare_first_rce_report import render_report


def test_render_report_includes_candidate_inventory_and_not_run_statuses():
    report = render_report(
        target_repo=Path("E:/tool/gpt_academic"),
        target_commit="abc123",
        generated_at="2026-06-01T08:30:00Z",
        candidates=[
            Candidate(
                file="crazy_functions/rag_fns/rag_file_support.py",
                line=22,
                sink_type="rce",
                semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                code_snippet="subprocess.run(command, shell=True, check=True)",
                enclosing_symbol="convert_to_markdown",
                enclosing_source="",
            )
        ],
    )

    assert "Candidate count: 1" in report
    assert "crazy_functions/rag_fns/rag_file_support.py" in report
    assert "line: 22" in report
    assert "Verification Status: Not run" in report
    assert "LLM Call Chain Reconstruction: Not run" in report
    assert "Use an LLM to reconstruct the call chain" in report
    assert "Draft a PoC for each candidate" in report
    assert "Run the verifier in an isolated Docker container" in report
    assert "Move only confirmed findings into a CVE report" in report


def test_render_report_keeps_candidate_code_blocks_separate():
    report = render_report(
        target_repo=Path("E:/tool/gpt_academic"),
        target_commit="abc123",
        generated_at="2026-06-01T08:30:00Z",
        candidates=[
            Candidate(
                file="first.py",
                line=1,
                sink_type="rce",
                semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                code_snippet="subprocess.Popen(command, shell=True)",
                enclosing_symbol="first",
                enclosing_source="",
            ),
            Candidate(
                file="second.py",
                line=2,
                sink_type="rce",
                semgrep_rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                code_snippet="subprocess.run(command, shell=True)",
                enclosing_symbol="second",
                enclosing_source="",
            ),
        ],
    )

    assert report.count("```") == 4
    assert report.count("```python") == 2

    candidate_1 = report.index("### Candidate 1")
    candidate_2 = report.index("### Candidate 2")
    first_open = report.index("```python")
    first_close = report.index("\n```\n", first_open + len("```python"))
    first_code_block = report[first_open:first_close + len("\n```")]

    assert candidate_1 < first_open
    assert first_close < candidate_2
    assert "### Candidate 2" not in first_code_block
    assert candidate_2 > first_close


def test_render_report_filters_non_rce_candidates():
    report = render_report(
        target_repo=Path("E:/tool/gpt_academic"),
        target_commit="abc123",
        generated_at="2026-06-01T08:30:00Z",
        candidates=[
            Candidate(
                file="app.py",
                line=10,
                sink_type="sqli",
                semgrep_rule_id="python.sql",
                code_snippet="query = f'SELECT {name}'",
                enclosing_symbol="query",
                enclosing_source="",
            )
        ],
    )

    assert "Candidate count: 0" in report
    assert "No RCE candidates were produced by Semgrep intake." in report
    assert "app.py" not in report
