import ast
import json
import os
import subprocess
from pathlib import Path
from typing import Callable

from vulnhuntr.__main__ import RepoOps
from vulnhuntr.candidate import Candidate
from vulnhuntr.candidate import SinkType

SEMGREP_RULE_TO_SINK: dict[str, SinkType] = {
    'python.lang.security.audit.eval-detected.eval-detected': 'rce',
    'python.lang.security.audit.exec-detected.exec-detected': 'rce',
    'python.lang.security.audit.subprocess-shell-true.subprocess-shell-true': 'rce',
    'python.lang.security.audit.formatted-sql-query.formatted-sql-query': 'sqli',
    'python.requests.security.disabled-cert-validation.disabled-cert-validation': 'ssrf',
}

SemgrepRunner = Callable[[Path], subprocess.CompletedProcess[str]]


class _EnclosingNodeFinder(ast.NodeVisitor):
    def __init__(self, line: int) -> None:
        self.line = line
        self.best_stack: list[ast.AST] = []
        self.current_stack: list[ast.AST] = []

    def visit(self, node: ast.AST) -> None:
        if not self._contains_line(node):
            return

        is_symbol = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        if is_symbol:
            self.current_stack.append(node)
            if len(self.current_stack) >= len(self.best_stack):
                self.best_stack = list(self.current_stack)

        super().visit(node)

        if is_symbol:
            self.current_stack.pop()

    def _contains_line(self, node: ast.AST) -> bool:
        start = getattr(node, 'lineno', None)
        end = getattr(node, 'end_lineno', None)
        if start is None:
            return True
        if end is None:
            end = start
        return start <= self.line <= end


def _run_semgrep_command(repo_path: Path) -> subprocess.CompletedProcess[str]:
    semgrep_home = repo_path / '.semgrep'
    semgrep_cache = semgrep_home / 'cache'
    semgrep_home.mkdir(exist_ok=True)
    semgrep_cache.mkdir(exist_ok=True)
    env = dict(os.environ)
    env['XDG_CONFIG_HOME'] = str(semgrep_home)
    env['XDG_CACHE_HOME'] = str(semgrep_cache)
    env['SEMGREP_LOG_FILE'] = str(semgrep_home / 'semgrep.log')
    env['SEMGREP_SETTINGS_FILE'] = str(semgrep_home / 'settings.yml')

    return subprocess.run(
        ['semgrep', '--config=p/security-audit', '--json', '--quiet'],
        cwd=repo_path,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        check=True,
        env=env,
    )


def _allowed_repo_paths(repo_path: Path) -> set[str]:
    repo = RepoOps(repo_path)
    return {path.relative_to(repo_path).as_posix() for path in repo.get_relevant_py_files()}


def _extract_code_snippet(file_path: Path, line: int, radius: int = 5) -> str:
    lines = file_path.read_text(encoding='utf-8', errors='ignore').splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return '\n'.join(lines[start:end])


def _node_source(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    if segment is not None:
        return segment

    start = getattr(node, 'lineno', None)
    end = getattr(node, 'end_lineno', None)
    if start is None or end is None:
        return ''

    lines = source.splitlines()
    return '\n'.join(lines[start - 1:end])


def _extract_enclosing_context(file_path: Path, line: int) -> tuple[str, str]:
    source = file_path.read_text(encoding='utf-8', errors='ignore')
    tree = ast.parse(source)
    finder = _EnclosingNodeFinder(line)
    finder.visit(tree)

    if not finder.best_stack:
        return '', ''

    symbol = '.'.join(getattr(node, 'name', '') for node in finder.best_stack if getattr(node, 'name', ''))
    enclosing_source = _node_source(source, finder.best_stack[-1])
    return symbol, enclosing_source


def _candidate_from_result(repo_path: Path, result: dict, allowed_paths: set[str]) -> Candidate | None:
    rule_id = result.get('check_id', '')
    sink_type = SEMGREP_RULE_TO_SINK.get(rule_id)
    if sink_type is None:
        return None

    relative_path = Path(result['path']).as_posix()
    if relative_path not in allowed_paths:
        return None

    file_path = repo_path / relative_path
    line = int(result['start']['line'])
    code_snippet = _extract_code_snippet(file_path, line)
    enclosing_symbol, enclosing_source = _extract_enclosing_context(file_path, line)

    return Candidate(
        file=relative_path,
        line=line,
        sink_type=sink_type,
        semgrep_rule_id=rule_id,
        code_snippet=code_snippet,
        enclosing_symbol=enclosing_symbol,
        enclosing_source=enclosing_source,
    )


def run_semgrep(repo_path: Path, runner: SemgrepRunner | None = None) -> list[Candidate]:
    repo_path = repo_path.resolve()
    runner = runner or _run_semgrep_command
    completed = runner(repo_path)
    payload = json.loads(completed.stdout)
    allowed_paths = _allowed_repo_paths(repo_path)

    candidates: set[Candidate] = set()
    for result in payload.get('results', []):
        candidate = _candidate_from_result(repo_path, result, allowed_paths)
        if candidate is not None:
            candidates.add(candidate)

    return sorted(candidates, key=lambda item: (item.file, item.line, item.semgrep_rule_id))
