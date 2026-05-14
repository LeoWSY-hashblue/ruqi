import json
from types import SimpleNamespace

from vulnhuntr.semgrep_intake import run_semgrep


class StubRunner:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def __call__(self, repo_path):
        self.calls.append(repo_path)
        return SimpleNamespace(stdout=json.dumps(self.payload))


def test_semgrep_intake_parses_mock_json(make_repo):
    repo_root = make_repo(
        {
            "app.py": '''
                def run_command(user_input):
                    eval(user_input)
            '''
        }
    )
    runner = StubRunner(
        {
            "results": [
                {
                    "path": "app.py",
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "start": {"line": 2},
                }
            ]
        }
    )

    candidates = run_semgrep(repo_root, runner=runner)

    assert len(candidates) == 1
    assert candidates[0].file == "app.py"
    assert candidates[0].line == 2
    assert candidates[0].sink_type == "rce"
    assert candidates[0].semgrep_rule_id == "python.lang.security.audit.eval-detected.eval-detected"
    assert "eval(user_input)" in candidates[0].code_snippet


def test_semgrep_intake_extracts_enclosing_function(make_repo):
    repo_root = make_repo(
        {
            "app.py": '''
                class Runner:
                    def execute(self, user_input):
                        eval(user_input)
            '''
        }
    )
    runner = StubRunner(
        {
            "results": [
                {
                    "path": "app.py",
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "start": {"line": 3},
                }
            ]
        }
    )

    candidates = run_semgrep(repo_root, runner=runner)

    assert candidates[0].enclosing_symbol == "Runner.execute"
    assert "def execute(self, user_input):" in candidates[0].enclosing_source
    assert "eval(user_input)" in candidates[0].enclosing_source


def test_semgrep_intake_handles_module_level_code(make_repo):
    repo_root = make_repo(
        {
            "app.py": '''
                eval("print(1)")
            '''
        }
    )
    runner = StubRunner(
        {
            "results": [
                {
                    "path": "app.py",
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "start": {"line": 1},
                }
            ]
        }
    )

    candidates = run_semgrep(repo_root, runner=runner)

    assert candidates[0].enclosing_symbol == ""
    assert candidates[0].enclosing_source == ""


def test_semgrep_intake_filters_excluded_dirs(make_repo):
    repo_root = make_repo(
        {
            "tests/risky.py": '''
                def run_command(user_input):
                    eval(user_input)
            ''',
            "app.py": '''
                def keep_me():
                    return "ok"
            ''',
        }
    )
    runner = StubRunner(
        {
            "results": [
                {
                    "path": "tests/risky.py",
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "start": {"line": 2},
                }
            ]
        }
    )

    assert run_semgrep(repo_root, runner=runner) == []


def test_semgrep_intake_drops_unknown_rules(make_repo):
    repo_root = make_repo(
        {
            "app.py": '''
                def run_command(user_input):
                    eval(user_input)
            '''
        }
    )
    runner = StubRunner(
        {
            "results": [
                {
                    "path": "app.py",
                    "check_id": "python.unknown.rule",
                    "start": {"line": 2},
                }
            ]
        }
    )

    assert run_semgrep(repo_root, runner=runner) == []
