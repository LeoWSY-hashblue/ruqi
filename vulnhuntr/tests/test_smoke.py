import json
import sys
from pathlib import Path
from types import SimpleNamespace

from vulnhuntr import prompts
from vulnhuntr.LLMs import LLM
import vulnhuntr.__main__ as main_mod
from vulnhuntr.symbol_finder import SymbolExtractor


class DummyLLM(LLM):
    def __init__(self, response_text):
        super().__init__()
        self.response_text = response_text

    def create_messages(self, user_prompt):
        return [{"role": "user", "content": user_prompt}]

    def send_message(self, messages, max_tokens, response_model):
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))

    def get_response(self, response):
        return self.response_text


class LoopingLLM:
    def __init__(self):
        self.calls = []
        self.analysis_calls = 0
        self.secondary_calls = 0

    def chat(self, user_prompt, response_model=None, max_tokens=4096):
        self.calls.append((user_prompt, response_model, max_tokens))
        if response_model is None:
            return "<summary>minimal test repo</summary>"

        self.analysis_calls += 1
        if self.analysis_calls == 1:
            return main_mod.Response(
                scratchpad="initial",
                analysis="initial",
                poc="None",
                confidence_score=8,
                vulnerability_types=[main_mod.VulnType.RCE],
                context_code=[],
            )

        self.secondary_calls += 1
        return main_mod.Response(
            scratchpad="secondary",
            analysis="secondary",
            poc="None",
            confidence_score=8,
            vulnerability_types=[main_mod.VulnType.RCE],
            context_code=[
                main_mod.ContextCode(
                    name="Foo.bar",
                    reason="keep requesting the same context",
                    code_line="foo.bar()",
                )
            ],
        )


class FakeSymbolExtractor:
    def __init__(self):
        self.calls = []

    def extract(self, symbol_name, code_line, filtered_files):
        self.calls.append((symbol_name, code_line, tuple(Path(path).name for path in filtered_files)))
        return {
            "name": "bar",
            "context_name_requested": symbol_name,
            "file_path": str(filtered_files[0]),
            "source": "def bar(self):\n    return 'bar'\n",
        }


def test_network_pattern_filter(make_repo):
    repo_root = make_repo(
        {
            "route_entry.py": '''
                from flask import Flask

                app = Flask(__name__)

                @app.route("/ping")
                def ping():
                    return "ok"
            ''',
            "main_entry.py": '''
                from flask import Flask

                app = Flask(__name__)

                def main():
                    app.run(host="0.0.0.0", port=8000)
            ''',
            "socket_bind.py": '''
                import socket

                sock = socket.socket()
                sock.bind(("127.0.0.1", 8080))
            ''',
        }
    )

    repo = main_mod.RepoOps(repo_root)
    files = repo.get_relevant_py_files()

    assert {path.name for path in repo.get_network_related_files(files)} == {
        "route_entry.py",
        "main_entry.py",
    }


def test_symbol_extractor_basic(make_repo):
    repo_root = make_repo(
        {
            "symbols.py": '''
                class Foo:
                    def bar(self):
                        return "bar"

                def baz():
                    return "baz"

                foo = Foo()
                foo.bar()
                baz()
            '''
        }
    )
    symbol_file = repo_root / "symbols.py"
    extractor = SymbolExtractor(repo_root)

    bar_match = extractor.extract("bar", "foo.bar()", [symbol_file])
    baz_match = extractor.extract("baz", "baz()", [symbol_file])

    assert bar_match["file_path"] == str(symbol_file)
    assert "def bar(self):" in bar_match["source"]
    assert "return \"bar\"" in bar_match["source"]

    assert baz_match["file_path"] == str(symbol_file)
    assert "def baz():" in baz_match["source"]
    assert "return \"baz\"" in baz_match["source"]


def test_initial_analysis_returns_response_shape():
    payload = json.dumps(
        {
            "scratchpad": "step one",
            "analysis": "looks reachable",
            "poc": "curl http://target",
            "confidence_score": 7,
            "vulnerability_types": ["RCE"],
            "context_code": [
                {
                    "name": "Foo.bar",
                    "reason": "trace the sink",
                    "code_line": "foo.bar()",
                }
            ],
        }
    )
    llm = DummyLLM(payload)

    report = llm.chat("analyze", response_model=main_mod.Response)

    assert isinstance(report, main_mod.Response)
    assert report.confidence_score == 7
    assert report.vulnerability_types == [main_mod.VulnType.RCE]
    assert report.context_code[0].name == "Foo.bar"


def test_secondary_analysis_loop_terminates(make_repo, monkeypatch):
    repo_root = make_repo(
        {
            "README.md": "# Demo\n",
            "app.py": '''
                from flask import Flask

                app = Flask(__name__)

                @app.route("/ping")
                def ping():
                    return "ok"
            ''',
        }
    )
    fake_llm = LoopingLLM()
    fake_extractor = FakeSymbolExtractor()

    monkeypatch.setattr(main_mod, "initialize_llm", lambda llm_arg, system_prompt="": fake_llm)
    monkeypatch.setattr(main_mod, "SymbolExtractor", lambda repo_path: fake_extractor)
    monkeypatch.setattr(main_mod, "print_readable", lambda report: None)
    monkeypatch.setattr(sys, "argv", ["vulnhuntr", "-r", str(repo_root)])

    main_mod.run()

    assert fake_llm.secondary_calls == 4
    assert fake_llm.analysis_calls == 5
    assert len(fake_llm.calls) == 6
    assert len(fake_extractor.calls) == 1


def test_bypass_list_no_concat_bug():
    bypasses = prompts.VULN_SPECIFIC_BYPASSES_AND_PROMPTS["LFI"]["bypasses"]

    assert bypasses == [
        "../../../../etc/passwd",
        "/proc/self/environ",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "file:///etc/passwd",
        "C:\\win.ini",
        "/?../../../../../../../etc/passwd",
    ]
