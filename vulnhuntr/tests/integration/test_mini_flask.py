import shutil
import sys
from pathlib import Path

import vulnhuntr.__main__ as main_mod


class ScriptedLLM:
    def __init__(self):
        self.prompts = []
        self.call_index = 0

    def chat(self, user_prompt, response_model=None, max_tokens=4096):
        self.prompts.append(user_prompt)
        self.call_index += 1

        if self.call_index == 1:
            assert response_model is None
            return "<summary>mini flask fixture</summary>"

        if self.call_index == 2:
            return main_mod.Response(
                scratchpad="initial",
                analysis="potential LFI in route handler",
                poc="GET /read?path=../../../../etc/passwd",
                confidence_score=8,
                vulnerability_types=[main_mod.VulnType.LFI],
                context_code=[],
            )

        if self.call_index == 3:
            return main_mod.Response(
                scratchpad="need helper",
                analysis="requesting helper implementation",
                poc="GET /read?path=../../../../etc/passwd",
                confidence_score=8,
                vulnerability_types=[main_mod.VulnType.LFI],
                context_code=[
                    main_mod.ContextCode(
                        name="unsafe_open",
                        reason="Need the helper to confirm user-controlled file access",
                        code_line="return unsafe_open(user_path)",
                    )
                ],
            )

        if self.call_index == 4:
            return main_mod.Response(
                scratchpad="final",
                analysis="user-controlled input flows into open() without sanitization",
                poc="GET /read?path=../../../../etc/passwd",
                confidence_score=8,
                vulnerability_types=[main_mod.VulnType.LFI],
                context_code=[],
            )

        raise AssertionError(f"Unexpected LLM call: {self.call_index}")


def test_mini_flask_pipeline(tmp_path_factory, monkeypatch):
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures" / "mini_flask_app"
    repo_root = tmp_path_factory.mktemp("repo")

    for source in fixture_root.rglob("*"):
        if source.is_dir():
            continue
        destination = repo_root / source.relative_to(fixture_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    fake_llm = ScriptedLLM()
    reports = []

    monkeypatch.setattr(main_mod, "initialize_llm", lambda llm_arg, system_prompt="": fake_llm)
    monkeypatch.setattr(main_mod, "print_readable", reports.append)
    monkeypatch.setattr(sys, "argv", ["vulnhuntr", "-r", str(repo_root)])

    main_mod.run()

    assert len(fake_llm.prompts) == 4
    assert "def unsafe_open(path):" in fake_llm.prompts[3]
    assert 'with open(path, "r", encoding="utf-8") as handle:' in fake_llm.prompts[3]
    assert reports[-1].vulnerability_types == [main_mod.VulnType.LFI]
    assert reports[-1].context_code == []
    assert reports[-1].confidence_score == 8
