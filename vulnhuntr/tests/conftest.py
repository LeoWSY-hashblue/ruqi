from pathlib import Path
import textwrap

import pytest


@pytest.fixture
def make_repo(tmp_path_factory):
    def _make_repo(files):
        repo_root = tmp_path_factory.mktemp("repo")
        for relative_path, content in files.items():
            file_path = repo_root / relative_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
        return repo_root

    return _make_repo
