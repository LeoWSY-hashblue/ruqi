import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnhuntr.__main__ import RepoOps

ROUTE_DECORATOR_PATTERNS = [
    re.compile(r"^\s*@app\.route", re.MULTILINE),
    re.compile(r"^\s*@router\.", re.MULTILINE),
    re.compile(r"^\s*@api\.", re.MULTILINE),
    re.compile(r"^\s*@get\b", re.MULTILINE),
    re.compile(r"^\s*@post\b", re.MULTILINE),
]
REQUEST_PARAM_PATTERN = re.compile(r"(?:async\s+)?def\s+\w+\([^)]*\brequest\b", re.MULTILINE)
WEB_IMPORT_PATTERN = re.compile(r"^\s*(?:from|import)\s+(?:flask|fastapi|django|starlette|aiohttp)\b", re.MULTILINE)
SINK_PATTERNS = {
    "subprocess": re.compile(r"\bsubprocess\b"),
    "eval": re.compile(r"\beval\s*\("),
    "exec": re.compile(r"\bexec\s*\("),
    "os.system": re.compile(r"\bos\.system\s*\("),
    "sqlalchemy": re.compile(r"\bsqlalchemy\b"),
    "requests.get": re.compile(r"\brequests\.get\s*\("),
}


def scan_file(path: Path) -> dict:
    content = path.read_text(encoding="utf-8", errors="ignore")
    checks = {
        "route_decorator": any(pattern.search(content) for pattern in ROUTE_DECORATOR_PATTERNS),
        "request_param": bool(REQUEST_PARAM_PATTERN.search(content)),
        "web_import": bool(WEB_IMPORT_PATTERN.search(content)),
        "sink_keywords": [name for name, pattern in SINK_PATTERNS.items() if pattern.search(content)],
    }
    return checks


def filter_reasons(repo: RepoOps, path: Path) -> list[str]:
    rel_parts = [part.lower() for part in path.relative_to(repo.repo_path).parts[:-1]]
    reasons = [f"dir:{part}" for part in rel_parts if part in repo.EXCLUDE_DIRS]

    file_name = path.name.lower()
    if file_name in repo.EXCLUDE_FILE_NAMES:
        reasons.append(f"file:{file_name}")
    if file_name.startswith("test_"):
        reasons.append("pattern:test_*.py")
    if file_name.endswith("_test.py"):
        reasons.append("pattern:*_test.py")

    return reasons


def audit_repo(repo_path: Path) -> dict:
    repo = RepoOps(repo_path)
    all_files = sorted(repo_path.rglob("*.py"))
    kept_files = sorted(repo.get_relevant_py_files())
    kept_set = {path.resolve() for path in kept_files}
    filtered_files = [path for path in all_files if path.resolve() not in kept_set]

    suspicious_files = []
    for path in filtered_files:
        checks = scan_file(path)
        trigger_any = checks["route_decorator"] or checks["request_param"] or checks["web_import"]
        if trigger_any and checks["sink_keywords"]:
            suspicious_files.append(
                {
                    "path": path.relative_to(repo_path).as_posix(),
                    "checks": {
                        "route_decorator": checks["route_decorator"],
                        "request_param": checks["request_param"],
                        "web_import": checks["web_import"],
                        "sink_keywords": checks["sink_keywords"],
                    },
                    "filter_reasons": filter_reasons(repo, path),
                }
            )

    return {
        "repo_path": str(repo_path.resolve()),
        "all_py_files": len(all_files),
        "kept_py_files": len(kept_files),
        "filtered_py_files": len(filtered_files),
        "suspicious_filtered_files": len(suspicious_files),
        "suspicious_files": suspicious_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit RepoOps path filtering against all Python files in a repository.")
    parser.add_argument("repo_path", type=Path, help="Path to the local repository to audit")
    args = parser.parse_args()

    result = audit_repo(args.repo_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
