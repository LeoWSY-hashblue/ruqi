import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnhuntr.semgrep_intake import run_semgrep


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Semgrep and emit normalized Candidate JSON.")
    parser.add_argument("repo_path", type=Path, help="Path to the repository to scan")
    args = parser.parse_args()

    candidates = [asdict(candidate) for candidate in run_semgrep(args.repo_path)]
    print(json.dumps(candidates, indent=2))


if __name__ == "__main__":
    main()
