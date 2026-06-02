import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnhuntr.candidate import Candidate
from vulnhuntr.ssrf_verifier import verify_ssrf


MODES = ("browser-redirect", "notification-redirect")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Skeleton runner for changedetection.io SSRF verifier experiments. "
            "Does not start changedetection.io or Docker."
        )
    )
    parser.add_argument("--target-base-url", required=True, help="Base URL of an already-running changedetection.io instance.")
    parser.add_argument("--mode", required=True, choices=MODES, help="Experiment mode to prepare.")
    parser.add_argument("--api-key", default=None, help="Optional changedetection.io API key.")
    return parser


def make_candidate(mode: str) -> Candidate:
    return Candidate(
        file="changedetection.io",
        line=0,
        sink_type="ssrf",
        semgrep_rule_id=f"manual.changedetection.{mode}",
        code_snippet="manual SSRF guard parity experiment",
        enclosing_symbol=mode,
        enclosing_source="manual experiment skeleton",
    )


def browser_redirect_poc(target_base_url: str, callback_url: str, redirect_url: str) -> int:
    raise NotImplementedError(
        "browser-redirect PoC is not implemented until watch API/auth/browser fetcher details are confirmed."
    )


def notification_redirect_poc(target_base_url: str, callback_url: str, redirect_url: str) -> int:
    raise NotImplementedError(
        "notification-redirect PoC is not implemented until notification API/auth payload details are confirmed."
    )


def poc_for_mode(mode: str):
    if mode == "browser-redirect":
        return browser_redirect_poc
    if mode == "notification-redirect":
        return notification_redirect_poc
    raise ValueError(f"Unsupported mode: {mode}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    candidate = make_candidate(args.mode)
    poc = poc_for_mode(args.mode)
    result = verify_ssrf(candidate, args.target_base_url, poc)
    print(result.status)
    print(result.evidence)
    return 2 if result.status == "false_positive" else 0


if __name__ == "__main__":
    raise SystemExit(main())
