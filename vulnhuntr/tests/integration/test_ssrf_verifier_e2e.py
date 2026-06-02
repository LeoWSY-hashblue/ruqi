import urllib.parse
import urllib.request

from vulnhuntr.candidate import Candidate
from vulnhuntr.ssrf_verifier import verify_ssrf
from vulnhuntr.tests.fixtures.ssrf_fixture_app.app import SSRFFixtureServer


def _candidate(sink_type="ssrf") -> Candidate:
    return Candidate(
        file="fixture.py",
        line=1,
        sink_type=sink_type,
        semgrep_rule_id="test.ssrf",
        code_snippet="urlopen(url)",
        enclosing_symbol="fetch",
        enclosing_source="def fetch(url): ...",
    )


def _target_get(url: str) -> int:
    try:
        response = urllib.request.urlopen(url, timeout=5)
        response.read()
        return 0 if 200 <= response.status < 300 else 1
    except Exception:
        return 1


def test_direct_callback_is_confirmed():
    with SSRFFixtureServer() as fixture:
        def poc(target_base_url, callback_url, redirect_url):
            target = target_base_url + "/fetch?" + urllib.parse.urlencode({"url": callback_url})
            return _target_get(target)

        result = verify_ssrf(_candidate(), fixture.base_url, poc)

    assert result.status == "confirmed"
    assert "/callback/" in result.evidence


def test_redirect_to_canary_is_confirmed():
    with SSRFFixtureServer() as fixture:
        def poc(target_base_url, callback_url, redirect_url):
            target = target_base_url + "/fetch-redirect?" + urllib.parse.urlencode({"url": redirect_url})
            return _target_get(target)

        result = verify_ssrf(_candidate(), fixture.base_url, poc)

    assert result.status == "confirmed"
    assert "/canary/" in result.evidence


def test_safe_no_callback_is_suspected():
    with SSRFFixtureServer() as fixture:
        def poc(target_base_url, callback_url, redirect_url):
            return _target_get(target_base_url + "/safe")

        result = verify_ssrf(_candidate(), fixture.base_url, poc, wait_timeout=0.1)

    assert result.status == "suspected"


def test_poc_failure_is_false_positive():
    with SSRFFixtureServer() as fixture:
        def poc(target_base_url, callback_url, redirect_url):
            return _target_get(target_base_url + "/reject")

        result = verify_ssrf(_candidate(), fixture.base_url, poc, wait_timeout=0.1)

    assert result.status == "false_positive"


def test_non_ssrf_candidate_is_false_positive():
    with SSRFFixtureServer() as fixture:
        result = verify_ssrf(_candidate(sink_type="rce"), fixture.base_url, lambda _target, _callback, _redirect: 0)

    assert result.status == "false_positive"
