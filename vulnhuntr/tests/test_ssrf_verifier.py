import urllib.request
from urllib.parse import parse_qs, urlparse

from vulnhuntr.candidate import Candidate
from vulnhuntr.ssrf_verifier import CallbackServer, verify_ssrf


def _candidate(sink_type="ssrf") -> Candidate:
    return Candidate(
        file="target.py",
        line=10,
        sink_type=sink_type,
        semgrep_rule_id="test.ssrf",
        code_snippet="requests.get(url)",
        enclosing_symbol="fetch",
        enclosing_source="def fetch(url): ...",
    )


def test_callback_server_records_tokenized_hit():
    with CallbackServer() as server:
        token = "unit-token"
        urllib.request.urlopen(server.callback_url(token), timeout=5).read()

        hits = server.wait_for_hit(token, timeout=0.5)

    assert len(hits) == 1
    assert hits[0].method == "GET"
    assert hits[0].path == f"/callback/{token}"
    assert len(hits[0].body_sha256) == 64


def test_redirect_url_encodes_complex_target_url():
    with CallbackServer() as server:
        target_url = "http://127.0.0.1/canary/token?x=1&y=two words"
        redirect_url = server.redirect_url("token", target_url)

    parsed = urlparse(redirect_url)
    assert parse_qs(parsed.query)["to"] == [target_url]


def test_verify_ssrf_confirmed_by_direct_callback():
    def poc(target_base_url, callback_url, redirect_url):
        assert target_base_url == "http://target.local"
        urllib.request.urlopen(callback_url, timeout=5).read()
        return 0

    result = verify_ssrf(_candidate(), "http://target.local", poc)

    assert result.status == "confirmed"
    assert "/callback/" in result.evidence


def test_verify_ssrf_confirmed_by_redirect_canary():
    def poc(target_base_url, callback_url, redirect_url):
        urllib.request.urlopen(redirect_url, timeout=5).read()
        return 0

    result = verify_ssrf(_candidate(), "http://target.local", poc)

    assert result.status == "confirmed"
    assert "/canary/" in result.evidence


def test_verify_ssrf_suspected_when_poc_succeeds_without_callback():
    result = verify_ssrf(_candidate(), "http://target.local", lambda _target, _callback, _redirect: 0, wait_timeout=0.1)

    assert result.status == "suspected"
    assert "no SSRF callback" in result.evidence


def test_verify_ssrf_false_positive_when_poc_fails():
    result = verify_ssrf(_candidate(), "http://target.local", lambda _target, _callback, _redirect: 1, wait_timeout=0.1)

    assert result.status == "false_positive"
    assert "code 1" in result.evidence


def test_verify_ssrf_false_positive_for_non_ssrf_candidate():
    result = verify_ssrf(_candidate(sink_type="rce"), "http://target.local", lambda _target, _callback, _redirect: 0)

    assert result.status == "false_positive"
    assert "Unsupported sink_type" in result.evidence


def test_verify_ssrf_token_isolation_with_reused_callback_server():
    with CallbackServer() as server:
        def first_poc(target_base_url, callback_url, redirect_url):
            urllib.request.urlopen(callback_url, timeout=5).read()
            return 0

        first = verify_ssrf(_candidate(), "http://target.local", first_poc, callback_server=server)

        def second_poc(target_base_url, callback_url, redirect_url):
            return 0

        second = verify_ssrf(
            _candidate(),
            "http://target.local",
            second_poc,
            callback_server=server,
            wait_timeout=0.1,
        )

    assert first.status == "confirmed"
    assert second.status == "suspected"
    assert first.canary_path != second.canary_path
