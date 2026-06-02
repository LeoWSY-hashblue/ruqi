import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "run_changedetection_ssrf_experiment.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("run_changedetection_ssrf_experiment", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_script_exposes_parser_main_and_modes():
    module = _load_script_module()

    parser = module.build_parser()
    help_text = parser.format_help()

    assert hasattr(module, "main")
    assert set(module.MODES) == {"browser-redirect", "notification-redirect"}
    assert "--target-base-url" in help_text
    assert "--api-key" in help_text
    assert "--dry-run" in help_text
    assert "--cleanup" in help_text
    assert "--no-cleanup" in help_text
    assert "--timeout" in help_text


def test_script_contains_no_real_metadata_targets():
    content = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "169.254.169.254" not in content
    assert "metadata.google.internal" not in content
    assert "100.100.100.200" not in content


def test_dry_run_does_not_send_network_requests(monkeypatch, capsys):
    module = _load_script_module()

    def fail_http(*_args, **_kwargs):
        raise AssertionError("dry-run should not make HTTP requests")

    monkeypatch.setattr(module, "_http_json", fail_http)

    rc = module.main(
        [
            "--target-base-url",
            "http://127.0.0.1:5000",
            "--mode",
            "browser-redirect",
            "--api-key",
            "dummy",
            "--dry-run",
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out
    assert "Dry run: no target requests will be sent" in output
    assert "POST http://127.0.0.1:5000/api/v1/watch" in output
    assert "GET <target-base-url>/api/v1/watch/<uuid>?recheck=true" in output
    assert "DELETE <target-base-url>/api/v1/watch/<uuid>" in output
    assert "html_webdriver" in output


def test_missing_api_key_returns_clear_error(monkeypatch, capsys):
    module = _load_script_module()
    monkeypatch.delenv("CHANGEDETECTION_API_KEY", raising=False)

    rc = module.main(["--target-base-url", "http://127.0.0.1:5000", "--mode", "browser-redirect"])

    assert rc == 2
    assert "Missing API key" in capsys.readouterr().err


def test_browser_redirect_poc_posts_rechecks_and_cleans_up(monkeypatch):
    module = _load_script_module()
    calls = []

    def fake_http(method, url, api_key, payload=None):
        calls.append((method, url, api_key, payload))
        if method == "POST":
            return 201, {"uuid": "watch-123"}
        return 200, "OK"

    monkeypatch.setattr(module, "_http_json", fake_http)

    poc = module.make_browser_redirect_poc("api-token", cleanup=True)
    rc = poc(
        "http://127.0.0.1:5000/",
        "http://callback.local/callback/token",
        "http://callback.local/redirect/token?to=http%3A%2F%2Fcallback.local%2Fcanary%2Ftoken",
    )

    assert rc == 0
    assert calls[0][0] == "POST"
    assert calls[0][1] == "http://127.0.0.1:5000/api/v1/watch"
    assert calls[0][2] == "api-token"
    assert calls[0][3]["url"].startswith("http://callback.local/redirect/token")
    assert calls[0][3]["fetch_backend"] == "html_webdriver"
    assert calls[0][3]["time_between_check"] == {"seconds": 3}
    assert calls[1] == ("GET", "http://127.0.0.1:5000/api/v1/watch/watch-123?recheck=true", "api-token", None)
    assert calls[2] == ("DELETE", "http://127.0.0.1:5000/api/v1/watch/watch-123", "api-token", None)


def test_browser_redirect_poc_can_skip_cleanup(monkeypatch):
    module = _load_script_module()
    calls = []

    def fake_http(method, url, api_key, payload=None):
        calls.append((method, url, api_key, payload))
        if method == "POST":
            return 201, {"uuid": "watch-123"}
        return 200, "OK"

    monkeypatch.setattr(module, "_http_json", fake_http)

    poc = module.make_browser_redirect_poc("api-token", cleanup=False)
    assert poc("http://target", "http://callback", "http://redirect") == 0

    assert [call[0] for call in calls] == ["POST", "GET"]


def test_notification_redirect_remains_not_implemented(capsys):
    module = _load_script_module()

    rc = module.main(
        [
            "--target-base-url",
            "http://127.0.0.1:5000",
            "--mode",
            "notification-redirect",
            "--api-key",
            "dummy",
        ]
    )

    assert rc == 2
    assert "not implemented pending UI session/CSRF" in capsys.readouterr().err
