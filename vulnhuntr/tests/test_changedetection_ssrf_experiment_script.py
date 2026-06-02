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

    assert hasattr(module, "main")
    assert set(module.MODES) == {"browser-redirect", "notification-redirect"}
    assert "--target-base-url" in parser.format_help()
    assert "--api-key" in parser.format_help()


def test_script_contains_no_real_metadata_targets():
    content = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "169.254.169.254" not in content
    assert "metadata.google.internal" not in content
    assert "100.100.100.200" not in content


def test_placeholder_pocs_raise_clear_not_implemented():
    module = _load_script_module()

    for mode in module.MODES:
        poc = module.poc_for_mode(mode)
        try:
            poc("http://target.local", "http://callback.local/callback/token", "http://callback.local/redirect/token")
        except NotImplementedError as exc:
            assert "not implemented until" in str(exc)
        else:
            raise AssertionError(f"{mode} PoC should remain a placeholder")
