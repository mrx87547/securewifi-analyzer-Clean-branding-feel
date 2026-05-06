import json
import sys

import pytest

from utils.helpers import (
    InputValidationError,
    atomic_write_text,
    check_root,
    run_command,
    sanitise_ssid,
    validate_interface_name,
    validate_timeout,
)


def test_run_command_captures_stderr_without_shell():
    script = "import sys; print('out'); sys.stderr.write('err')"

    output = run_command([sys.executable, "-c", script], timeout=5, capture_stderr=True)

    assert output is not None
    assert "out" in output
    assert "err" in output


@pytest.mark.parametrize("value", ["wlan0", "wlp2s0", "mon0", "wifi.ap-1", "phy0:wlan0"])
def test_validate_interface_accepts_safe_names(value):
    assert validate_interface_name(value) == value


@pytest.mark.parametrize("value", ["-bad", "wlan0;rm", "../wlan0", "", "a" * 65])
def test_validate_interface_rejects_unsafe_names(value):
    with pytest.raises(InputValidationError):
        validate_interface_name(value)


def test_validate_timeout_bounds():
    assert validate_timeout(1) == 1
    assert validate_timeout(300) == 300
    with pytest.raises(InputValidationError):
        validate_timeout(0)
    with pytest.raises(InputValidationError):
        validate_timeout(301)


def test_sanitise_ssid_removes_control_chars_and_bounds_length():
    value = sanitise_ssid("Lab\x00\nNetwork" + "A" * 100)

    assert "\x00" not in value
    assert "\n" not in value
    assert len(value) <= 64


def test_atomic_write_text_writes_complete_json(tmp_path):
    target = tmp_path / "report.json"

    atomic_write_text(target, json.dumps({"ok": True}))

    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_check_root_is_cross_platform_safe():
    assert isinstance(check_root(), bool)
