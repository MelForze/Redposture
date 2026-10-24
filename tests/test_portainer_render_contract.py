"""Keep Portainer's phase formatters and final report in the same order."""

from __future__ import annotations

import pytest

from redposture_core.modules.portainer import render


def record():
    return {
        "host": "qa",
        "port": 9443,
        "surface": "ui",
        "ui_product": "portainer",
        "is_portainer": True,
        "credential_state": "valid",
        "provided_username": "admin",
        "provided_password": "secret",
        "ui": {
            "version": "2.39.7",
            "auth_required": True,
            "inventory": {"containers": {"count": 1, "items": ["qa-container"]}},
        },
    }


def test_phase_formatters_do_not_mix_credentials_with_inventory():
    payload = record()
    detect = render._format_detect_record(payload, "txt")
    auth = render._format_record(payload, "txt")
    inventory = render._format_inventory_records(payload, "txt")
    assert detect.endswith("(version:2.39.7) (UI)")
    assert "admin:secret" in auth and "(UI)" not in auth and "qa-container" not in auth
    assert any("qa-container" in line for line in inventory)
    assert not any("admin:secret" in line for line in inventory)
    assert "\x1b" not in "\n".join([detect, auth, *inventory])


@pytest.mark.parametrize("output_format", ["json", "unsupported"])
def test_phase_formatters_leave_structured_output_to_the_runner(output_format):
    assert render._format_detect_record(record(), output_format) == ""
    assert render._format_record(record(), output_format) == ""
    assert render._format_inventory_records(record(), output_format) == []


def test_unknown_and_blocked_attempts_remain_visible_without_duplicate_pairs():
    payload = record()
    payload["attempted_credentials"] = [
        None,
        {"credential_state": "unverified"},
        {"username": "admin", "password": "secret", "credential_state": "valid"},
        {"username": "admin", "password": "secret", "credential_state": "valid"},
        {"credential_state": "captcha"},
    ]
    lines = render.render_record(payload)
    assert sum("admin:secret" in line for line in lines) == 1
    unknown = next(i for i, line in enumerate(lines) if "Credentials unverified" in line)
    blocked = next(i for i, line in enumerate(lines) if "attempts stopped" in line)
    inventory = next(i for i, line in enumerate(lines) if "Containers Enumeration" in line)
    assert unknown < blocked < inventory
