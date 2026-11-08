"""Kafka UI uses the same credential palette as the Airflow baseline."""

from __future__ import annotations

import pytest

from redposture_core.console import Console
from redposture_core.modules.airflow import render as airflow
from redposture_core.modules.kafka import render as kafka


@pytest.mark.parametrize("vendor", ["provectus", "kafbat"])
@pytest.mark.parametrize("accepted", [True, False])
def test_login_pair_ui_suffix_keeps_airflow_colors(vendor, accepted, capsys):
    record = {
        "host": "localhost",
        "port": 8080,
        "is_kafka_ui": True,
        "ui_vendor": vendor,
        "status": "valid_credentials" if accepted else "invalid_credentials",
        "provided_username": "profile-user",
        "provided_password": "profile-password",
    }
    line = kafka._format_record(record, "txt")
    assert line.endswith(" (UI)")
    kafka._render_colored_kafka_line(Console(no_color=False), line)
    rendered = capsys.readouterr().out
    marker = "[+]" if accepted else "[-]"
    airflow._render_colored_airflow_line(
        Console(no_color=False), f"AIRFLOW\tlocalhost\t8080\t {marker} profile-user:profile-password"
    )
    reference = capsys.readouterr().out
    marker_color = "\x1b[1;92m" if accepted else "\x1b[1;38;5;196m"
    pair_color = "\x1b[1;38;5;196m" if accepted else "\x1b[1;97m"
    for text in [rendered, reference]:
        assert marker_color + marker in text
        assert pair_color + "profile-user:profile-password" in text
    kafka._render_colored_kafka_line(Console(no_color=True), line)
    plain = capsys.readouterr().out
    assert "\x1b" not in plain and f"{marker} profile-user:profile-password (UI)" in plain


@pytest.mark.parametrize("vendor", ["provectus", "kafbat"])
@pytest.mark.parametrize("rce", [True, False])
def test_real_ui_detect_fields_and_plain_output(vendor, rce, capsys):
    record = {
        "host": "localhost",
        "port": 8080,
        "is_kafka_ui": True,
        "ui_vendor": vendor,
        "auth_required": True,
        "version": "v1.5.0",
        "rce": rce,
    }
    line = kafka._format_detect_record(record, "txt")
    kafka._render_colored_kafka_line(Console(no_color=False), line)
    text = capsys.readouterr().out
    assert ("\x1b[1;38;5;196m" if rce else "\x1b[1;92m") + f"rce:{rce}" in text
    kafka._render_colored_kafka_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
