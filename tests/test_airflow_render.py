from __future__ import annotations

from redposture_core.modules.airflow import render

_PFX = "AIRFLOW\t10.0.0.5\t8080\t"


def _record(**over):
    base = {"host": "10.0.0.5", "port": 8080, "detection_status": "confirmed", "auth_required": True}
    base.update(over)
    return base


class _Console:
    def __init__(self):
        self.lines = []

    def _paint(self, text, color, _s):
        return f"<{color}>{text}</{color}>"

    def plain(self, line):
        self.lines.append(line)


def test_detect_line_auth_required_and_version():
    line = render._format_detect_record(_record(version="2.9.3"), "txt")
    assert line == f"{_PFX} [*] Airflow (auth required:True) (version:2.9.3)"


def test_detect_line_anon_admin_when_open():
    line = render._format_detect_record(_record(auth_required=False, anonymous_role="admin", version="3.0.2"), "txt")
    assert line == f"{_PFX} [*] Airflow (auth required:False) (anon:admin) (version:3.0.2)"


def test_detect_line_no_anon_when_auth_required():
    line = render._format_detect_record(_record(auth_required=True, anonymous_role="none"), "txt")
    assert "(anon:" not in line


def test_detect_suppressed_for_non_airflow_and_json():
    assert render._format_detect_record(_record(detection_status="not_airflow"), "txt") == ""
    assert render._format_detect_record(_record(), "json") == ""


def test_record_line_user_pass_and_role():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        role="admin",
    )
    assert render._format_record(rec, "txt") == f"{_PFX} [+] airflow:airflow (role:admin)"


def test_record_line_empty_when_not_valid():
    assert render._format_record(_record(credential_state="invalid"), "txt") == ""


def test_attempts_render_rejected_skip_winner():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        attempted_credentials=[
            {"username": "airflow", "password": "airflow", "credential_state": "valid"},
            {"username": "admin", "password": "admin", "credential_state": "invalid"},
            {"username": "admin", "password": "", "credential_state": "invalid"},
        ],
    )
    lines = render._format_credential_attempts_records(rec, "txt")
    assert "airflow" not in "\n".join(lines)  # winner shown by _format_record
    assert f"{_PFX} [-] admin:admin" in lines
    assert f"{_PFX} [-] admin:<empty>" in lines


def test_detect_coloring_auth_and_anon():
    console = _Console()
    render._render_colored_airflow_line(
        console, render._format_detect_record(_record(auth_required=False, anonymous_role="admin"), "txt")
    )
    out = console.lines[0]
    assert "<true_red>auth required:False</true_red>" in out
    assert "<true_red>anon:admin</true_red>" in out


def test_record_coloring_role_admin_red():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        role="admin",
    )
    console = _Console()
    render._render_colored_airflow_line(console, render._format_record(rec, "txt"))
    assert "<true_red>role:admin</true_red>" in console.lines[0]
