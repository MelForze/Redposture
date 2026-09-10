"""Negative and edge rendering scenarios for the Airflow module.

The happy-path lines live in `test_airflow_render.py`. This file pins what the
renderers must do with incomplete, ambiguous or hostile record shapes: missing
fields, truthy-but-not-bool values, suppressed detect lines, `--defcreds` attempt
lists with odd entries, and the coloring fallbacks.
"""

from __future__ import annotations

import pytest

from redposture_core.modules.airflow import render

_PFX = "AIRFLOW\t10.0.0.5\t8080\t"


def _record(**over):
    base = {"host": "10.0.0.5", "port": 8080, "detection_status": "confirmed", "auth_required": True}
    base.update(over)
    return base


class _Console:
    def __init__(self):
        self.lines: list[str] = []

    def _paint(self, text, color, _s):
        return f"<{color}>{text}</{color}>"

    def plain(self, line):
        self.lines.append(line)


# --- detect line: suppression --------------------------------------------


@pytest.mark.parametrize("status", ["not_airflow", "transport_failure", ""])
def test_detect_line_suppressed_for_undetected_statuses(status):
    assert render._format_detect_record(_record(detection_status=status), "txt") == ""


def test_detect_line_suppressed_when_detection_status_missing():
    record = _record()
    del record["detection_status"]
    assert render._format_detect_record(record, "txt") == ""


def test_detect_line_suppressed_when_detection_status_none():
    assert render._format_detect_record(_record(detection_status=None), "txt") == ""


@pytest.mark.parametrize("fmt", ["json", "csv", ""])
def test_detect_line_suppressed_for_non_txt_formats(fmt):
    assert render._format_detect_record(_record(), fmt) == ""


def test_detect_line_rendered_for_probable_detection():
    line = render._format_detect_record(_record(detection_status="probable"), "txt")
    assert line.startswith(f"{_PFX} [*] Airflow (auth required:True)")


# --- detect line: auth_required is a tri-state ----------------------------


@pytest.mark.parametrize("value", [None, 1, 0, "True", "yes", []])
def test_detect_line_non_bool_auth_required_renders_unknown(value):
    line = render._format_detect_record(_record(auth_required=value), "txt")
    assert "(auth required:unknown)" in line


def test_detect_line_missing_auth_required_renders_unknown():
    record = _record()
    del record["auth_required"]
    assert "(auth required:unknown)" in render._format_detect_record(record, "txt")


# --- detect line: anonymous role suffix rules -----------------------------


@pytest.mark.parametrize("role", ["none", "unknown", None])
def test_detect_line_hides_anon_for_benign_or_unknown_roles(role):
    line = render._format_detect_record(_record(auth_required=False, anonymous_role=role), "txt")
    assert "(anon:" not in line


@pytest.mark.parametrize("role", ["viewer", "op", "admin"])
def test_detect_line_shows_anon_for_real_exposure(role):
    line = render._format_detect_record(_record(auth_required=False, anonymous_role=role), "txt")
    assert f"(anon:{role})" in line


def test_detect_line_hides_anon_when_auth_required_is_unknown():
    # Only an explicit `auth_required is False` may advertise anonymous access.
    line = render._format_detect_record(_record(auth_required=None, anonymous_role="admin"), "txt")
    assert "(anon:" not in line


def test_detect_line_hides_anon_when_auth_required_is_true():
    line = render._format_detect_record(_record(auth_required=True, anonymous_role="admin"), "txt")
    assert "(anon:" not in line


# --- detect line: version suffix ------------------------------------------


@pytest.mark.parametrize("version", ["", None, 0])
def test_detect_line_omits_falsy_version(version):
    line = render._format_detect_record(_record(version=version), "txt")
    assert "(version:" not in line


def test_detect_line_omits_version_when_missing():
    assert "(version:" not in render._format_detect_record(_record(), "txt")


# --- prefix fallbacks ------------------------------------------------------


def test_prefix_falls_back_for_missing_host_and_port():
    line = render._format_detect_record({"detection_status": "confirmed", "auth_required": True}, "txt")
    assert line.startswith("AIRFLOW\t?\t0\t")


def test_prefix_coerces_string_port():
    line = render._format_detect_record(
        {"host": "h", "port": "8081", "detection_status": "confirmed", "auth_required": True}, "txt"
    )
    assert line.startswith("AIRFLOW\th\t8081\t")


# --- accepted-credential line ---------------------------------------------


@pytest.mark.parametrize("state", ["invalid", "transient_failure", "verification_unavailable", "", None])
def test_record_line_empty_for_non_accepting_states(state):
    assert render._format_record(_record(credential_state=state), "txt") == ""


def test_record_line_empty_when_credential_state_missing():
    assert render._format_record(_record(), "txt") == ""


def test_record_line_rendered_for_restricted_state():
    record = _record(
        credential_state="valid_but_restricted",
        credential_results=[{"username": "u", "state": "valid_but_restricted"}],
        credential_password="p",
        role="viewer",
    )
    assert render._format_record(record, "txt") == f"{_PFX} [+] u:p (role:viewer)"


def test_record_line_unknown_username_placeholder():
    record = _record(credential_state="valid", credential_results=[], credential_password="p")
    assert render._format_record(record, "txt") == f"{_PFX} [+] ?:p"


def test_record_line_username_placeholder_when_results_missing():
    record = _record(credential_state="valid", credential_password="p")
    assert render._format_record(record, "txt") == f"{_PFX} [+] ?:p"


def test_record_line_username_placeholder_when_entry_lacks_username():
    record = _record(credential_state="valid", credential_results=[{"state": "valid"}], credential_password="p")
    assert render._format_record(record, "txt") == f"{_PFX} [+] ?:p"


def test_record_line_without_password_shows_username_only():
    record = _record(credential_state="valid", credential_results=[{"username": "airflow", "state": "valid"}])
    assert render._format_record(record, "txt") == f"{_PFX} [+] airflow"


def test_record_line_empty_password_still_shows_colon():
    record = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="",
    )
    assert render._format_record(record, "txt") == f"{_PFX} [+] airflow:"


@pytest.mark.parametrize("role", [None, "", 0])
def test_record_line_omits_falsy_role_suffix(role):
    record = _record(
        credential_state="valid",
        credential_results=[{"username": "u", "state": "valid"}],
        credential_password="p",
        role=role,
    )
    assert render._format_record(record, "txt") == f"{_PFX} [+] u:p"


def test_record_line_suppressed_for_json():
    record = _record(
        credential_state="valid",
        credential_results=[{"username": "u", "state": "valid"}],
        credential_password="p",
    )
    assert render._format_record(record, "json") == ""


# --- --defcreds attempt lines ---------------------------------------------


def test_attempts_empty_for_json():
    record = _record(
        attempted_credentials=[
            {"username": "a", "password": "a", "credential_state": "invalid"},
            {"username": "b", "password": "b", "credential_state": "invalid"},
        ]
    )
    assert render._format_credential_attempts_records(record, "json") == []


def test_attempts_empty_for_single_attempt():
    # A lone attempt is already covered by the detect/accepted lines.
    record = _record(attempted_credentials=[{"username": "a", "password": "a", "credential_state": "invalid"}])
    assert render._format_credential_attempts_records(record, "txt") == []


@pytest.mark.parametrize("attempts", [None, "not-a-list", {"username": "a"}, 5])
def test_attempts_empty_for_non_list_payloads(attempts):
    assert render._format_credential_attempts_records(_record(attempted_credentials=attempts), "txt") == []


def test_attempts_skip_non_dict_entries():
    record = _record(
        credential_results=[{"username": "airflow", "state": "valid"}],
        attempted_credentials=[
            "garbage",
            None,
            {"username": "admin", "password": "admin", "credential_state": "invalid"},
        ],
    )
    lines = render._format_credential_attempts_records(record, "txt")
    assert lines == [f"{_PFX} [-] admin:admin"]


@pytest.mark.parametrize(
    ("password", "shown"),
    [(None, "<no-password>"), ("", "<empty>"), ("secret", "secret"), (123, "123")],
)
def test_attempts_password_placeholders(password, shown):
    record = _record(
        attempted_credentials=[
            {"username": "a", "password": password, "credential_state": "invalid"},
            {"username": "b", "password": "b", "credential_state": "invalid"},
        ]
    )
    lines = render._format_credential_attempts_records(record, "txt")
    assert lines[0] == f"{_PFX} [-] a:{shown}"


def test_attempts_missing_password_key_is_no_password():
    record = _record(
        attempted_credentials=[
            {"username": "a", "credential_state": "invalid"},
            {"username": "b", "password": "b", "credential_state": "invalid"},
        ]
    )
    assert render._format_credential_attempts_records(record, "txt")[0] == f"{_PFX} [-] a:<no-password>"


def test_attempts_accepted_non_winner_rendered_with_password():
    # A second accepted pair is real exposure and must be shown WITH its password:
    # several defaults can share a username, so the operator needs the exact pair.
    record = _record(
        credential_results=[{"username": "airflow", "state": "valid"}],
        attempted_credentials=[
            {"username": "airflow", "password": "airflow", "credential_state": "valid"},
            {"username": "admin", "password": "admin", "credential_state": "valid"},
        ],
    )
    lines = render._format_credential_attempts_records(record, "txt")
    assert lines == [f"{_PFX} [+] admin:admin"]


def test_attempts_winner_skipped_only_once():
    # Two accepted entries with the winner's username: the first is the winner
    # (already rendered elsewhere), the duplicate must still surface.
    record = _record(
        credential_results=[{"username": "airflow", "state": "valid"}],
        attempted_credentials=[
            {"username": "airflow", "password": "airflow", "credential_state": "valid"},
            {"username": "airflow", "password": "other", "credential_state": "valid"},
        ],
    )
    assert render._format_credential_attempts_records(record, "txt") == [f"{_PFX} [+] airflow:other"]


def test_attempts_accepted_restricted_counts_as_accepted():
    record = _record(
        credential_results=[{"username": "airflow", "state": "valid"}],
        attempted_credentials=[
            {"username": "u", "password": "p", "credential_state": "valid_but_restricted"},
            {"username": "x", "password": "y", "credential_state": "invalid"},
        ],
    )
    lines = render._format_credential_attempts_records(record, "txt")
    assert lines == [f"{_PFX} [+] u:p", f"{_PFX} [-] x:y"]


def test_attempts_missing_username_renders_empty_user():
    record = _record(
        attempted_credentials=[
            {"password": "p", "credential_state": "invalid"},
            {"username": "b", "password": "b", "credential_state": "invalid"},
        ]
    )
    assert render._format_credential_attempts_records(record, "txt")[0] == f"{_PFX} [-] :p"


# --- coloring --------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "color"),
    [("admin", "true_red"), ("op", "yellow"), ("viewer", "bright_green"), ("none", "bright_green")],
)
def test_role_span_colors(role, color):
    spans = render._airflow_role_spans("[+]", f"airflow:pw (role:{role})")
    assert spans and spans[0][2] == color


def test_unknown_role_falls_back_to_yellow():
    spans = render._airflow_role_spans("[*]", "Airflow (anon:weird)")
    assert spans and spans[0][2] == "yellow"


def test_auth_required_true_is_green():
    console = _Console()
    render._render_colored_airflow_line(console, render._format_detect_record(_record(auth_required=True), "txt"))
    assert "<bright_green>auth required:True</bright_green>" in console.lines[0]


def test_colorizer_ignores_foreign_lines():
    console = _Console()
    assert render._render_colored_airflow_line(console, "MINIO\th\t9000\t [*] MinIO") is False
    assert console.lines == []


def test_colorizer_falls_back_to_detail_line_without_marker():
    console = _Console()
    assert render._render_colored_airflow_line(console, "AIRFLOW\th\t8080\tsome detail") is True
    assert console.lines


def test_colorizer_rejects_tagless_line():
    console = _Console()
    assert render._render_colored_airflow_line(console, "not an airflow line") is False
    assert console.lines == []
