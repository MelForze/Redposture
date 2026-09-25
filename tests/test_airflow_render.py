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
    assert line == f"{_PFX} [*] Airflow (auth required:True) (Dags allowed anonymously:unknown) (version:2.9.3)"


def test_detect_line_does_not_infer_anonymous_role_when_open():
    line = render._format_detect_record(_record(auth_required=False, anonymous_role="admin", version="3.0.2"), "txt")
    assert line == f"{_PFX} [*] Airflow (auth required:False) (Dags allowed anonymously:unknown) (version:3.0.2)"


def test_detect_line_no_anon_when_auth_required():
    line = render._format_detect_record(_record(auth_required=True, anonymous_role="none"), "txt")
    assert "(anon:" not in line


def test_detect_line_sso_keeps_boolean_in_record_but_renders_method():
    line = render._format_detect_record(
        _record(auth_required=True, auth_method="sso", sso_provider="keycloak", version="2.11.1"), "txt"
    )
    assert line == (
        f"{_PFX} [*] Airflow (auth required:sso) (Dags allowed anonymously:unknown) "
        "(provider:keycloak) (version:2.11.1)"
    )


def test_detect_suppressed_for_non_airflow_and_json():
    assert render._format_detect_record(_record(detection_status="not_airflow"), "txt") == ""
    assert render._format_detect_record(_record(), "json") == ""


def test_record_line_user_pass_and_resource_access():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        authenticated_dags_access="allowed",
        authenticated_dags_count=4,
        authenticated_keys_access="allowed",
        authenticated_keys_count=2,
        authenticated_connections_access="denied",
    )
    assert render._format_record(rec, "txt") == (
        f"{_PFX} [+] airflow:airflow (Dags:4) (Keys:2) (Connections:Access Denied)"
    )


def test_record_line_empty_when_not_valid():
    assert render._format_record(_record(credential_state="invalid"), "txt") == ""


def test_record_line_waits_for_capability_phase_to_avoid_duplicate_credentials():
    auth_phase = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        _credential_capabilities_pending=True,
    )
    capability_phase = {
        **auth_phase,
        "_credential_capabilities_pending": False,
        "authenticated_dags_access": "allowed",
        "authenticated_dags_count": 1,
        "authenticated_keys_access": "denied",
        "authenticated_connections_access": "unknown",
    }

    assert render._format_record(auth_phase, "txt") == ""
    assert render._format_record(capability_phase, "txt") == (
        f"{_PFX} [+] airflow:airflow (Dags:1) (Keys:Access Denied) (Connections:Unknown)"
    )


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
    assert "anon:admin" not in out


def test_detect_line_and_color_expose_anonymous_dag_access():
    line = render._format_detect_record(_record(dags_allowed=True), "txt")
    assert "(Dags allowed anonymously:True)" in line
    console = _Console()
    render._render_colored_airflow_line(console, line)
    assert "<true_red>Dags allowed anonymously:True</true_red>" in console.lines[0]


def test_authenticated_credential_line_reports_counts_and_access_once():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        authenticated_dags_access="allowed",
        authenticated_dags_count=3,
        authenticated_keys_access="denied",
        authenticated_connections_access="allowed",
        authenticated_connections_count=0,
    )
    line = render._format_record(rec, "txt")

    assert line == f"{_PFX} [+] airflow:airflow (Dags:3) (Keys:Access Denied) (Connections:0)"
    console = _Console()
    render._render_colored_airflow_line(console, line)
    assert "<true_red>Dags:3</true_red>" in console.lines[0]
    assert "<bright_green>Keys:Access Denied</bright_green>" in console.lines[0]
    assert "<true_red>Connections:0</true_red>" in console.lines[0]


def test_authenticated_resource_denial_is_green():
    rec = _record(
        credential_state="valid_but_restricted",
        credential_results=[{"username": "viewer", "state": "valid_but_restricted"}],
        credential_password="viewer",
        authenticated_dags_access="denied",
        authenticated_keys_access="denied",
        authenticated_connections_access="denied",
    )
    console = _Console()

    assert render._render_colored_airflow_line(console, render._format_record(rec, "txt"))
    assert "<bright_green>Dags:Access Denied</bright_green>" in console.lines[0]


def test_unknown_authenticated_resource_is_orange():
    rec = _record(
        credential_state="valid",
        credential_results=[{"username": "airflow", "state": "valid"}],
        credential_password="airflow",
        authenticated_dags_access="unknown",
        authenticated_keys_access="unknown",
        authenticated_connections_access="unknown",
    )
    console = _Console()
    render._render_colored_airflow_line(console, render._format_record(rec, "txt"))
    assert "<orange>Dags:Unknown</orange>" in console.lines[0]


def test_discovery_finding_and_summary_use_common_colors():
    record = _record(
        discover_requested=True,
        discover_report={
            "status": "complete",
            "logs_scanned": 1,
            "bytes_scanned": 42,
            "findings": [
                {
                    "type": "password",
                    "confidence": "medium",
                    "value": "secret",
                    "dag_id": "dag",
                    "dag_run_id": "run",
                    "task_id": "task",
                    "try_number": 1,
                    "map_index": -1,
                    "object_path": "$",
                }
            ],
        },
    )
    summary, finding = render._format_discover_records(record, "txt")

    summary_console = _Console()
    assert render._render_colored_airflow_line(summary_console, summary)
    assert "<white>Discover Secrets (</white>" in summary_console.lines[0]
    assert "<bright_green>status:complete</bright_green>" in summary_console.lines[0]
    assert "<true_red>findings:1</true_red>" in summary_console.lines[0]

    finding_console = _Console()
    assert render._render_colored_airflow_line(finding_console, finding)
    assert "<red>[!]</red>" in finding_console.lines[0]
    assert '<orange>Pass Value="secret" Place="dag/run/task/try:1/map:-1$"</orange>' in finding_console.lines[0]


def test_streamed_discovery_uses_header_then_distinct_completion_label():
    record = _record(
        discover_requested=True,
        _discover_findings_streamed=True,
        discover_report={"status": "complete", "findings": [], "bytes_scanned": 42},
    )

    line = render._format_discover_records(record, "txt")[0]
    assert line == f"{_PFX} [*] Discover Complete (status:complete) (findings:0)"
    console = _Console()
    assert render._render_colored_airflow_line(console, line)
    assert "<white>Discover Complete (</white>" in console.lines[0]
    assert "<bright_green>status:complete</bright_green>" in console.lines[0]
    assert "<bright_green>findings:0</bright_green>" in console.lines[0]


def test_cve_payload_is_orange_and_uses_normal_airflow_prefix():
    line = f"{_PFX} [!] CVE-2024-39877 potentially affected (HIGH 8.8) Airflow scheduler RCE"
    console = _Console()

    assert render._render_colored_airflow_line(console, line)
    assert "<orange>CVE-2024-39877 potentially affected (HIGH 8.8) Airflow scheduler RCE</orange>" in console.lines[0]


def test_cve_enumeration_header_is_white():
    console = _Console()

    assert render._render_colored_airflow_line(console, f"{_PFX} [*] CVE's Enumeration")
    assert "<white>CVE's Enumeration</white>" in console.lines[0]


def test_console_lines_use_fixed_airflow_columns_without_changing_txt_prefix():
    raw = "AIRFLOW\t127.0.0.1\t18080\t [*] Discover Secrets"
    console = _Console()

    assert render._render_colored_airflow_line(console, raw)
    assert console.lines[0].startswith("<blue>AIRFLOW</blue><white>         127.0.0.1       18080  </white>")
    assert raw.startswith("AIRFLOW\t127.0.0.1\t18080\t")


def test_variable_keys_render_names_without_values():
    lines = render._format_show_keys_records(
        _record(
            show_keys_requested=True,
            variable_keys=["warehouse_password", "api_token_name"],
            variable_keys_total=2,
        ),
        "txt",
    )
    assert "Airflow Variable Keys (keys:2)" in lines[0]
    assert lines[1].endswith('Variable Name="warehouse_password"')
    assert lines[2].endswith('Variable Name="api_token_name"')

    console = _Console()
    assert render._render_colored_airflow_line(console, lines[1])
    assert '<orange>Variable Name="warehouse_password"</orange>' in console.lines[0]


def test_variable_key_count_is_red_when_nonzero_and_green_when_zero():
    nonzero = _format_show_keys_summary_for_color(["warehouse_password"])
    empty = _format_show_keys_summary_for_color([])

    nonzero_console = _Console()
    empty_console = _Console()
    assert render._render_colored_airflow_line(nonzero_console, nonzero)
    assert render._render_colored_airflow_line(empty_console, empty)
    assert "<true_red>keys:1</true_red>" in nonzero_console.lines[0]
    assert "<bright_green>keys:0</bright_green>" in empty_console.lines[0]


def test_connections_render_full_objects_and_color_exposed_contents() -> None:
    connection = {
        "connection_id": "warehouse",
        "conn_type": "postgres",
        "host": "db.internal",
        "password": "connection-secret",
    }
    lines = render._format_show_connections_records(
        _record(show_connections_requested=True, airflow_connections=[connection]),
        "txt",
    )

    assert lines[0].endswith("Airflow Connections (connections:1)")
    assert 'Connection Id="warehouse" Value=' in lines[1]
    assert '"password":"connection-secret"' in lines[1]
    console = _Console()
    assert render._render_colored_airflow_line(console, lines[1])
    assert '<orange>Connection Id="warehouse" Value=' in console.lines[0]


def _format_show_keys_summary_for_color(keys: list[str]) -> str:
    return render._format_show_keys_records(
        _record(show_keys_requested=True, variable_keys=keys, variable_keys_total=len(keys)),
        "txt",
    )[0]
