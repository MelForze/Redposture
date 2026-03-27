from __future__ import annotations

import json
import re
from argparse import Namespace
from pathlib import Path

import pytest

from redposture_core.cli import main
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.db import cli as db_cli
from redposture_core.db.cli import (
    _attach_host_port_summaries,
    _clip_text,
    _compact_bytes,
    _emit_dashboard_section,
    _emit_line_section,
    _emit_module_dashboard,
    _emit_module_recent_hits,
    _emit_rows,
    _format_rows,
    _marker_for_severity,
    _marker_for_status,
    _module_tag,
    _normalized_ports,
    _render_artifact_row,
    _render_database_totals,
    _render_endpoint_row,
    _render_finding_row,
    _render_host_row,
    _render_module_artifact_row,
    _render_module_endpoint_row,
    _render_module_finding_row,
    _render_module_host_row,
    _render_module_recent_hit,
    _render_module_run_row,
    _render_module_summary_line,
    _render_run_row,
    _severity_color,
    _status_color,
    _timestamp_text,
    run_db_command,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run_db(*args: str) -> int:
    return main(["db", *args])


def test_db_cli_ingest_show_search_and_export_commands(
    db_url: str,
    db_fixture_dir: Path,
    tmp_path: Path,
    capsys,
) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    for module_name, filename in (
        ("grafana", "grafana.json"),
        ("kubeapi", "kubeapi.json"),
        ("postgres", "postgres.json"),
    ):
        assert _run_db("ingest", module_name, str(db_fixture_dir / filename), "--db-url", db_url, "--json") == 0
        capsys.readouterr()

    assert _run_db("show", "--db-url", db_url, "--json") == 0
    overview = json.loads(capsys.readouterr().out)
    assert overview["totals"]["hosts_count"] >= 3
    assert overview["totals"]["findings_count"] >= 3
    assert any(item["module"] == "grafana" and item["records_count"] > 0 for item in overview["modules"])

    assert _run_db("show", "grafana", "--db-url", db_url, "--json") == 0
    landing = json.loads(capsys.readouterr().out)
    assert landing["module"] == "grafana"
    assert landing["shown"] == len(landing["recent_hits"])
    assert landing["limit"] == 10
    assert landing["shown"] >= 1
    assert all(item["module"] == "grafana" for item in landing["recent_hits"])
    assert all(item["target"] == "10.10.10.10:3000" for item in landing["recent_hits"])
    assert {item["finding_type"] for item in landing["recent_hits"]} >= {"open_no_auth", "anonymous_access"}

    assert _run_db("show", "grafana", "summary", "--db-url", db_url, "--json") == 0
    summary_rows = json.loads(capsys.readouterr().out)
    assert summary_rows == [
        {
            "module": "grafana",
            "hosts_count": 1,
            "endpoints_count": 1,
            "findings_count": 2,
            "runs_count": 1,
            "artifacts_count": 1,
            "last_seen_at": summary_rows[0]["last_seen_at"],
        }
    ]
    assert summary_rows[0]["last_seen_at"] is not None

    assert _run_db("show", "grafana", "hosts", "--db-url", db_url, "--json") == 0
    module_hosts_rows = json.loads(capsys.readouterr().out)

    assert _run_db("show", "hosts", "--db-url", db_url, "--module", "grafana", "--json") == 0
    generic_hosts_rows = json.loads(capsys.readouterr().out)
    assert module_hosts_rows == generic_hosts_rows
    host_id = generic_hosts_rows[0]["id"]

    assert _run_db("show", "findings", "--db-url", db_url, "--module", "grafana", "--json") == 0
    finding_rows = json.loads(capsys.readouterr().out)
    assert finding_rows
    assert all(row["module_name"] == "grafana" for row in finding_rows)

    assert _run_db("show", "findings", "--db-url", db_url, "--module-name", "grafana", "--json") == 0
    compat_rows = json.loads(capsys.readouterr().out)
    assert compat_rows == finding_rows

    assert _run_db("show", "grafana", "findings", "--db-url", db_url, "--json") == 0
    module_finding_rows = json.loads(capsys.readouterr().out)
    assert module_finding_rows == finding_rows

    assert _run_db("show", "hosts", "--db-url", db_url, "--module", "grafana") == 0
    hosts_output = capsys.readouterr().out
    assert "GRAFANA" in hosts_output
    assert "10.10.10.10" in hosts_output
    assert "10.10.10.20" not in hosts_output

    assert _run_db("show", "endpoints", "--db-url", db_url, "--json") == 0
    endpoint_rows = json.loads(capsys.readouterr().out)
    assert endpoint_rows

    assert (
        _run_db("show", "endpoints", "--db-url", db_url, "--host-id", str(host_id), "--module", "grafana", "--json")
        == 0
    )
    filtered_endpoints = json.loads(capsys.readouterr().out)
    assert filtered_endpoints
    assert all(row["port"] == 3000 for row in filtered_endpoints)

    assert _run_db("show", "grafana", "endpoints", "--db-url", db_url, "--host-id", str(host_id), "--json") == 0
    module_endpoints_rows = json.loads(capsys.readouterr().out)
    assert module_endpoints_rows == filtered_endpoints

    assert _run_db("show", "runs", "--db-url", db_url, "--target", "10.10.10.10", "--module", "grafana", "--json") == 0
    run_rows = json.loads(capsys.readouterr().out)
    assert run_rows
    assert all(row["module_name"] == "grafana" for row in run_rows)

    assert _run_db("show", "grafana", "runs", "--db-url", db_url, "--target", "10.10.10.10", "--json") == 0
    module_run_rows = json.loads(capsys.readouterr().out)
    assert module_run_rows == run_rows

    assert (
        _run_db(
            "show", "artifacts", "--db-url", db_url, "--run-id", str(run_rows[0]["id"]), "--module", "grafana", "--json"
        )
        == 0
    )
    artifact_rows = json.loads(capsys.readouterr().out)
    assert artifact_rows

    assert (
        _run_db("show", "grafana", "artifacts", "--db-url", db_url, "--run-id", str(run_rows[0]["id"]), "--json") == 0
    )
    module_artifact_rows = json.loads(capsys.readouterr().out)
    assert module_artifact_rows == artifact_rows

    assert _run_db("search", "Grafana", "--db-url", db_url, "--json") == 0
    search_rows = json.loads(capsys.readouterr().out)
    assert all("workspace_id" not in row for row in search_rows)
    assert any(row["entity_type"] == "finding" for row in search_rows)

    export_path = tmp_path / "findings.json"
    assert (
        _run_db(
            "export",
            "findings",
            "--db-url",
            db_url,
            "--module",
            "grafana",
            "--format",
            "json",
            "--output",
            str(export_path),
        )
        == 0
    )
    export_output = capsys.readouterr().out
    assert export_path.exists()
    assert "grafana" in export_output
    assert "kubeapi" not in export_output

    backup_path = tmp_path / "backup.sqlite3"
    assert _run_db("export", "database", "--db-url", db_url, "--output", str(backup_path)) == 0
    exported_db_path = capsys.readouterr().out.strip()
    assert exported_db_path.endswith("backup.sqlite3")
    assert backup_path.exists()

    imported_db_url = f"sqlite:///{tmp_path / 'imported.db'}"
    assert _run_db("import", "database", "--db-url", imported_db_url, "--input", str(backup_path)) == 0
    imported_path = capsys.readouterr().out.strip()
    assert imported_path.endswith("imported.db")

    assert _run_db("show", "findings", "--db-url", imported_db_url, "--module", "grafana", "--json") == 0
    imported_findings = json.loads(capsys.readouterr().out)
    assert imported_findings
    assert all(row["module_name"] == "grafana" for row in imported_findings)

    assert _run_db("show", "redis", "--db-url", db_url, "--json") == 0
    empty_landing = json.loads(capsys.readouterr().out)
    assert empty_landing == {
        "module": "redis",
        "recent_hits": [],
        "shown": 0,
        "limit": 10,
    }


def test_db_cli_invalid_missing_path_errors(db_url: str, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("ingest", "grafana", "missing.json", "--db-url", db_url) != 0
    assert "[error]" in capsys.readouterr().err


def test_db_main_dispatches_argparse_commands(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert main(["db", "init", "--db-url", db_url]) == 0
    capsys.readouterr()
    assert main(["db", "ingest", "grafana", str(db_fixture_dir / "grafana.json"), "--db-url", db_url]) == 0
    capsys.readouterr()
    assert main(["db", "show", "grafana", "--db-url", db_url]) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "recent grafana hits/results: shown=" not in output
    assert "[*] Grafana Service (auth required:False)" in output
    assert "[*] Dump Datasources" in output
    assert "GRAFANA" in output


def test_db_help_uses_argparse_and_supports_short_h(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show", "hosts", "-h"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "Usage:" not in help_text
    assert "usage:" in help_text
    assert "--module" in help_text
    assert "--workspace" not in help_text


def test_db_show_help_lists_generic_and_module_commands(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show", "-h"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage:" in help_text
    assert "db show [-h] [--json] [--db-url url] [-v|--debug] [item] ..." in help_text
    assert "Read stored assessment data." in help_text
    assert "Module Views:" in help_text
    assert "Options:" in help_text
    assert "view ..." not in help_text
    assert "grafana" in help_text
    assert "db show <module> -h" in help_text
    assert "db show hosts -h" in help_text
    assert "Inventory Views:" not in help_text
    assert "Examples:" not in help_text
    assert "Default:" not in help_text

    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show", "exporters", "-h"])
    assert exc.value.code == 0
    exporters_help = capsys.readouterr().out
    assert "usage:" in exporters_help
    assert "db show exporters [-h] [--json] [--db-url url] [-v|--debug]" in exporters_help
    assert "--hosts" in exporters_help
    assert "--list-host" in exporters_help
    assert "--host value" in exporters_help
    assert "--endpoints" in exporters_help
    assert "--summary" in exporters_help
    assert "--findings" in exporters_help
    assert "--runs" in exporters_help
    assert "--artifacts" in exporters_help
    assert "--collect" in exporters_help
    assert "--trigger" in exporters_help
    assert "--debug" in exporters_help
    assert "summary|hosts|endpoints|findings|runs|artifacts" not in exporters_help
    assert "Inspect stored exporters data." in exporters_help
    assert "db show exporters  -> recent useful hits/results" in exporters_help
    assert "Modules:" not in exporters_help
    assert "Sections:" not in exporters_help
    assert "Examples:" in exporters_help
    assert "db show exporters --list-host" in exporters_help
    assert "db show exporters --host 10.10.10.10" in exporters_help
    assert "db show exporters --collect" in exporters_help
    assert "--workspace" not in exporters_help

    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show", "grafana", "-h"])
    assert exc.value.code == 0
    grafana_help = capsys.readouterr().out
    assert "usage:" in grafana_help
    assert "db show grafana [-h] [--json] [--db-url url] [-v|--debug]" in grafana_help
    assert "--hosts" in grafana_help
    assert "--summary" in grafana_help
    assert "--collect" not in grafana_help
    assert "--trigger" not in grafana_help
    assert "Inspect stored grafana data." in grafana_help
    assert "db show grafana  -> recent useful hits/results" in grafana_help

    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show", "grafana", "hosts", "-h"])
    assert exc.value.code == 0
    module_hosts_help = capsys.readouterr().out
    assert "--json" in module_hosts_help
    assert "--workspace" not in module_hosts_help


def test_db_show_module_hosts_and_endpoints_flags_dispatch(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "grafana", str(db_fixture_dir / "grafana.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "grafana", "--hosts", "--db-url", db_url) == 0
    hosts_output = capsys.readouterr().out
    assert "grafana hosts: shown=" in hosts_output
    assert "GRAFANA" in hosts_output
    assert "10.10.10.10" in hosts_output
    assert "ports=" in hosts_output
    assert "seen=" in hosts_output

    assert _run_db("show", "grafana", "--endpoints", "--db-url", db_url) == 0
    endpoints_output = capsys.readouterr().out
    assert "grafana endpoints: shown=" in endpoints_output
    assert "GRAFANA" in endpoints_output
    assert "3000" in endpoints_output
    assert "scheme=" not in endpoints_output

    assert _run_db("show", "grafana", "--endpoints", "--debug", "--db-url", db_url) == 0
    endpoints_debug_output = capsys.readouterr().out
    assert "grafana endpoints: shown=" in endpoints_debug_output
    assert "scheme=" in endpoints_debug_output

    assert _run_db("show", "grafana", "--host", "--db-url", db_url) == 0
    host_alias_output = capsys.readouterr().out
    assert "grafana hosts: shown=" in host_alias_output
    assert "ports=" in host_alias_output


def test_db_show_module_hosts_prints_one_line_per_port(db_url: str, tmp_path: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    payload_path = tmp_path / "exporters_hosts.json"
    payload_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "timestamp": "2026-03-23T18:15:53Z",
                    "host": "127.0.0.1",
                    "exporter": f"exporter_{port}",
                    "port": port,
                    "status": "open_no_auth",
                    "service": f"exporter_{port}",
                    "source_type": "collect",
                    "endpoint": "/metrics",
                    "url": f"http://127.0.0.1:{port}/metrics",
                    "ok": True,
                    "tool_version": "3.5.0",
                }
            )
            for port in (7777, 9100, 9102, 9104, 9113, 9114, 9116, 9117, 9119)
        )
        + "\n",
        encoding="utf-8",
    )

    assert _run_db("ingest", "exporters", str(payload_path), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--list-host", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "exporters hosts: shown=1" in output
    assert output.count("127.0.0.1") == 9
    assert output.count("ports=") == 9
    assert "EXPORTERS   127.0.0.1 ports=7777 seen=" in output
    assert "EXPORTERS   127.0.0.1 ports=9100 seen=" in output
    assert "EXPORTERS   127.0.0.1 ports=9119 seen=" in output


def test_db_show_module_text_output_uses_stage_style_view(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "grafana", str(db_fixture_dir / "grafana.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "grafana", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "recent grafana hits/results: shown=" not in output
    assert "recent findings: shown=" not in output
    assert "recent hosts: shown=" not in output
    assert "GRAFANA" in output
    assert "[*] Grafana Service (auth required:False)" in output
    assert "[+] anonymous access" in output
    assert "[*] Dump Datasources" in output
    assert "name=prometheus-prod type=prometheus url=https://metrics.internal access=proxy" in output

    assert _run_db("show", "grafana", "summary", "--db-url", db_url) == 0
    summary_output = capsys.readouterr().out
    assert "recent grafana hits/results" not in summary_output
    assert "grafana summary" in summary_output
    assert "hosts=" in summary_output


def test_db_show_exporters_uses_stage_style_view_with_colors(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "exporters", str(db_fixture_dir / "exporters.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "Summary" not in output
    assert "recent exporters hits/results" not in output
    assert (
        "COLLECT \t10.20.30.40\t9187\t [+] Postgres Exporter url=http://10.20.30.40:9187/debug/pprof/cmdline?debug=1"
        in output
    )
    assert "VALIDATE\t10.20.30.40\t9187\t [*] Dump Validate Postgres Exporter" in output
    assert "VALIDATE\t10.20.30.40\t9187\t reason=open_no_auth endpoint=/debug/pprof/cmdline?debug=1" in output
    assert "TRIGGER \t10.99.0.10\t-\t [+] Redis Exporter" in output
    assert "VALIDATE\t10.99.0.10\t-\t [*] Dump Validate Redis Exporter" in output
    assert "VALIDATE\t10.99.0.10\t-\t reason=open_no_auth" in output
    assert "http://10.20.30.41:9121/scrape?target=redis://10.99.0.10:6379" in output

    assert _run_db("show", "exporters", "--db-url", db_url, "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["module"] == "exporters"
    assert payload["shown"] == 2
    assert payload["limit"] == 10
    assert [item["phase"] for item in payload["recent_hits"]] == ["trigger", "collect"]

    assert _run_db("show", "exporters", "summary", "--db-url", db_url) == 0
    summary_output = capsys.readouterr().out
    assert "exporters summary" in summary_output
    assert "hosts=" in summary_output


def test_db_show_exporters_collect_and_trigger_filters(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "exporters", str(db_fixture_dir / "exporters.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--collect", "--db-url", db_url) == 0
    collect_output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "COLLECT \t10.20.30.40\t9187\t [+] Postgres Exporter" in collect_output
    assert "TRIGGER \t10.99.0.10\t-\t [+] Redis Exporter" not in collect_output

    assert _run_db("show", "exporters", "--trigger", "--db-url", db_url) == 0
    trigger_output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "TRIGGER \t10.99.0.10\t-\t [+] Redis Exporter" in trigger_output
    assert "COLLECT \t10.20.30.40\t9187\t [+] Postgres Exporter" not in trigger_output

    assert _run_db("show", "exporters", "--collect", "--db-url", db_url, "--json") == 0
    collect_payload = json.loads(capsys.readouterr().out)
    assert collect_payload["shown"] == 1
    assert [item["phase"] for item in collect_payload["recent_hits"]] == ["collect"]

    assert _run_db("show", "exporters", "--trigger", "--db-url", db_url, "--json") == 0
    trigger_payload = json.loads(capsys.readouterr().out)
    assert trigger_payload["shown"] == 1
    assert [item["phase"] for item in trigger_payload["recent_hits"]] == ["trigger"]


def test_db_show_exporters_host_filter_on_landing_and_json(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "exporters", str(db_fixture_dir / "exporters.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--host", "10.20.30.40", "--db-url", db_url) == 0
    collect_output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "COLLECT \t10.20.30.40\t9187\t [+] Postgres Exporter" in collect_output
    assert "TRIGGER \t10.99.0.10\t-\t [+] Redis Exporter" not in collect_output

    assert _run_db("show", "exporters", "--host", "10.99.0.10", "--db-url", db_url) == 0
    trigger_output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "TRIGGER \t10.99.0.10\t-\t [+] Redis Exporter" in trigger_output
    assert "COLLECT \t10.20.30.40\t9187\t [+] Postgres Exporter" not in trigger_output

    assert _run_db("show", "exporters", "--host", "10.99.0.10", "--trigger", "--db-url", db_url, "--json") == 0
    trigger_payload = json.loads(capsys.readouterr().out)
    assert trigger_payload["shown"] == 1
    assert [item["phase"] for item in trigger_payload["recent_hits"]] == ["trigger"]

    assert _run_db("show", "exporters", "--host", "10.20.30.40", "--collect", "--db-url", db_url, "--json") == 0
    collect_payload = json.loads(capsys.readouterr().out)
    assert collect_payload["shown"] == 1
    assert [item["phase"] for item in collect_payload["recent_hits"]] == ["collect"]


def test_db_show_exporters_host_filter_empty_state(db_url: str, db_fixture_dir: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()
    assert _run_db("ingest", "exporters", str(db_fixture_dir / "exporters.json"), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--host", "203.0.113.10", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "no recent exporter results" in output


def test_db_show_exporters_does_not_clip_validation_sample(db_url: str, tmp_path: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    payload_path = tmp_path / "exporters_collect.json"
    payload_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-03-23T18:15:53Z",
                        "host": "127.0.0.1",
                        "exporter": "nats_exporter",
                        "port": 7777,
                        "endpoint": "/debug/vars",
                        "url": "http://127.0.0.1:7777/debug/vars",
                        "ok": True,
                        "status": 200,
                        "body": '{"nats":{"url":"nats://nats_metrics:NatsRead!2026@nats.internal:4222"}}',
                    }
                )
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert _run_db("ingest", "exporters", str(payload_path), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "COLLECT \t127.0.0.1\t7777\t [+] NATS Exporter url=http://127.0.0.1:7777/debug/vars" in output
    assert "VALIDATE\t127.0.0.1\t7777\t [*] Dump Validate NATS Exporter" in output
    assert "VALIDATE\t127.0.0.1\t7777\t reason=connection_string_auth endpoint=/debug/vars" in output
    assert "<redacted:dsn_auth>@nats.internal:4222" in output
    assert "NatsRead!2026" not in output
    assert "..." not in output


def test_db_show_exporters_uses_short_empty_state(db_url: str, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "recent exporters hits/results" not in output
    assert "no recent exporter results" in output


def test_db_show_exporters_trigger_uses_successful_observation_without_finding(
    db_url: str,
    tmp_path: Path,
    capsys,
) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    payload_path = tmp_path / "exporters_trigger.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-03-27T10:00:00Z",
                    "source_type": "trigger",
                    "host": "127.0.0.1",
                    "exporter": "redis_exporter",
                    "port": 9121,
                    "listen_port": 6379,
                    "callback_target": "10.0.0.99",
                    "trigger_url": "http://127.0.0.1:9121/scrape?target=redis://10.0.0.99:6379",
                    "success": True,
                    "probe_success": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    assert _run_db("ingest", "exporters", str(payload_path), "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("show", "exporters", "--trigger", "--db-url", db_url) == 0
    output = ANSI_RE.sub("", capsys.readouterr().out)
    assert "TRIGGER \t10.0.0.99\t6379\t [+] Redis Exporter" in output
    assert "reason=trigger_success" in output
    assert "http://127.0.0.1:9121/scrape?target=redis://10.0.0.99:6379" in output

    assert _run_db("show", "exporters", "--trigger", "--db-url", db_url, "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["shown"] == 1
    assert payload["recent_hits"][0]["phase"] == "trigger"
    assert payload["recent_hits"][0]["status"] == "trigger_success"


def test_db_cli_helper_renderers_and_formatters_cover_text_branches(capsys) -> None:
    assert _format_rows([], ["id"], empty_label="empty") == "empty"
    formatted = _format_rows([{"id": 1, "name": "grafana"}], ["id", "name"])
    assert "id" in formatted and "grafana" in formatted

    _emit_rows([{"id": 1}], ["id"], as_json=False)
    _emit_rows([{"id": 1}], ["id"], as_json=True)
    _emit_dashboard_section("summary", [{"id": 1}], ["id"], empty_label="empty")
    text_output = capsys.readouterr().out
    assert "summary" in text_output
    assert '"id": 1' in text_output

    assert _clip_text("abcdef", 3) == "abc"
    assert _clip_text("abcdef", 5) == "ab..."
    assert _severity_color("high") == "red"
    assert _severity_color("info") == "cyan"
    assert _status_color("completed") == "green"
    assert _status_color("failed") == "red"
    assert _marker_for_status("open") == ("[!]", "orange")
    assert _marker_for_severity("medium") == ("[!]", "orange")
    assert _module_tag("proxmox") == "PVE"
    assert _module_tag(None) == "MODULE"
    assert _timestamp_text("2026-03-23T18:26:43.123456+00:00") == "2026-03-23 18:26:43"
    assert _timestamp_text("") == "-"
    assert _compact_bytes(1024) == "1.0KB"
    assert _compact_bytes("oops") == "oops"
    assert _normalized_ports(["9100", "9100", "abc", "-", "9113"]) == ["9100", "9113", "abc"]

    enriched = _attach_host_port_summaries(
        [{"canonical_key": "10.0.0.10", "ip_address": "10.0.0.10", "hostname": "", "fqdn": ""}],
        [
            {"host": "10.0.0.10", "ip": "10.0.0.10", "port": 3000},
            {"host": "10.0.0.10", "ip": "10.0.0.10", "port": 9090},
        ],
    )
    assert enriched[0]["ports_values"] == ["3000", "9090"]

    console = Console(debug=False)
    _render_database_totals(
        console,
        {
            "hosts_count": 1,
            "endpoints_count": 2,
            "findings_count": 3,
            "runs_count": 4,
            "artifacts_count": 5,
            "import_jobs_count": 6,
            "export_jobs_count": 7,
            "last_seen_at": "2026-03-23T18:26:43Z",
        },
    )
    _render_module_summary_line(
        console,
        {
            "module": "grafana",
            "hosts_count": 1,
            "endpoints_count": 1,
            "findings_count": 2,
            "runs_count": 1,
            "artifacts_count": 1,
            "records_count": 6,
            "last_seen_at": "2026-03-23T18:26:43Z",
        },
        include_records=True,
    )
    _render_host_row(
        console,
        {
            "ip_address": "10.0.0.10",
            "hostname": "grafana",
            "fqdn": "grafana.internal",
            "canonical_key": "10.0.0.10",
            "last_seen_at": "2026-03-23T18:26:43Z",
        },
    )
    _render_module_host_row(
        console,
        {"ip_address": "10.0.0.10", "ports_values": ["3000"], "last_seen_at": "2026-03-23T18:26:43Z"},
        module_name="grafana",
    )
    _render_endpoint_row(
        console,
        {
            "canonical_key": "http://10.0.0.10:3000/login",
            "scheme": "http",
            "host": "10.0.0.10",
            "ip": "",
            "port": 3000,
            "path": "/login",
        },
        verbose=True,
    )
    _render_module_endpoint_row(
        console,
        {
            "canonical_key": "http://10.0.0.10:3000/login",
            "scheme": "http",
            "host": "10.0.0.10",
            "ip": "",
            "port": 3000,
            "path": "/login",
        },
        module_name="grafana",
        verbose=True,
    )
    _render_finding_row(
        console,
        {
            "module_name": "grafana",
            "title": "Grafana anonymous access",
            "finding_type": "anonymous_access",
            "protocol": "grafana",
            "severity": "high",
            "status": "open",
            "last_seen_at": "2026-03-23T18:26:43Z",
        },
    )
    _render_module_recent_hit(
        console,
        {
            "module": "exporters",
            "target": "127.0.0.1:9187",
            "subject": "postgres_exporter",
            "phase": "collect",
            "finding_type": "connection_string_auth",
            "severity": "high",
            "seen_at": "2026-03-23T18:26:43Z",
            "endpoint_or_resource_label": "endpoint",
            "endpoint_or_resource": "/debug/vars",
            "detail_label": "sample",
            "detail": "postgres://postgres:postgres@db/app",
            "title": "postgres_exporter collect credential exposure",
        },
    )
    _render_module_finding_row(
        console,
        {
            "target": "10.0.0.10",
            "endpoint": "http://10.0.0.10:3000",
            "finding_type": "anonymous_access",
            "status": "open",
            "severity": "high",
            "description": "detail",
            "title": "Grafana anonymous access",
            "last_seen_at": "2026-03-23T18:26:43Z",
        },
        module_name="grafana",
    )
    _render_run_row(
        console,
        {
            "module_name": "grafana",
            "source_type": "scan",
            "protocol": "grafana",
            "execution_status": "success",
            "started_at": "2026-03-23T18:26:43Z",
            "finished_at": "2026-03-23T18:27:43Z",
        },
    )
    _render_module_run_row(
        console,
        {
            "source_type": "scan",
            "protocol": "grafana",
            "execution_status": "success",
            "started_at": "2026-03-23T18:26:43Z",
            "finished_at": "2026-03-23T18:27:43Z",
        },
        module_name="grafana",
    )
    _render_artifact_row(
        console,
        {
            "artifact_role": "raw_payload",
            "mime_type": "application/json",
            "content_encoding": "gzip",
            "size_bytes": 1024,
            "sha256": "abcdef1234567890",
            "sanitized_preview_text": "preview text",
        },
    )
    _render_module_artifact_row(
        console,
        {
            "artifact_role": "raw_payload",
            "mime_type": "application/json",
            "content_encoding": "gzip",
            "size_bytes": 1024,
            "sha256": "abcdef1234567890",
            "sanitized_preview_text": "preview text",
        },
        module_name="grafana",
    )
    _emit_line_section(console, "empty lines", [], _render_host_row, empty_label="none")
    _emit_module_recent_hits(console, "grafana", {"recent_hits": [], "limit": 10})
    _emit_module_dashboard(
        console,
        "grafana",
        {
            "summary": {
                "hosts_count": 1,
                "endpoints_count": 1,
                "findings_count": 1,
                "runs_count": 1,
                "artifacts_count": 1,
                "last_seen_at": "2026-03-23T18:26:43Z",
            },
            "findings": [],
            "hosts": [],
            "endpoints": [],
            "runs": [],
        },
        verbose=True,
    )
    rendered = ANSI_RE.sub("", capsys.readouterr().out)
    assert "DB" in rendered
    assert "GRAFANA" in rendered
    assert "preview=" in rendered
    assert "no recent grafana hits/results" in rendered
    assert "recent runs: shown=0" in rendered


def test_run_db_command_covers_error_paths(monkeypatch, capsys) -> None:
    assert run_db_command(Namespace(db_handler_name="missing")) == 2
    assert "unsupported db command" in capsys.readouterr().err

    monkeypatch.setattr(
        "redposture_core.db.cli._ensure_db_ready", lambda _args: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert run_db_command(Namespace(db_handler_name="show_hosts")) == 2
    assert "failed to initialize db: boom" in capsys.readouterr().err

    monkeypatch.setattr("redposture_core.db.cli._ensure_db_ready", lambda _args: None)
    monkeypatch.setitem(db_cli._DB_HANDLERS, "bad", lambda _args: (_ for _ in ()).throw(ValueError("bad-input")))
    assert run_db_command(Namespace(db_handler_name="bad")) == 2
    assert "[error] bad-input" in capsys.readouterr().err


def test_db_cli_search_and_database_import_export_error_paths(db_url: str, tmp_path: Path, capsys) -> None:
    assert _run_db("init", "--db-url", db_url) == 0
    capsys.readouterr()

    assert _run_db("search", "grafana", "--db-url", db_url) == 0
    search_output = capsys.readouterr().out
    assert "No rows" in search_output

    current_path = Path(db_url.removeprefix("sqlite:///"))
    assert _run_db("export", "database", "--db-url", db_url, "--output", str(current_path)) == 2
    assert "export target must be different" in capsys.readouterr().err

    assert _run_db("import", "database", "--db-url", db_url, "--input", str(tmp_path / "missing.sqlite3")) == 2
    assert str(tmp_path / "missing.sqlite3") in capsys.readouterr().err
