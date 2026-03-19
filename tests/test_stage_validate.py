from __future__ import annotations

from pathlib import Path

import pytest

from redposture_core.stage_validate import run_validation, run_validation_records


def test_validate_detects_cred_marker(tmp_path: Path) -> None:
    path = tmp_path / "trigger.txt"
    path.write_text("[12:00:00] [CRED] [REDIS] 10.0.0.1:6379 user=redis pass=redis\n", encoding="utf-8")

    rc = run_validation(str(path), fail_on_creds=True)
    assert rc == 1


def test_validate_detects_json_sensitive_key(tmp_path: Path) -> None:
    path = tmp_path / "index.jsonl"
    path.write_text('{"service":"collect","endpoint":"/debug/vars","password":"secret"}\n', encoding="utf-8")

    rc = run_validation(str(path), input_format="json", fail_on_creds=True)
    assert rc == 1


def test_validate_directory_without_hits_returns_zero(tmp_path: Path) -> None:
    folder = tmp_path / "collect_raw"
    folder.mkdir()
    (folder / "a.txt").write_text("version=1\nmodule=node\n", encoding="utf-8")

    rc = run_validation(str(folder))
    assert rc == 0


def test_validate_records_detects_credential_without_files() -> None:
    records = [
        {
            "host": "10.0.0.1",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "password=secret\n",
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_detects_multiline_json_sensitive_key(tmp_path: Path) -> None:
    path = tmp_path / "vars.txt"
    path.write_text(
        '{\n  "kafka": {\n    "sasl_username": "metrics_collector",\n    "sasl_password": "Kfka-M0nitor-2026"\n  }\n}\n',
        encoding="utf-8",
    )

    rc = run_validation(str(path), fail_on_creds=True)
    assert rc == 1


def test_validate_records_reports_sasl_username_when_paired_with_password(capsys) -> None:
    records = [
        {
            "host": "10.0.0.7",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/vars",
            "body": (
                "{\n"
                '  "kafka": {\n'
                '    "sasl_username": "metrics_collector",\n'
                '    "sasl_password": "Kfka-M0nitor-2026"\n'
                "  }\n"
                "}\n"
            ),
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "sasl_username" in output


def test_validate_records_detects_basic_auth_header() -> None:
    records = [
        {
            "host": "10.0.0.2",
            "port": 9115,
            "exporter": "blackbox_exporter",
            "endpoint": "/debug/vars",
            "body": "Authorization: Basic bWV0cmljczpzM2NyM3Q=\n",
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_detects_url_query_secret() -> None:
    records = [
        {
            "host": "10.0.0.3",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/vars",
            "body": "probe_url=https://kafka.local/bootstrap?access_token=abc123456789\n",
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_detects_cmd_flag_and_jwt() -> None:
    records = [
        {
            "host": "10.0.0.4",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": (
                "/usr/local/bin/kafka_exporter --sasl.password=Kfka-M0nitor-2026 "
                "Authorization: Bearer "
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiJtZXRyaWNzIiwiZXhwIjoxNzQwMDAwMDAwfQ."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
            ),
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_detects_private_key_pem_marker() -> None:
    records = [
        {
            "host": "10.0.0.5",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkq\n-----END PRIVATE KEY-----\n",
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_ignores_empty_or_masked_values() -> None:
    records = [
        {
            "host": "10.0.0.6",
            "port": 9121,
            "exporter": "redis_exporter",
            "endpoint": "/debug/vars",
            "body": 'sasl_password="*****"\npassword=<empty>\nmasterauth none\n',
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 0


def test_validate_jsonl_file_in_json_mode(tmp_path: Path) -> None:
    path = tmp_path / "scan.jsonl"
    path.write_text('{"password":"secret123"}\n{"token":"abc123456"}\n', encoding="utf-8")

    rc = run_validation(str(path), input_format="json", fail_on_creds=True)
    assert rc == 1


def test_validate_records_detects_pgpass_line_without_keywords() -> None:
    records = [
        {
            "host": "10.0.0.8",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "body": "db.local:5432:appdb:metrics:Sup3rS3cret2026\n",
        }
    ]
    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_detects_url_basic_auth_without_explicit_keys() -> None:
    records = [
        {
            "host": "10.0.0.9",
            "port": 9115,
            "exporter": "blackbox_exporter",
            "endpoint": "/debug/vars",
            "body": "https://metrics_user:Sup3rS3cret!2026@metrics.internal/probe\n",
        }
    ]
    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


@pytest.mark.parametrize(
    ("exporter", "display"),
    [
        ("nats_exporter", "NATS Exporter"),
        ("statsd_exporter", "StatsD Exporter"),
        ("mysqld_exporter", "MySQLd Exporter"),
        ("haproxy_exporter", "HAProxy Exporter"),
        ("memcached_exporter", "Memcached Exporter"),
        ("nginx_exporter", "Nginx Exporter"),
        ("elasticsearch_exporter", "Elasticsearch Exporter"),
        ("snmp_exporter", "SNMP Exporter"),
        ("apache_exporter", "Apache Exporter"),
        ("bind_exporter", "BIND Exporter"),
        ("ceph_exporter", "Ceph Exporter"),
        ("varnish_exporter", "Varnish Exporter"),
        ("windows_exporter", "Windows Exporter"),
        ("ipmi_exporter", "IPMI Exporter"),
        ("rabbitmq_exporter", "RabbitMQ Exporter"),
        ("sql_exporter", "SQL Exporter"),
    ],
)
def test_validate_records_uses_display_name_for_new_exporters(
    capsys: pytest.CaptureFixture[str], exporter: str, display: str
) -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9999,
            "exporter": exporter,
            "endpoint": "/debug/vars",
            "body": "password=TopSecret-2026\n",
        }
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert f"Dump Validate {display}" in output
