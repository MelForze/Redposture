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


def test_validate_records_detects_cmd_connection_string_for_elastic(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.10",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--es.uri=https://elastic:password@elastic.mydomain.local\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "cmd_connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_postgres_data_source_name_default_pair(
    capsys: pytest.CaptureFixture[str],
) -> None:
    records = [
        {
            "host": "10.0.0.11",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "DATA_SOURCE_NAME=postgresql://postgres:postgres@db.local/app\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_mongodb_uri_default_pair(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.12",
            "port": 9216,
            "exporter": "mongodb_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--mongodb.uri=mongodb://root:root@mongo.local/admin\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "cmd_connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_rabbit_url_default_pair(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.13",
            "port": 9419,
            "exporter": "rabbitmq_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--rabbit.url=http://guest:guest@rabbit.local:15672\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "cmd_connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_json_connection_string_field(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.14",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": '{"es.uri":"https://elastic:password@elastic.mydomain.local"}\n',
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "es.uri:connection_string_auth" in output
    assert "es.uri:default_creds_known_pair" in output


def test_validate_records_detects_basic_auth_known_default_pair(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.15",
            "port": 9419,
            "exporter": "rabbitmq_exporter",
            "endpoint": "/debug/vars",
            "body": "Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "authorization_basic" in output
    assert "default_creds_known_pair" in output


def test_validate_records_ignores_non_secret_connection_string_without_auth() -> None:
    records = [
        {
            "host": "10.0.0.16",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--es.uri=https://elastic.mydomain.local\n",
        }
    ]

    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 0


def test_validate_records_does_not_flag_unknown_default_like_pair(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.17",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--es.uri=https://elastic:changeme@elastic.mydomain.local\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "cmd_connection_string_auth" in output
    assert "default_creds_known_pair" not in output


def test_validate_records_detects_sqlalchemy_connection_string(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.18",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "body": "sqlalchemy.url=postgresql+psycopg2://postgres:postgres@db.local/app\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_jdbc_query_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.19",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "body": "jdbc:postgresql://db.local/app?user=postgres&password=postgres\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_query_secret" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_jdbc_sqlserver_semicolon_dsn(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.20",
            "port": 9399,
            "exporter": "sql_exporter",
            "endpoint": "/debug/vars",
            "body": "jdbc:sqlserver://sql.local:1433;user=sa;password=Sup3rS3cret!2026;databaseName=master\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output


def test_validate_records_detects_semicolon_server_user_id_password_dsn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    records = [
        {
            "host": "10.0.0.21",
            "port": 9399,
            "exporter": "sql_exporter",
            "endpoint": "/debug/vars",
            "body": "Server=tcp:sql.local,1433;User ID=sa;Password=Sup3rS3cret!2026;Database=master\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output


def test_validate_records_detects_libpq_keyword_dsn(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.22",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "body": "host=db.local port=5432 dbname=app user=postgres password=postgres\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output
    assert "default_creds_known_pair" in output


def test_validate_records_detects_mysql_tcp_style_dsn(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.23",
            "port": 9104,
            "exporter": "mysqld_exporter",
            "endpoint": "/debug/vars",
            "body": "root:root@tcp(db.local:3306)/app\n",
        }
    ]

    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "connection_string_auth" in output
    assert "default_creds_known_pair" in output


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
