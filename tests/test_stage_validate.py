from __future__ import annotations

import re
from pathlib import Path

import pytest

from redposture_core.stage_validate import (
    VALIDATION_PRECISION_COLLECT_STRICT,
    VALIDATION_PRECISION_LEGACY,
    ValidationRecordAccumulator,
    run_validation,
    run_validation_records,
    scan_validation_hits,
)


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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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


def test_validate_records_collect_strict_suppresses_placeholder_conn_string() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "https://$ES_USERNAME:$ES_PASSWORD@localhost:9200\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_keeps_real_conn_string_detection() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "https://metrics:Sup3rS3cret-2026@localhost:9200\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_suppresses_query_placeholder_secret() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "jdbc:postgresql://db.local/app?user=postgres&password=${DB_PASSWORD}\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_suppresses_dummy_values() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "password=changeme token=example\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_suppresses_low_quality_token_value() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "[CRED] api_token=token\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_keeps_high_quality_token_value() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "[CRED] api_token=A1b2C3d4E5f6G7h8I9j0K1l2\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_deny_context_suppresses_medium_only_hit() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "password=Sup3rS3cret2026 template example\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_deny_context_penalizes_but_keeps_strong_hit() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "template https://elastic:password@elastic.local:9200\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_cross_line_user_password_correlation() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "username=metrics_collector\npassword=R34lSecurePass2026\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_keeps_known_default_pair() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/debug/vars",
            "body": "DATA_SOURCE_NAME=postgresql://postgres:postgres@db.local/app\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_keeps_strong_signal_jwt() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aGVsbG8gd29ybGQ.c2lnbmF0dXJl\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_metrics_gates_medium_only_hit() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "postgres_exporter",
            "endpoint": "/metrics",
            "body": 'metric_name{password="Sup3rS3cret2026"} 1\n',
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0


def test_validate_records_collect_strict_metrics_accepts_strong_signal() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/metrics",
            "body": "jdbc:postgresql://db.local/app?user=postgres&password=postgres\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 1


def test_validate_records_collect_strict_debug_shows_score_and_gate(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9100,
            "exporter": "postgres_exporter",
            "endpoint": "/metrics",
            "body": 'metric_name{password="Sup3rS3cret2026"} 1\n',
        }
    ]
    rc = run_validation_records(
        records,
        show=True,
        fail_on_creds=False,
        debug=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc == 0
    output = re.sub(r"\x1b\[[0-9;]*m", "", f"{capsys.readouterr().out}\n")
    assert "Score:" in output
    assert "gated_non_debug=yes" in output
    assert "Policy: metrics_profile" in output


def test_scan_validation_hits_collect_strict_adds_cross_line_strong_correlation_signal() -> None:
    body = "[CRED] leaked marker\nAuthorization: Basic bWV0cmljczpzM2NyM3Q=\n"
    _line_count, hits = scan_validation_hits(
        body,
        input_format="txt",
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    reasons = [str(item.get("reason") or "") for item in hits]
    assert any("correlated_with_strong" in reason for reason in reasons)


def test_validate_records_collect_strict_cmdline_structured_split_variants() -> None:
    spaced = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": (
                "/usr/local/bin/kafka_exporter --kafka.server kafka-1.internal:9093 "
                "--sasl.username metrics_collector --sasl.password Sup3rS3cret2026\n"
            ),
        }
    ]
    equals = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": (
                "/usr/local/bin/kafka_exporter --kafka.server=kafka-1.internal:9093 "
                "--sasl.username=metrics_collector --sasl.password=Sup3rS3cret2026\n"
            ),
        }
    ]
    rc_spaced = run_validation_records(
        spaced,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    rc_equals = run_validation_records(
        equals,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert rc_spaced == 1
    assert rc_equals == 1


def test_collect_strict_vulnerable_credentials_extracts_wordlists_from_shown_hits() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--es.uri=https://elastic:ElasticRead2026!@elastic.local:9200?api_key=ZXMtbGFiLWFwaS1rZXktMjAyNg==\n",
        },
        {
            "host": "127.0.0.2",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--sasl.username metrics_collector --sasl.password Sup3rS3cret2026\n",
        },
        {
            "host": "127.0.0.4",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/vars",
            "body": (
                '{\n  "sasl_username": "json_metrics",\n'
                '  "sasl_password": "JsonPass2026!",\n'
                '  "probe_url": "https://metrics_reader:ReaderPass2026!@kafka.local:9093"\n}\n'
            ),
        },
        {
            "host": "127.0.0.3",
            "port": 9100,
            "exporter": "node_exporter",
            "endpoint": "/debug/vars",
            "body": "Authorization: Bearer A1b2C3d4E5f6G7h8I9j0K1l2\n",
        },
    ]
    accumulator = ValidationRecordAccumulator(
        input_format="auto",
        max_lines=0,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    for record in records:
        accumulator.feed(record)

    users, passwords, api_keys = accumulator.vulnerable_credentials_from_shown_hits()

    assert users == ["elastic", "metrics_collector", "metrics_reader", "json_metrics"]
    assert passwords == ["ElasticRead2026!", "Sup3rS3cret2026", "ReaderPass2026!", "JsonPass2026!"]
    assert api_keys == [
        "127.0.0.1:9114:ZXMtbGFiLWFwaS1rZXktMjAyNg==",
        "127.0.0.3:9100:A1b2C3d4E5f6G7h8I9j0K1l2",
    ]
    assert accumulator.vulnerable_login_rows_from_shown_hits() == [
        ("127.0.0.1", "elastic", "ElasticRead2026!"),
        ("127.0.0.2", "metrics_collector", "Sup3rS3cret2026"),
        ("127.0.0.4", "metrics_reader", "ReaderPass2026!"),
        ("127.0.0.4", "json_metrics", "JsonPass2026!"),
    ]
    findings = accumulator.vulnerable_findings_from_shown_hits()
    assert any(item["host"] == "127.0.0.1" and item["passwords"] == ["ElasticRead2026!"] for item in findings)
    assert any(item["api_keys"] == ["127.0.0.3:9100:A1b2C3d4E5f6G7h8I9j0K1l2"] for item in findings)


def test_collect_strict_vulnerable_login_pairs_strip_jsonish_cmdline_quotes() -> None:
    accumulator = ValidationRecordAccumulator(
        input_format="auto",
        max_lines=0,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    accumulator.feed(
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": '("--sasl.username=exporter","--sasl.password=superpassword123456",)\n',
        }
    )

    assert accumulator.vulnerable_login_rows_from_shown_hits() == [("127.0.0.1", "exporter", "superpassword123456")]
    users, passwords, _api_keys = accumulator.vulnerable_credentials_from_shown_hits()
    assert users == ["exporter"]
    assert passwords == ["superpassword123456"]


def test_collect_strict_vulnerable_credentials_ignore_gated_placeholder_values() -> None:
    accumulator = ValidationRecordAccumulator(
        input_format="auto",
        max_lines=0,
        precision_profile=VALIDATION_PRECISION_COLLECT_STRICT,
    )
    accumulator.feed(
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "https://$ES_USERNAME:$ES_PASSWORD@localhost:9200\npassword=changeme\n",
        }
    )

    assert accumulator.vulnerable_credentials_from_shown_hits() == ([], [], [])


def test_validate_records_legacy_still_detects_placeholder_conn_string() -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9114,
            "exporter": "elasticsearch_exporter",
            "endpoint": "/debug/vars",
            "body": "https://$ES_USERNAME:$ES_PASSWORD@localhost:9200\n",
        }
    ]
    rc = run_validation_records(
        records,
        fail_on_creds=True,
        precision_profile=VALIDATION_PRECISION_LEGACY,
    )
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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

    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
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
        ("pgbackrest_exporter", "pgBackRest Exporter"),
        ("victoriametrics_exporter", "VictoriaMetrics Exporter"),
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


def test_validate_records_suppresses_metric_query_sql_noise() -> None:
    records = [
        {
            "host": "10.46.128.105",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/metrics",
            "body": (
                'ccp_io_cpu_pg_stat_statements_calls{datname="vacancy",'
                'query="SELECT usename, passwd FROM pg_shadow WHERE usename=$1",'
                'queryid="7208025334231650648",rolname="username",'
                'server="/var/run/postgresql/:5432",toplevel="true"} 4.5813332e+07\n'
            ),
        }
    ]
    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 0


def test_validate_records_keeps_metric_query_with_explicit_secret_assignment() -> None:
    records = [
        {
            "host": "10.46.128.106",
            "port": 9187,
            "exporter": "postgres_exporter",
            "endpoint": "/metrics",
            "body": (
                'ccp_stmt{query="SELECT 1 /* password=Sup3rS3cret-2026 */",'
                'datname="app",server="/var/run/postgresql/:5432"} 1\n'
            ),
        }
    ]
    rc = run_validation_records(records, fail_on_creds=True)
    assert rc == 1


def test_validate_records_renders_human_reason_and_hides_signals_without_debug(
    capsys: pytest.CaptureFixture[str],
) -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": (
                "/usr/local/bin/kafka_exporter --kafka.server=kafka-1.internal:9093 "
                "--sasl.username=metrics_collector --sasl.password=Kfka-M0nitor-2026\n"
            ),
        }
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    plain_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    assert "Endpoint: /debug/pprof/cmdline?debug=1" in plain_output
    assert "Reason:" in plain_output
    assert "conn creds" in plain_output
    assert "Signals:" not in plain_output


def test_validate_records_renders_signals_in_debug(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "127.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": (
                "/usr/local/bin/kafka_exporter --kafka.server=kafka-1.internal:9093 "
                "--sasl.username=metrics_collector --sasl.password=Kfka-M0nitor-2026\n"
            ),
        }
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False, debug=True)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    plain_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    assert "Signals:" in plain_output
    assert "connection_string_auth" in plain_output


def test_validate_records_evidence_contains_hit_highlight(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--sasl.password=Kfka-M0nitor-2026\n",
        }
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert "Leak:" in output
    assert "[HIT]" not in output
    assert "[/HIT]" not in output


def test_validate_records_evidence_does_not_append_more_suffix(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.2",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/vars",
            "body": "password=Sup3rS3cret token=AbCdEf1234567890\n",
        }
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert re.search(r"\(\+\d+ more\)", output) is None


def test_validate_records_groups_duplicates_with_count_and_unique_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    records = [
        {
            "host": "10.0.0.9",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--sasl.password=FirstSecret-2026\n",
        },
        {
            "host": "10.0.0.9",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--sasl.password=SecondSecret-2026\n",
        },
    ]
    rc = run_validation_records(records, show=True, fail_on_creds=False)
    assert rc == 0
    captured = capsys.readouterr()
    plain = re.sub(r"\x1b\[[0-9;]*m", "", f"{captured.out}\n{captured.err}")
    assert "Count: 2" in plain
    assert "SecondSecret-2026" in plain
    assert "credential_hits=2 unique_hits=1" in plain


def test_validate_records_debug_emits_staged_markers(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "host": "10.0.0.1",
            "port": 9308,
            "exporter": "kafka_exporter",
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "--sasl.password=Sup3rS3cret2026\n",
        }
    ]

    rc = run_validation_records(records, show=False, fail_on_creds=False, debug=True)
    assert rc == 0
    plain = re.sub(r"\x1b\[[0-9;]*m", "", f"{capsys.readouterr().out}\n")
    assert "pass=1 detect start total=1" in plain
    assert "pass=2 deep start total=1" in plain
    assert "stage2_gate=run reason=credential_hits>0" in plain
    assert "stage_timing_summary status=hits attempts=1/1" in plain
