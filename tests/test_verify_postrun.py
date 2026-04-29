from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_postrun import (
    _EXPECTED_LABELS,
    _PROGRESS_EXPECTED_TARGETS,
    _infer_target_count_from_jsonl,
    _parse_status_file,
    _progress_counts_from_log,
    _validate_expected_exits,
    _validate_expected_labels,
    _validate_openapi_artifacts,
    _validate_output_sanity,
)


def _write_status(path: Path, header: str, rows: list[str]) -> None:
    body = "\n".join(rows)
    path.write_text(f"{header}\n{body}\n", encoding="utf-8")


def test_parse_status_file_supports_legacy_header(tmp_path: Path) -> None:
    status = tmp_path / "matrix-status.tsv"
    _write_status(
        status,
        "module\tlabel\texit_code\tjson_path\tlog_path",
        ["elastic\telastic_open\t0\t/tmp/elastic_open.json\t/tmp/elastic_open.log"],
    )

    rows = _parse_status_file(status)

    assert rows == [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "/tmp/elastic_open.json",
            "log_path": "/tmp/elastic_open.log",
        }
    ]


def test_parse_status_file_supports_new_header(tmp_path: Path) -> None:
    status = tmp_path / "matrix-status.tsv"
    _write_status(
        status,
        "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path",
        ["elastic\telastic_open\t2\t2\t-\t/tmp/elastic_open.log"],
    )

    rows = _parse_status_file(status)

    assert rows == [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "2",
            "exit_code": "2",
            "json_path": "-",
            "log_path": "/tmp/elastic_open.log",
        }
    ]


def test_validate_expected_exits_fails_on_mismatch() -> None:
    rows = [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "2",
            "exit_code": "0",
            "json_path": "-",
            "log_path": "/tmp/elastic_open.log",
        }
    ]
    with pytest.raises(SystemExit, match="exit mismatch"):
        _validate_expected_exits(rows)


def test_validate_expected_labels_fails_when_missing_label() -> None:
    rows = [{"module": "elastic", "label": _EXPECTED_LABELS[0]}]
    with pytest.raises(SystemExit, match="missing expected labels"):
        _validate_expected_labels(rows)


def test_validate_expected_labels_passes_with_full_label_set() -> None:
    rows = [{"module": "elastic", "label": label} for label in _EXPECTED_LABELS]
    _validate_expected_labels(rows)


def test_progress_counts_from_log_parses_counts() -> None:
    text = "Running redposture against 1 target\nsomething\nRunning redposture against 5 targets\n"
    assert _progress_counts_from_log(text) == [1, 5]


def test_infer_target_count_from_jsonl_counts_unique_host_port_pairs() -> None:
    text = (
        '{"host":"127.0.0.1","port":15000}\n'
        '{"host":"127.0.0.1","port":15001}\n'
        '{"host":"127.0.0.1","port":15000}\n'
        "not-json\n"
    )
    assert _infer_target_count_from_jsonl(text) == 2


def test_validate_output_sanity_detects_single_target_regression(tmp_path: Path) -> None:
    log = tmp_path / "consul.log"
    log.write_text(
        "Running redposture against 1 target\nRunning redposture against 1 target\n",
        encoding="utf-8",
    )
    rows = [
        {
            "module": "consul",
            "label": "consul_multi_instance_urls",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="progress target count mismatch|single-target batches"):
        _validate_output_sanity(rows)


def test_validate_output_sanity_rejects_debug_trace_leak(tmp_path: Path) -> None:
    log = tmp_path / "elastic.log"
    log.write_text("stage_trace stage_name=detect attempt=1 duration_ms=3 result=ok error=-\n", encoding="utf-8")
    rows = [
        {
            "module": "elastic",
            "label": "elastic_open",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="unexpected debug stage_trace"):
        _validate_output_sanity(rows)


def test_validate_output_sanity_rejects_noisy_connection_failed_line(tmp_path: Path) -> None:
    log = tmp_path / "redis.log"
    log.write_text(
        "REDIS 127.0.0.1 6379 [!] connection failed err=[Errno 111] Connection refused\n",
        encoding="utf-8",
    )
    rows = [
        {
            "module": "redis",
            "label": "redis_default",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="unexpected noisy connection failed line"):
        _validate_output_sanity(rows)


def test_validate_output_sanity_passes_for_expected_multi_target_log(tmp_path: Path) -> None:
    log = tmp_path / "kafka.log"
    log.write_text("Running redposture against 5 targets\n", encoding="utf-8")
    rows = [
        {
            "module": "kafka",
            "label": "kafka_multi_ports",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    _validate_output_sanity(rows)


def test_validate_output_sanity_allows_repeated_same_progress_total(tmp_path: Path) -> None:
    log = tmp_path / "consul.log"
    log.write_text(
        "Running redposture against 5 targets\nRunning redposture against 5 targets\n",
        encoding="utf-8",
    )
    rows = [
        {
            "module": "consul",
            "label": "consul_multi_instance_urls",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    _validate_output_sanity(rows)


def test_validate_output_sanity_rejects_mixed_progress_totals(tmp_path: Path) -> None:
    log = tmp_path / "consul.log"
    log.write_text(
        "Running redposture against 5 targets\nRunning redposture against 4 targets\n",
        encoding="utf-8",
    )
    rows = [
        {
            "module": "consul",
            "label": "consul_multi_instance_urls",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="progress target count mismatch"):
        _validate_output_sanity(rows)


def test_clickhouse_multi_ports_expected_targets_is_five() -> None:
    assert _PROGRESS_EXPECTED_TARGETS["clickhouse_multi_ports"] == 5


def test_grpc_multi_ports_expected_targets_is_five() -> None:
    assert _PROGRESS_EXPECTED_TARGETS["grpc_multi_ports"] == 5


def test_grpc_expected_labels_include_feature_wave() -> None:
    for label in (
        "grpc_invoke_health",
        "grpc_proto_invoke",
        "grpc_protoset_invoke",
        "grpc_openapi_export",
        "grpc_web_detect",
    ):
        assert label in _EXPECTED_LABELS


def test_validate_openapi_artifacts_checks_grpc_export(tmp_path: Path) -> None:
    json_dir = tmp_path / "json"
    json_dir.mkdir()
    (json_dir / "grpc_openapi.json").write_text(
        """
        {
          "openapi": "3.1.0",
          "paths": {
            "/grpc.health.v1.Health/Check": {
              "post": {
                "x-grpc-service": "grpc.health.v1.Health",
                "x-grpc-method": "Check",
                "x-grpc-input-type": "grpc.health.v1.HealthCheckRequest",
                "x-grpc-output-type": "grpc.health.v1.HealthCheckResponse",
                "x-grpc-streaming": {"client": false, "server": false}
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )
    rows = [
        {
            "module": "grpc",
            "label": "grpc_openapi_export",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": "-",
        }
    ]
    _validate_openapi_artifacts(tmp_path, rows)


def test_validate_output_sanity_allows_multi_target_json_log_without_progress(tmp_path: Path) -> None:
    log = tmp_path / "registry_multi.log"
    log.write_text(
        "\n".join(f'{{"host":"127.0.0.1","port":1500{i},"type":"detect"}}' for i in range(5)) + "\n",
        encoding="utf-8",
    )
    rows = [
        {
            "module": "registry",
            "label": "registry_multi_instance_urls",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    ]
    _validate_output_sanity(rows)
