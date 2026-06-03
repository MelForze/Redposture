from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_postrun import (
    _EXPECTED_LABELS,
    _EXPECTED_MODULES,
    _EXTENDED_EXPECTED_LABELS,
    _PROGRESS_EXPECTED_TARGETS,
    _combined_run_output,
    _expected_labels_for_profile,
    _infer_target_count_from_jsonl,
    _parse_status_file,
    _progress_counts_from_log,
    _validate_expected_exits,
    _validate_expected_labels,
    _validate_openapi_artifacts,
    _validate_output_sanity,
    _validate_rich_lab_outputs,
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


def test_validate_expected_labels_profile_extended_requires_extended_labels() -> None:
    rows = [{"module": "elastic", "label": label} for label in _EXPECTED_LABELS]
    with pytest.raises(SystemExit, match="missing expected labels"):
        _validate_expected_labels(rows, profile="extended")

    rows.extend({"module": "elastic", "label": label} for label in _EXTENDED_EXPECTED_LABELS)
    _validate_expected_labels(rows, profile="extended")


def test_expected_labels_for_profile_rejects_unknown_profile() -> None:
    with pytest.raises(SystemExit, match="unsupported verifier profile"):
        _expected_labels_for_profile("full")


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


def test_validate_output_sanity_infers_targets_from_json_artifact(tmp_path: Path) -> None:
    log = tmp_path / "oracle.log"
    log.write_text("ORACLE logger-only output\n", encoding="utf-8")
    jsonl = tmp_path / "oracle.json"
    jsonl.write_text(
        "\n".join(
            f'{{"host":"127.0.0.1","port":{port},"status":"valid_credentials"}}'
            for port in (1521, 31521, 31522, 31523, 31524)
        ),
        encoding="utf-8",
    )
    rows = [
        {
            "module": "oracle",
            "label": "oracle_multi_ports",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(jsonl),
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


def test_mongodb_expected_labels_and_progress_targets() -> None:
    for label in (
        "mongodb_open",
        "mongodb_auth",
        "mongodb_defcreds",
        "mongodb_multi_ports",
        "mongodb_query_dump",
        "mongodb_debug_smoke",
    ):
        assert label in _EXPECTED_LABELS
    assert _PROGRESS_EXPECTED_TARGETS["mongodb_multi_ports"] == 5


def test_docker_expected_labels_and_progress_targets() -> None:
    for label in {
        "docker_open",
        "docker_tls",
        "docker_multi_ports",
        "docker_inventory",
        "docker_exec",
        "docker_debug_smoke",
    }:
        assert label in _EXPECTED_LABELS
    assert "docker" in _EXPECTED_MODULES
    assert _PROGRESS_EXPECTED_TARGETS["docker_multi_ports"] == 5


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


def test_combined_run_output_includes_text_sibling_for_text_cases(tmp_path: Path) -> None:
    log = tmp_path / "oracle_listener_protected.log"
    text = tmp_path / "oracle_listener_protected.txt"
    log.write_text("logger warning\n", encoding="utf-8")
    text.write_text("Listener Dump password_protected=True\n", encoding="utf-8")

    combined = _combined_run_output(
        {
            "module": "oracle",
            "label": "oracle_listener_protected",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": "-",
            "log_path": str(log),
        }
    )

    assert "logger warning" in combined
    assert "password_protected=True" in combined


def test_validate_rich_lab_outputs_rejects_empty_kafka_dump(tmp_path: Path) -> None:
    artifact = tmp_path / "kafka.jsonl"
    log = tmp_path / "kafka.log"
    artifact.write_text(
        '{"type":"topics_list","topics":["orders"]}\n{"type":"topic_dump","topic":"orders"}\n', encoding="utf-8"
    )
    log.write_text("<no messages>\n", encoding="utf-8")

    rows = [
        {
            "module": "kafka",
            "label": "kafka_open",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="missing expected seeded lab data|empty/unseeded"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_requires_qdrant_seeded_collections(tmp_path: Path) -> None:
    artifact = tmp_path / "qdrant.jsonl"
    log = tmp_path / "qdrant.log"
    artifact.write_text('{"type":"collections","collections":["demo_vectors"]}\n', encoding="utf-8")
    log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "qdrant",
            "label": "qdrant_default",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="missing expected seeded lab data"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_requires_zookeeper_dump_for_all_ports(tmp_path: Path) -> None:
    artifact = tmp_path / "zookeeper.jsonl"
    log = tmp_path / "zookeeper.log"
    artifact.write_text(
        "\n".join(
            [
                '{"type":"znodes_dump","port":2181,"znode_values":["/redposture/app/api_key:rp-zk-key-2026"]}',
                '{"type":"znodes_dump","port":22181,"znode_values":["/redposture/app/api_key:rp-zk-key-2026"]}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "zookeeper",
            "label": "zookeeper_multi_ports",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="did not dump znodes for all expected ports"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_accepts_seeded_happy_paths(tmp_path: Path) -> None:
    kafka = tmp_path / "kafka.jsonl"
    kafka_log = tmp_path / "kafka.log"
    kafka.write_text(
        '{"type":"topics_list","topics":["orders","payments.events","audit.logs","security.alerts"]}\n'
        '{"type":"topic_dump","topic":"orders","messages":["ord-1001"]}\n',
        encoding="utf-8",
    )
    kafka_log.write_text("", encoding="utf-8")

    zookeeper = tmp_path / "zookeeper.jsonl"
    zookeeper_log = tmp_path / "zookeeper.log"
    zookeeper.write_text(
        "\n".join(
            f'{{"type":"znodes_dump","port":{port},"znode_values":["/redposture/app/api_key:rp-zk-key-2026"]}}'
            for port in (2181, 22181, 22182, 22183, 22184)
        )
        + "\n",
        encoding="utf-8",
    )
    zookeeper_log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "kafka",
            "label": "kafka_open",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(kafka),
            "log_path": str(kafka_log),
        },
        {
            "module": "zookeeper",
            "label": "zookeeper_multi_ports",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(zookeeper),
            "log_path": str(zookeeper_log),
        },
    ]
    _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_accepts_proxmox_json_findings(tmp_path: Path) -> None:
    artifact = tmp_path / "proxmox.jsonl"
    log = tmp_path / "proxmox.log"
    artifact.write_text(
        '{"type":"credential_hit","host":"127.0.0.1","port":18006,'
        '"sample":"GitLabCloudInit!2026","path":"$.cipassword"}\n'
        '{"type":"nodes","nodes":["pve-edge-01","pve-core-02"]}\n',
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "proxmox",
            "label": "proxmox_admin",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_accepts_oracle_json_artifacts(tmp_path: Path) -> None:
    wallet = tmp_path / "oracle_wallet.jsonl"
    wallet_log = tmp_path / "oracle_wallet.log"
    wallet.write_text(
        '{"type":"wallet_findings","wallet_findings":[{"file_name":"redposture_wallet_hint.txt","data":"wallet"}]}\n',
        encoding="utf-8",
    )
    wallet_log.write_text("", encoding="utf-8")

    large_file = tmp_path / "oracle_large_file.jsonl"
    large_file_log = tmp_path / "oracle_large_file.log"
    large_file.write_text(
        '{"type":"file_results","file_results":[{"action":"download","path":"redposture_large_file.txt",'
        '"ok":true,"bytes":4096}]}\n',
        encoding="utf-8",
    )
    large_file_log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "oracle",
            "label": "oracle_wallet_extract",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(wallet),
            "log_path": str(wallet_log),
        },
        {
            "module": "oracle",
            "label": "oracle_large_file_resume",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(large_file),
            "log_path": str(large_file_log),
        },
    ]
    _validate_rich_lab_outputs(rows)


def test_sequential_matrix_uses_deep_dump_for_multi_target_seeded_labs() -> None:
    matrix = Path("scripts/run_lab_matrix_sequential.sh").read_text(encoding="utf-8")

    assert "qdrant_multi_instance_urls" in matrix
    assert "qdrant_multi_instance_urls 0 qdrant" in matrix
    assert "qdrant_multi_instance_urls 0 qdrant" in matrix and "--collections --dump" in matrix
    assert "kafka_multi_ports 0 kafka" in matrix and "--show-topics --dump --max-messages 10" in matrix
    assert "zookeeper_multi_ports 0 zookeeper" in matrix and "--show-znodes --dump" in matrix
    assert "registry_gitlab 0 registry" in matrix and "--token glrt-lab-token --gitlab --images" in matrix
