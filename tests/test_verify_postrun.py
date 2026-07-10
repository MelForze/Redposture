from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_postrun
from scripts.verify_postrun import (
    _EXPECTED_FAILURE_OUTPUT_SUBSTRINGS,
    _EXPECTED_LABELS,
    _EXPECTED_MODULES,
    _EXTENDED_EXPECTED_LABELS,
    _FUZZ_LABELS,
    _PROGRESS_EXPECTED_TARGETS,
    _combined_run_output,
    _expected_labels_for_profile,
    _golden_text_for_row,
    _infer_target_count_from_jsonl,
    _parse_status_file,
    _progress_counts_from_log,
    _validate_capability_sanity,
    _validate_cross_case_invariants,
    _validate_dump_not_empty,
    _validate_elapsed_sanity,
    _validate_expected_exits,
    _validate_expected_failure_outputs,
    _validate_expected_labels,
    _validate_multi_record_consistency,
    _validate_openapi_artifacts,
    _validate_output_sanity,
    _validate_rich_lab_outputs,
    _validate_schema_mandatory_fields,
    _validate_stage_coherence,
    _validate_status_coherence,
    _validate_tee_when_output_set,
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


def test_golden_text_for_row_ignores_parallel_target_completion_order(tmp_path: Path) -> None:
    artifact = tmp_path / "multi-port.jsonl"
    row = {
        "module": "registry",
        "label": "registry_multi_instance_urls",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = '{"host":"127.0.0.1","port":15010,"status":"open_no_auth"}\n'
    second = '{"host":"127.0.0.1","port":15011,"status":"open_no_auth"}\n'

    artifact.write_text(first + second, encoding="utf-8")
    forward = _golden_text_for_row(row)
    artifact.write_text(second + first, encoding="utf-8")
    reverse = _golden_text_for_row(row)

    assert forward == reverse
    assert forward is not None
    assert '"port": 15010' in forward
    assert '"port": 15011' in forward


def test_golden_snapshot_comparison_ignores_parallel_target_completion_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "multi-port.jsonl"
    artifact.write_text(
        '{"host":"127.0.0.1","port":15011,"status":"open_no_auth"}\n'
        '{"host":"127.0.0.1","port":15010,"status":"open_no_auth"}\n',
        encoding="utf-8",
    )
    golden_dir = tmp_path / "golden"
    golden_dir.mkdir()
    (golden_dir / "registry_multi_instance_urls.json").write_text(
        "[\n"
        '  {"host": "127.0.0.1", "port": 15010, "status": "open_no_auth"},\n'
        '  {"host": "127.0.0.1", "port": 15011, "status": "open_no_auth"}\n'
        "]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(verify_postrun, "_GOLDEN_DIR", golden_dir)

    verify_postrun._validate_golden_snapshots(
        [
            {
                "module": "registry",
                "label": "registry_multi_instance_urls",
                "expected_exit": "0",
                "exit_code": "0",
                "json_path": str(artifact),
                "log_path": "-",
            }
        ]
    )


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


def _mk_row(
    *,
    module: str,
    label: str,
    exit_code: str,
    json_path: str,
    log_path: str,
    expected_exit: str = "0",
) -> dict[str, str]:
    return {
        "module": module,
        "label": label,
        "expected_exit": expected_exit,
        "exit_code": exit_code,
        "json_path": json_path,
        "log_path": log_path,
    }


def test_validate_tee_when_output_set_passes_when_log_contains_json(tmp_path: Path) -> None:
    json_path = tmp_path / "redis_default.json"
    log_path = tmp_path / "redis_default.log"
    json_text = '{"host": "127.0.0.1", "port": 6379, "status": "valid_credentials"}'
    json_path.write_text(json_text + "\n", encoding="utf-8")
    log_path.write_text(f"banner\n{json_text}\n", encoding="utf-8")

    _validate_tee_when_output_set(
        [
            _mk_row(
                module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path)
            )
        ]
    )


def test_validate_tee_when_output_set_fails_when_log_lacks_json(tmp_path: Path) -> None:
    json_path = tmp_path / "redis_default.json"
    log_path = tmp_path / "redis_default.log"
    json_path.write_text('{"host": "127.0.0.1", "port": 6379}\n', encoding="utf-8")
    log_path.write_text("only banner -- no json payload echoed\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="tee regression for label 'redis_default'"):
        _validate_tee_when_output_set(
            [
                _mk_row(
                    module="redis",
                    label="redis_default",
                    exit_code="0",
                    json_path=str(json_path),
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_tee_when_output_set_skips_run_text_case(tmp_path: Path) -> None:
    # run_text_case writes json_path="-" -- no JSON file to compare against, no tee check.
    log_path = tmp_path / "smoke.log"
    log_path.write_text("only debug text output\n", encoding="utf-8")
    _validate_tee_when_output_set(
        [_mk_row(module="redis", label="redis_debug_smoke", exit_code="0", json_path="-", log_path=str(log_path))]
    )


def test_validate_dump_not_empty_fires_on_empty_key_values(tmp_path: Path) -> None:
    json_path = tmp_path / "redis_default.json"
    log_path = tmp_path / "redis_default.log"
    json_path.write_text('{"status": "valid_credentials", "key_values": []}\n', encoding="utf-8")
    log_path.write_text("anything\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="empty-dump marker"):
        _validate_dump_not_empty(
            [
                _mk_row(
                    module="redis",
                    label="redis_default",
                    exit_code="0",
                    json_path=str(json_path),
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_dump_not_empty_skips_auth_required(tmp_path: Path) -> None:
    # When auth was required (no creds passed), an empty dump is expected -- the
    # status-coherence rule covers the credential-flow regression separately.
    json_path = tmp_path / "clickhouse_native_open.json"
    log_path = tmp_path / "clickhouse_native_open.log"
    json_path.write_text(
        '{"status": "auth_required", "table_dumps": []}\n',
        encoding="utf-8",
    )
    log_path.write_text("auth probe\n", encoding="utf-8")
    _validate_dump_not_empty(
        [
            _mk_row(
                module="clickhouse",
                label="clickhouse_native_open",
                exit_code="0",
                json_path=str(json_path),
                log_path=str(log_path),
            )
        ]
    )


def test_validate_dump_not_empty_passes_when_dump_has_content(tmp_path: Path) -> None:
    json_path = tmp_path / "redis_default.json"
    log_path = tmp_path / "redis_default.log"
    json_path.write_text(
        '{"status": "valid_credentials", "key_values": ["app:env:prod", "user:1001:name=alice"]}\n',
        encoding="utf-8",
    )
    log_path.write_text("ok\n", encoding="utf-8")
    _validate_dump_not_empty(
        [
            _mk_row(
                module="redis",
                label="redis_default",
                exit_code="0",
                json_path=str(json_path),
                log_path=str(log_path),
            )
        ]
    )


def test_validate_status_coherence_fires_on_auth_required_with_credentials(tmp_path: Path) -> None:
    json_path = tmp_path / "postgres_default.json"
    log_path = tmp_path / "postgres_default.log"
    # Provided credentials AND auth_required -> 5.5.1 credential-flow regression signature.
    json_path.write_text(
        '{"provided_credentials": true, "status": "auth_required"}\n',
        encoding="utf-8",
    )
    log_path.write_text("ok\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="credential-flow regression"):
        _validate_status_coherence(
            [
                _mk_row(
                    module="postgres",
                    label="postgres_default",
                    exit_code="0",
                    json_path=str(json_path),
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_status_coherence_ignores_defcreds_and_probe_cases(tmp_path: Path) -> None:
    # Defcreds/probe cases do NOT set provided_credentials=true, so an auth_required outcome
    # is intentional and the rule must stay silent.
    json_path = tmp_path / "oracle_listener.json"
    log_path = tmp_path / "oracle_listener.log"
    json_path.write_text(
        '{"provided_credentials": false, "status": "auth_required"}\n',
        encoding="utf-8",
    )
    log_path.write_text("ok\n", encoding="utf-8")
    _validate_status_coherence(
        [
            _mk_row(
                module="oracle",
                label="oracle_listener",
                exit_code="0",
                json_path=str(json_path),
                log_path=str(log_path),
            )
        ]
    )


def test_validate_multi_record_consistency_fires_on_status_split(tmp_path: Path) -> None:
    json_path = tmp_path / "consul_multi_instance_urls.json"
    # 5 records, one with a different status -> partial-failure regression.
    records = [
        '{"host": "127.0.0.1", "port": 8500, "status": "open_no_auth"}',
        '{"host": "127.0.0.1", "port": 8501, "status": "open_no_auth"}',
        '{"host": "127.0.0.1", "port": 8502, "status": "fail"}',
        '{"host": "127.0.0.1", "port": 8503, "status": "open_no_auth"}',
        '{"host": "127.0.0.1", "port": 8504, "status": "open_no_auth"}',
    ]
    json_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    rows = [
        _mk_row(
            module="consul",
            label="consul_multi_instance_urls",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(tmp_path / "consul.log"),
        )
    ]
    (tmp_path / "consul.log").write_text("ok\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="inconsistent status across host records"):
        _validate_multi_record_consistency(rows)


def test_validate_multi_record_consistency_fires_on_short_count(tmp_path: Path) -> None:
    json_path = tmp_path / "consul_multi_instance_urls.json"
    records = [f'{{"host": "127.0.0.1", "port": {8500 + i}, "status": "open_no_auth"}}' for i in range(3)]
    json_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    (tmp_path / "consul.log").write_text("ok\n", encoding="utf-8")
    rows = [
        _mk_row(
            module="consul",
            label="consul_multi_instance_urls",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(tmp_path / "consul.log"),
        )
    ]
    with pytest.raises(SystemExit, match="expected 5 host records, got 3"):
        _validate_multi_record_consistency(rows)


def test_validate_multi_record_consistency_passes_uniform_status(tmp_path: Path) -> None:
    json_path = tmp_path / "redis_multi_ports.json"
    records = [f'{{"host": "127.0.0.1", "port": {6379 + i}, "status": "valid_credentials"}}' for i in range(5)]
    json_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    (tmp_path / "redis.log").write_text("ok\n", encoding="utf-8")
    rows = [
        _mk_row(
            module="redis",
            label="redis_multi_ports",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(tmp_path / "redis.log"),
        )
    ]
    _validate_multi_record_consistency(rows)


def test_validate_multi_record_consistency_skips_known_mixed_cases(tmp_path: Path) -> None:
    # docker_multi_ports is explicitly mixed-by-design (4 open + 1 auth_required).
    json_path = tmp_path / "docker_multi_ports.json"
    records = ['{"host": "127.0.0.1", "port": 2375, "status": "open_no_auth"}'] * 4 + [
        '{"host": "127.0.0.1", "port": 2376, "status": "auth_required"}'
    ]
    json_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    (tmp_path / "docker.log").write_text("ok\n", encoding="utf-8")
    rows = [
        _mk_row(
            module="docker",
            label="docker_multi_ports",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(tmp_path / "docker.log"),
        )
    ]
    _validate_multi_record_consistency(rows)


def test_validate_json_artifacts_handles_nel_byte_in_payload(tmp_path: Path) -> None:
    # Real flaky-test source: exporter response bodies can contain bytes that str.splitlines()
    # treats as line separators (\r, \x85/NEL, U+2028, ...). A single such byte inside a
    # JSON string value would shred an otherwise-valid JSONL record into invalid fragments.
    # The reader must split only on '\n'.
    from scripts.verify_postrun import _validate_json_artifacts

    log_path = tmp_path / "exporters_collect.log"
    json_path = tmp_path / "exporters_collect.json"
    log_path.write_text("ok\n", encoding="utf-8")
    # One JSONL record on one physical line, with NEL (U+0085) embedded inside the body.
    json_path.write_text(
        '{"exporter": "node_exporter", "body": "headtail"}\n',
        encoding="utf-8",
    )
    rows = [
        _mk_row(
            module="exporters",
            label="exporters_collect",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    # No exception expected: the record is valid JSONL even though it contains \x85.
    successful = _validate_json_artifacts(rows)
    assert successful["exporters"] == 1


def _audit_json(tmp_path: Path, label: str, body: str) -> tuple[Path, Path]:
    json_path = tmp_path / f"{label}.json"
    log_path = tmp_path / f"{label}.log"
    json_path.write_text(body + ("\n" if not body.endswith("\n") else ""), encoding="utf-8")
    log_path.write_text("ok\n", encoding="utf-8")
    return json_path, log_path


# --- P3-A schema -----------------------------------------------------------------


def test_validate_schema_mandatory_fields_fires_on_missing_host(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "redis_default",
        '{"port": 6379, "status": "valid_credentials", "timestamp": "2026-01-01T00:00:00Z", "stages": [], "module": "redis"}',
    )
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="missing/empty 'host'"):
        _validate_schema_mandatory_fields(rows)


def test_validate_schema_mandatory_fields_passes_complete_record(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "redis_default",
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","stages":[],"module":"redis"}',
    )
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    _validate_schema_mandatory_fields(rows)


def test_validate_schema_mandatory_fields_skips_exporter_records(tmp_path: Path) -> None:
    # Exporter-shape records (carry "exporter" field) are validated separately.
    json_path, log_path = _audit_json(
        tmp_path,
        "exporters_collect",
        '{"host":"h","port":9100,"exporter":"node_exporter","status":"trigger_success","timestamp":"t"}',
    )
    rows = [
        _mk_row(
            module="exporters",
            label="exporters_collect",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    _validate_schema_mandatory_fields(rows)


# --- P3-F elapsed sanity ---------------------------------------------------------


def test_validate_elapsed_sanity_fires_on_zero_timer_for_success_status(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "redis_default",
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","stages":[],"elapsed_ms":0,"module":"redis"}',
    )
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="no positive timer"):
        _validate_elapsed_sanity(rows)


def test_validate_elapsed_sanity_accepts_stage_sum(tmp_path: Path) -> None:
    # Failed audits omit top-level timers, but per-stage durations remain; total > 0 is OK.
    body = (
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t",'
        '"stages":[{"duration_ms":5},{"duration_ms":10}],"module":"redis","elapsed_ms":null}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    _validate_elapsed_sanity(rows)


def test_validate_elapsed_sanity_skips_fail_status(tmp_path: Path) -> None:
    body = '{"host":"h","port":3000,"status":"fail","timestamp":"t","stages":[],"elapsed_ms":null,"module":"grafana"}'
    json_path, log_path = _audit_json(tmp_path, "grafana_default", body)
    rows = [
        _mk_row(
            module="grafana", label="grafana_default", exit_code="0", json_path=str(json_path), log_path=str(log_path)
        )
    ]
    _validate_elapsed_sanity(rows)


# --- P3-E capability sanity ------------------------------------------------------


def test_validate_capability_sanity_fires_when_all_fields_empty(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","stages":[],'
        '"module":"redis","is_redis":false,"key_count":0,"keys":null,"key_values":null}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="capability regression"):
        _validate_capability_sanity(rows)


def test_validate_capability_sanity_passes_when_one_field_populated(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","stages":[],'
        '"module":"redis","is_redis":true}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    _validate_capability_sanity(rows)


# --- P3-B stage coherence --------------------------------------------------------


def test_validate_stage_coherence_fires_on_success_with_failed_stage(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","module":"redis",'
        '"stages":[{"stage_name":"detect","result":"ok","error":null},'
        '{"stage_name":"data","result":"fail","error":"timeout"}]}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="stage-coherence"):
        _validate_stage_coherence(rows)


def test_validate_stage_coherence_fires_on_fail_stage_with_null_error(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":6379,"status":"fail","timestamp":"t","module":"redis",'
        '"stages":[{"stage_name":"detect","result":"fail","error":null}]}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="silent failure"):
        _validate_stage_coherence(rows)


# --- P3-D cross-case invariants --------------------------------------------------


def test_validate_cross_case_invariants_fires_on_disagreement(tmp_path: Path) -> None:
    # redis_default and redis_extended_paged_dump must agree on key_count.
    body_a = '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","module":"redis","stages":[],"key_count":16}'
    body_b = '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","module":"redis","stages":[],"key_count":12}'
    ja, la = _audit_json(tmp_path, "redis_default", body_a)
    jb, lb = _audit_json(tmp_path, "redis_extended_paged_dump", body_b)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(ja), log_path=str(la)),
        _mk_row(module="redis", label="redis_extended_paged_dump", exit_code="0", json_path=str(jb), log_path=str(lb)),
    ]
    with pytest.raises(SystemExit, match="cross-case invariant violated"):
        _validate_cross_case_invariants(rows)


def test_validate_cross_case_invariants_passes_on_agreement(tmp_path: Path) -> None:
    body = '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","module":"redis","stages":[],"key_count":16}'
    ja, la = _audit_json(tmp_path, "redis_default", body)
    jb, lb = _audit_json(tmp_path, "redis_extended_paged_dump", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(ja), log_path=str(la)),
        _mk_row(module="redis", label="redis_extended_paged_dump", exit_code="0", json_path=str(jb), log_path=str(lb)),
    ]
    _validate_cross_case_invariants(rows)


def test_validate_expected_failure_outputs_passes_for_expected_error(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzz_redis_invalid_port_negative.log"
    log_path.write_text(
        "usage: redposture redis\nerror: argument --port: port must be in range 1..65535\n", encoding="utf-8"
    )

    _validate_expected_failure_outputs(
        [
            _mk_row(
                module="redis",
                label="fuzz_redis_invalid_port_negative",
                expected_exit="2",
                exit_code="2",
                json_path="-",
                log_path=str(log_path),
            )
        ]
    )


def test_validate_expected_failure_outputs_fails_on_wrong_error(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzz_redis_invalid_port_negative.log"
    log_path.write_text("some unrelated failure\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="failed for the wrong reason"):
        _validate_expected_failure_outputs(
            [
                _mk_row(
                    module="redis",
                    label="fuzz_redis_invalid_port_negative",
                    expected_exit="2",
                    exit_code="2",
                    json_path="-",
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_expected_failure_outputs_rejects_traceback(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzz_redis_invalid_port_negative.log"
    log_path.write_text(
        "error: argument --port: port must be in range 1..65535\nTraceback (most recent call last)\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="Python traceback"):
        _validate_expected_failure_outputs(
            [
                _mk_row(
                    module="redis",
                    label="fuzz_redis_invalid_port_negative",
                    expected_exit="2",
                    exit_code="2",
                    json_path="-",
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_expected_failure_outputs_rejects_nonempty_json_artifact(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzz_redis_invalid_port_negative.log"
    json_path = tmp_path / "fuzz_redis_invalid_port_negative.json"
    log_path.write_text("error: argument --port: port must be in range 1..65535\n", encoding="utf-8")
    json_path.write_text('{"status":"valid_credentials"}\n', encoding="utf-8")

    with pytest.raises(SystemExit, match="non-empty JSON artifact"):
        _validate_expected_failure_outputs(
            [
                _mk_row(
                    module="redis",
                    label="fuzz_redis_invalid_port_negative",
                    expected_exit="2",
                    exit_code="2",
                    json_path=str(json_path),
                    log_path=str(log_path),
                )
            ]
        )


def test_validate_expected_failure_outputs_rejects_progress_marker(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzz_redis_invalid_port_negative.log"
    log_path.write_text(
        "error: argument --port: port must be in range 1..65535\nRunning redposture against 1 target\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="unexpectedly reached target execution"):
        _validate_expected_failure_outputs(
            [
                _mk_row(
                    module="redis",
                    label="fuzz_redis_invalid_port_negative",
                    expected_exit="2",
                    exit_code="2",
                    json_path="-",
                    log_path=str(log_path),
                )
            ]
        )


def test_expected_failure_output_expectations_cover_matrix_failures() -> None:
    from scripts.matrix_flag_coverage import parse_matrix_cases

    cases = parse_matrix_cases(Path("scripts/run_lab_matrix_sequential.sh").read_text(encoding="utf-8"))
    failure_labels = {case.label for case in cases if case.expected_exit != "0"}

    assert failure_labels <= set(_EXPECTED_FAILURE_OUTPUT_SUBSTRINGS)
    assert _FUZZ_LABELS == frozenset(label for label in _EXTENDED_EXPECTED_LABELS if label.startswith("fuzz_"))
    assert _FUZZ_LABELS <= set(_EXPECTED_FAILURE_OUTPUT_SUBSTRINGS)
