from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import verify_postrun
from scripts.verify_postrun import (
    _EXPECTED_FAILURE_OUTPUT_SUBSTRINGS,
    _EXPECTED_LABELS,
    _EXPECTED_MODULES,
    _EXTENDED_EXPECTED_LABELS,
    _FUZZ_LABELS,
    _OPENSEARCH_DEFAULT_CREDENTIALS,
    _PROGRESS_EXPECTED_TARGETS,
    _combined_run_output,
    _expected_labels_for_profile,
    _golden_text_for_row,
    _infer_target_count_from_jsonl,
    _parse_status_file,
    _progress_counts_from_log,
    _validate_action_contracts,
    _validate_capability_sanity,
    _validate_cross_case_invariants,
    _validate_discover_lab_contracts,
    _validate_dump_not_empty,
    _validate_elapsed_sanity,
    _validate_expected_exits,
    _validate_expected_failure_outputs,
    _validate_expected_labels,
    _validate_meaningful_outcomes,
    _validate_multi_record_consistency,
    _validate_openapi_artifacts,
    _validate_opensearch_defcreds_contract,
    _validate_output_sanity,
    _validate_progress_target_mappings,
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


def test_golden_text_replaces_exact_runtime_out_dir(tmp_path: Path) -> None:
    out_dir = tmp_path / "custom-artifacts-name"
    artifact = out_dir / "json" / "gitlab_clone.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        f'{{"host":"h","port":18080,"status":"detected","module":"gitlab","clone_dir":"{out_dir}/gitlab_clones"}}\n',
        encoding="utf-8",
    )
    normalized = _golden_text_for_row(
        {
            "module": "gitlab",
            "label": "gitlab_extended_token_project_clone",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": "-",
        }
    )
    assert normalized is not None
    assert str(out_dir) not in normalized
    assert "<OUT_DIR>/gitlab_clones" in normalized


def test_golden_text_sorts_only_documented_mongodb_unordered_lists(tmp_path: Path) -> None:
    out_dir = tmp_path / "mongo"
    artifact = out_dir / "json" / "mongodb.json"
    artifact.parent.mkdir(parents=True)
    row = {
        "module": "mongodb",
        "label": "mongodb_auth",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    forward = {
        "host": "h",
        "port": 27017,
        "status": "valid_credentials",
        "module": "mongodb",
        "database_names": ["redposture", "admin"],
        "collections": [{"collection": "tokens"}, {"collection": "accounts"}],
        "documents": [
            {"collection": "tokens", "document": {"_id": 2}},
            {"collection": "accounts", "document": {"_id": 1}},
        ],
        "indexes": [{"name": "username_1"}, {"name": "_id_"}],
        "credential_attempts": [{"username": "first"}, {"username": "second"}],
        "query_documents": [{"_id": 1}, {"_id": 2}],
        "stages": [{"stage_name": "detect"}, {"stage_name": "data"}],
    }
    reverse_unordered = dict(forward)
    reverse_unordered["database_names"] = list(reversed(forward["database_names"]))
    reverse_unordered["collections"] = list(reversed(forward["collections"]))
    reverse_unordered["documents"] = list(reversed(forward["documents"]))
    reverse_unordered["indexes"] = list(reversed(forward["indexes"]))
    artifact.write_text(json.dumps(forward) + "\n", encoding="utf-8")
    normalized_forward = _golden_text_for_row(row)
    artifact.write_text(json.dumps(reverse_unordered) + "\n", encoding="utf-8")
    normalized_reverse = _golden_text_for_row(row)
    assert normalized_forward == normalized_reverse

    reverse_stages = dict(reverse_unordered)
    reverse_stages["stages"] = list(reversed(forward["stages"]))
    artifact.write_text(json.dumps(reverse_stages) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized_forward

    reverse_attempts = dict(reverse_unordered)
    reverse_attempts["credential_attempts"] = list(reversed(forward["credential_attempts"]))
    artifact.write_text(json.dumps(reverse_attempts) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized_forward

    reverse_query_results = dict(reverse_unordered)
    reverse_query_results["query_documents"] = list(reversed(forward["query_documents"]))
    artifact.write_text(json.dumps(reverse_query_results) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized_forward


def test_golden_text_normalizes_grafana_temporary_datasource_identity(tmp_path: Path) -> None:
    artifact = tmp_path / "grafana.json"
    row = {
        "module": "grafana",
        "label": "grafana_ssrf_edge",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "grafana",
        "status": "valid_credentials",
        "check_results": [
            {
                "datasource_uid": "generated-first",
                "probe_elapsed_ms": 7,
                "target_url": "http://127.0.0.1:19115/probe",
                "probe_status": 404,
            }
        ],
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second["check_results"][0]["datasource_uid"] = "generated-second"
    second["check_results"][0]["probe_elapsed_ms"] = 31
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    second["check_results"][0]["probe_status"] = 500
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


def test_golden_text_normalizes_only_generated_kube_system_secret_values(tmp_path: Path) -> None:
    artifact = tmp_path / "kubeapi.json"
    row = {
        "module": "kubeapi",
        "label": "kubeapi_admin",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "kubeapi",
        "status": "auth_valid",
        "secrets": [
            {
                "namespace": "kube-system",
                "name": "abc123.node-password.k3s",
                "data": {"hash": "generated-first"},
            },
            {
                "namespace": "kube-system",
                "name": "k3s-serving",
                "type": "kubernetes.io/tls",
                "data": {"tls.crt": "generated-cert-first", "tls.key": "generated-key-first"},
            },
            {
                "namespace": "kube-system",
                "name": "seeded-control",
                "type": "Opaque",
                "data": {"token": "seeded-system-token"},
            },
            {
                "namespace": "finance",
                "name": "payroll-service",
                "data": {"service_token": "seeded-token"},
            },
        ],
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second["secrets"][0]["data"]["hash"] = "generated-second"
    second["secrets"][1]["data"]["tls.crt"] = "generated-cert-second"
    second["secrets"][1]["data"]["tls.key"] = "generated-key-second"
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    second["secrets"][2]["data"]["token"] = "unexpected-change"
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


def test_golden_text_normalizes_kube_pod_phase_but_keeps_namespace(tmp_path: Path) -> None:
    artifact = tmp_path / "kubeapi.json"
    row = {
        "module": "kubeapi",
        "label": "kubeapi_open",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "kubeapi",
        "status": "open_no_auth",
        "pods": [{"namespace": "kube-system", "name": "coredns-a", "phase": "Pending"}],
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second["pods"][0]["phase"] = "Running"
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    second["pods"][0]["namespace"] = "unexpected"
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


def test_golden_text_normalizes_elastic_node_identity_but_keeps_roles(tmp_path: Path) -> None:
    artifact = tmp_path / "elastic.json"
    row = {
        "module": "elastic",
        "label": "elastic_open",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "elastic",
        "status": "open_no_auth",
        "cluster_nodes": [{"id": "node-a", "host": "172.18.0.2", "ip": "172.18.0.2", "roles": ["data"]}],
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second["cluster_nodes"][0].update({"id": "node-b", "host": "172.31.0.4", "ip": "172.31.0.4"})
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    second["cluster_nodes"][0]["roles"] = ["master"]
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


def test_golden_text_normalizes_canonical_keeper_election_and_timing_but_keeps_dump(tmp_path: Path) -> None:
    artifact = tmp_path / "keeper.json"
    row = {
        "module": "keeper",
        "label": "keeper_cluster",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "keeper",
        "status": "open_no_auth",
        "connections": 1,
        "latency_ms": {"min": 0, "avg": 0, "max": 0},
        "server_state": "leader",
        "quorum_status": "healthy",
        "raft": {"followers": 2},
        "znode_values": ["/redposture/app/api_key:rp-keeper-key-2026"],
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second.update(
        {
            "connections": 3,
            "latency_ms": {"min": 1, "avg": 2.5, "max": 7},
            "server_state": "follower",
            "quorum_status": "unknown",
            "raft": {"followers": None},
        }
    )
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    stable_role_row = dict(row, label="keeper_tls")
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    stable_role_normalized = _golden_text_for_row(stable_role_row)
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(stable_role_row) != stable_role_normalized

    second["znode_values"] = ["/redposture/app/api_key:wrong"]
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


def test_golden_text_normalizes_only_bounded_zookeeper_traversal_subset(tmp_path: Path) -> None:
    artifact = tmp_path / "zookeeper.json"
    row = {
        "module": "zookeeper",
        "label": "zookeeper_extended_znode_limits",
        "expected_exit": "0",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": "-",
    }
    first = {
        "module": "zookeeper",
        "status": "open_no_auth",
        "znode_count": 22,
        "max_znodes": 10,
        "znodes_truncated": True,
        "znodes": ["/observability", "/redposture"],
        "znode_details": [{"path": "/observability", "bytes": 33}],
        "query_znode": "/redposture/app/api_key",
        "query_znode_dump": "rp-zk-key-2026",
    }
    artifact.write_text(json.dumps(first) + "\n", encoding="utf-8")
    normalized = _golden_text_for_row(row)
    second = json.loads(json.dumps(first))
    second["znodes"] = ["/brokers", "/config"]
    second["znode_details"] = [{"path": "/brokers", "bytes": 18}]
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) == normalized

    second["query_znode_dump"] = "unexpected"
    artifact.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert _golden_text_for_row(row) != normalized


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


def test_keeper_cluster_expected_targets_matches_matrix_command() -> None:
    assert _PROGRESS_EXPECTED_TARGETS["keeper_cluster"] == 2
    assert "keeper" in _EXPECTED_MODULES
    _validate_progress_target_mappings()


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
    with pytest.raises(SystemExit, match="did not dump seeded znodes"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_requires_keeper_dump_for_each_cluster_target(tmp_path: Path) -> None:
    artifact = tmp_path / "keeper.jsonl"
    log = tmp_path / "keeper.log"
    records = [
        {
            "host": "127.0.0.1",
            "port": 19181,
            "status": "open_no_auth",
            "service": "keeper",
            "implementation": "clickhouse-keeper",
            "znode_values": [
                "/redposture/app/api_key:rp-keeper-key-2026",
                "/clickhouse:clickhouse-keeper",
            ],
        },
        {
            "host": "127.0.0.1",
            "port": 29181,
            "status": "open_no_auth",
            "service": "keeper",
            "implementation": "clickhouse-keeper",
            "znode_values": [],
        },
    ]
    artifact.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    log.write_text("", encoding="utf-8")
    rows = [
        {
            "module": "keeper",
            "label": "keeper_cluster",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="empty_ports=\\[29181\\]"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_accepts_explicit_zookeeper_query_dump(tmp_path: Path) -> None:
    artifact = tmp_path / "zookeeper.jsonl"
    log = tmp_path / "zookeeper.log"
    artifact.write_text(
        '{"host":"127.0.0.1","port":2181,"status":"open_no_auth",'
        '"znode_values":null,"query_znode":"/redposture/app/api_key",'
        '"query_znode_dump":"rp-zk-key-2026"}\n',
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")

    _validate_rich_lab_outputs(
        [
            {
                "module": "zookeeper",
                "label": "zookeeper_extended_znode_limits",
                "expected_exit": "0",
                "exit_code": "0",
                "json_path": str(artifact),
                "log_path": str(log),
            }
        ]
    )


def test_validate_rich_lab_outputs_requires_all_pgbackrest_exporter_ports(tmp_path: Path) -> None:
    artifact = tmp_path / "exporters_scan.jsonl"
    log = tmp_path / "exporters_scan.log"
    artifact.write_text(
        "\n".join(
            f'{{"host":"127.0.0.1","port":{port},"exporter":"pgbackrest_exporter","detected":true}}'
            for port in (9854, 19854)
        )
        + "\n",
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")

    rows = [
        {
            "module": "exporters",
            "label": "exporters_scan",
            "expected_exit": "0",
            "exit_code": "0",
            "json_path": str(artifact),
            "log_path": str(log),
        }
    ]
    with pytest.raises(SystemExit, match="did not cover all pgBackRest exporter ports"):
        _validate_rich_lab_outputs(rows)


def test_validate_rich_lab_outputs_accepts_all_pgbackrest_exporter_ports(tmp_path: Path) -> None:
    artifact = tmp_path / "exporters_collect.jsonl"
    log = tmp_path / "exporters_collect.log"
    artifact.write_text(
        '{"host":"127.0.0.1","port":7777,"exporter":"nats_exporter","ok":true}\n'
        + "\n".join(
            f'{{"host":"127.0.0.1","port":{port},"exporter":"pgbackrest_exporter","ok":true}}'
            for port in (9854, 19854, 29854)
        )
        + "\n",
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")

    _validate_rich_lab_outputs(
        [
            {
                "module": "exporters",
                "label": "exporters_collect",
                "expected_exit": "0",
                "exit_code": "0",
                "json_path": str(artifact),
                "log_path": str(log),
            }
        ]
    )


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
    assert "keeper_cluster 0 keeper" in matrix and "--show-znodes 20 --dump 20" in matrix
    assert "registry_gitlab 0 registry" in matrix and "--token glrt-lab-token --gitlab --images" in matrix


def test_exporter_matrices_cover_all_pgbackrest_ports() -> None:
    expected_ports = {9854, 19854, 29854}
    for matrix_path in (Path("scripts/run_lab_matrix.sh"), Path("scripts/run_lab_matrix_sequential.sh")):
        matrix = matrix_path.read_text(encoding="utf-8")
        match = re.search(r'^EXPORTER_PORTS="([^"]+)"$', matrix, re.MULTILINE)
        assert match is not None, f"missing EXPORTER_PORTS in {matrix_path}"
        ports = {int(value) for value in match.group(1).split(",")}
        assert expected_ports <= ports

    assert _PROGRESS_EXPECTED_TARGETS["exporters_scan"] == 51


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
    with pytest.raises(SystemExit, match="without a meaningful outcome"):
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


def test_validate_meaningful_outcomes_rejects_zero_exit_fail(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "grafana_default",
        '{"host":"h","port":3000,"status":"fail","module":"grafana","error":"Connection reset by peer"}',
    )
    rows = [
        _mk_row(
            module="grafana",
            label="grafana_default",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    with pytest.raises(SystemExit, match="without a meaningful outcome"):
        _validate_meaningful_outcomes(rows)


def test_validate_meaningful_outcomes_rejects_summary_only(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "grafana_default",
        '{"type":"summary","status":"no_results","module":"grafana","requested_targets":1}',
    )
    rows = [
        _mk_row(
            module="grafana",
            label="grafana_default",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    with pytest.raises(SystemExit, match="without an audit record"):
        _validate_meaningful_outcomes(rows)


def test_validate_meaningful_outcomes_accepts_canonical_apache_classification(tmp_path: Path) -> None:
    json_path, log_path = _audit_json(
        tmp_path,
        "keeper_apache_control",
        '{"host":"h","port":12181,"status":"open_no_auth","module":"zookeeper",'
        '"service":"zookeeper","implementation":"apache-zookeeper","is_keeper":false}',
    )
    rows = [
        _mk_row(
            module="zookeeper",
            label="keeper_apache_control",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    _validate_meaningful_outcomes(rows)


def test_validate_multi_record_consistency_rejects_failed_grafana_replica(tmp_path: Path) -> None:
    json_path = tmp_path / "grafana_multi_instance_urls.json"
    records = [f'{{"host":"127.0.0.1","port":{3000 + index},"status":"valid_credentials"}}' for index in range(4)]
    records.append('{"host":"127.0.0.1","port":13004,"status":"fail"}')
    json_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    log_path = tmp_path / "grafana.log"
    log_path.write_text("ok\n", encoding="utf-8")
    rows = [
        _mk_row(
            module="grafana",
            label="grafana_multi_instance_urls",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    with pytest.raises(SystemExit, match="without a meaningful outcome"):
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


def test_validate_limit_conformance_enforces_zookeeper_show_znodes_hard_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import matrix_flag_coverage

    label = "zookeeper_hard_limit"
    monkeypatch.setattr(
        matrix_flag_coverage,
        "parse_matrix_cases",
        lambda _text: [
            SimpleNamespace(
                label=label,
                tokens=("redposture", "zookeeper", "-t", "127.0.0.1", "--show-znodes", "2"),
            )
        ],
    )
    record = {
        "module": "zookeeper",
        "host": "127.0.0.1",
        "port": 2181,
        "status": "open_no_auth",
        "znodes": ["/", "/one"],
    }
    json_path, log_path = _audit_json(tmp_path, label, json.dumps(record))
    rows = [
        _mk_row(
            module="zookeeper",
            label=label,
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    verify_postrun._validate_limit_conformance(rows)

    record["znodes"].append("/three")
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match=r"--show-znodes 2.*znodes contains 3"):
        verify_postrun._validate_limit_conformance(rows)


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


def test_keeper_module_schema_requires_identity_and_keeper_telemetry(tmp_path: Path) -> None:
    required = verify_postrun._MODULE_SCHEMA_REQUIRED["keeper"]
    assert {
        "implementation",
        "implementation_confidence",
        "vendor",
        "protocol",
        "transport",
        "is_keeper",
        "version",
        "server_state",
        "read_only",
        "connections",
        "latency_ms",
        "raft",
        "quorum_status",
    } <= set(required)

    payload: dict[str, object] = {field: None for field in required}
    payload.update(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "status": "open_no_auth",
            "module": "keeper",
            "service": "keeper",
        }
    )
    json_path, log_path = _audit_json(tmp_path, "keeper_cluster", json.dumps(payload))
    rows = [
        _mk_row(
            module="keeper",
            label="keeper_cluster",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    verify_postrun._validate_module_schema(rows)

    del payload["implementation"]
    json_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="implementation"):
        verify_postrun._validate_module_schema(rows)


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
        '"module":"redis","is_redis":true,"key_count":1}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    _validate_capability_sanity(rows)


def test_validate_capability_sanity_rejects_identity_marker_only(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":6379,"status":"valid_credentials","timestamp":"t","stages":[],'
        '"module":"redis","is_redis":true}'
    )
    json_path, log_path = _audit_json(tmp_path, "redis_default", body)
    rows = [
        _mk_row(module="redis", label="redis_default", exit_code="0", json_path=str(json_path), log_path=str(log_path))
    ]
    with pytest.raises(SystemExit, match="capability regression"):
        _validate_capability_sanity(rows)


def test_validate_capability_sanity_accepts_successful_empty_elastic_plugins(
    tmp_path: Path,
) -> None:
    body = (
        '{"host":"h","port":9200,"status":"valid_credentials","timestamp":"t","stages":[],'
        '"module":"elastic","show_plugins":true,"cat_plugins":[],"plugins_error":null}'
    )
    json_path, log_path = _audit_json(tmp_path, "elastic_plugins_edge", body)
    rows = [
        _mk_row(
            module="elastic",
            label="elastic_plugins_edge",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_capability_sanity(rows)


def test_validate_capability_sanity_rejects_failed_empty_elastic_plugins(
    tmp_path: Path,
) -> None:
    body = (
        '{"host":"h","port":9200,"status":"valid_credentials","timestamp":"t","stages":[],'
        '"module":"elastic","show_plugins":true,"cat_plugins":[],"plugins_error":"status=500"}'
    )
    json_path, log_path = _audit_json(tmp_path, "elastic_plugins_edge", body)
    rows = [
        _mk_row(
            module="elastic",
            label="elastic_plugins_edge",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    with pytest.raises(SystemExit, match="capability regression"):
        _validate_capability_sanity(rows)


def test_validate_capability_sanity_accepts_grpc_web_detection(
    tmp_path: Path,
) -> None:
    body = (
        '{"host":"h","port":50071,"status":"detected","timestamp":"t","stages":[],'
        '"module":"grpc","services":null,"reflection_enabled":null,"grpc_web_detected":true}'
    )
    json_path, log_path = _audit_json(tmp_path, "grpc_web_detect", body)
    rows = [
        _mk_row(
            module="grpc",
            label="grpc_web_detect",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_capability_sanity(rows)


def test_validate_action_contracts_requires_grafana_datasource_effect(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":3000,"status":"valid_credentials","module":"grafana",'
        '"is_grafana":true,"show_datasources":true,"datasources":[]}'
    )
    json_path, log_path = _audit_json(tmp_path, "grafana_default", body)
    rows = [
        _mk_row(
            module="grafana",
            label="grafana_default",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    with pytest.raises(SystemExit, match="datasources is empty"):
        _validate_action_contracts(rows)


def test_validate_action_contracts_accepts_typed_nexus_inventory(tmp_path: Path) -> None:
    body = (
        '{"host":"h","port":15004,"status":"open_no_auth","module":"registry",'
        '"is_registry":true,"is_nexus":true,"nexus":true,"assets":true,'
        '"nexus_info":{"version":"3.72.0"},"nexus_repositories":["raw-internal"],'
        '"nexus_assets":[{"path":"release-metadata.json"}]}'
    )
    json_path, log_path = _audit_json(tmp_path, "registry_nexus", body)
    rows = [
        _mk_row(
            module="registry",
            label="registry_nexus",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    _validate_action_contracts(rows)


def test_validate_action_contracts_require_clickhouse_multi_port_database_results(tmp_path: Path) -> None:
    records = [
        {
            "host": "h",
            "port": port,
            "status": "open_no_auth",
            "module": "clickhouse",
            "is_clickhouse": True,
            "show_databases": True,
            "database_names": ["default", "system"],
        }
        for port in (9000, 29001)
    ]
    json_path, log_path = _audit_json(
        tmp_path,
        "clickhouse_multi_ports",
        "\n".join(json.dumps(record) for record in records),
    )
    rows = [
        _mk_row(
            module="clickhouse",
            label="clickhouse_multi_ports",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    _validate_action_contracts(rows)

    records[1]["database_names"] = []
    json_path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="database_names is empty"):
        _validate_action_contracts(rows)


def test_validate_action_contracts_preserve_proxmox_explicit_empty_password_attempt(tmp_path: Path) -> None:
    record = {
        "host": "h",
        "port": 8006,
        "status": "auth_failed",
        "module": "proxmox",
        "is_proxmox": True,
        "use_https": True,
        "auth_attempts": [{"username": "root@pam", "source": "provided", "ok": "False"}],
    }
    json_path, log_path = _audit_json(
        tmp_path,
        "proxmox_extended_defcreds_empty_password",
        json.dumps(record),
    )
    rows = [
        _mk_row(
            module="proxmox",
            label="proxmox_extended_defcreds_empty_password",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]
    _validate_action_contracts(rows)

    record["auth_attempts"] = []
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="auth_attempts"):
        _validate_action_contracts(rows)


def test_validate_action_contracts_require_exact_grpc_metadata_and_request(tmp_path: Path) -> None:
    record = {
        "host": "h",
        "port": 50051,
        "status": "open_no_auth",
        "module": "grpc",
        "is_grpc": True,
        "invoke_result": {
            "status": "ok",
            "request": {"service": ""},
            "metadata": [{"key": "x-redposture-matrix", "value": "extended"}],
        },
    }
    json_path, log_path = _audit_json(
        tmp_path,
        "grpc_extended_metadata_invoke",
        json.dumps(record),
    )
    rows = [
        _mk_row(
            module="grpc",
            label="grpc_extended_metadata_invoke",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_action_contracts(rows)
    record["invoke_result"]["metadata"] = []
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="invoke_result.metadata"):
        _validate_action_contracts(rows)


def test_validate_action_contracts_require_exact_consul_selectors(tmp_path: Path) -> None:
    record = {
        "host": "h",
        "port": 8500,
        "status": "open_no_auth",
        "module": "consul",
        "is_consul": True,
        "keys_requested": True,
        "services_list_requested": True,
        "agents_list_requested": True,
        "checks_list_requested": True,
        "nodes_list_requested": True,
        "dump_requested": True,
        "kv_key_requested": "redposture/kafka/sasl_password",
        "service_dump_name": "redposture-api",
        "agent_dump_name": "redposture-lab-consul",
        "node_dump_name": "redposture-lab-consul",
        "kv_keys_list": None,
        "kv_dump_items": [{"key": "redposture/kafka/sasl_password"}],
        "services_list": [{"name": "redposture-api"}],
        "service_instances": {"redposture-api": [{"service_id": "svc-redposture-api"}]},
        "agents_list": [{"name": "redposture-lab-consul"}],
        "checks_list": [{"id": "service:svc-redposture-api"}],
        "nodes_list": [{"name": "redposture-lab-consul"}],
    }
    json_path, log_path = _audit_json(
        tmp_path,
        "consul_extended_inventory_filters",
        json.dumps(record),
    )
    rows = [
        _mk_row(
            module="consul",
            label="consul_extended_inventory_filters",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_action_contracts(rows)
    record["agent_dump_name"] = None
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="agent_dump_name"):
        _validate_action_contracts(rows)


@pytest.mark.parametrize("label", ["grafana_ssrf_edge", "grafana_extended_auth_ssrf_controls"])
def test_validate_action_contracts_require_exact_grafana_ssrf_url(tmp_path: Path, label: str) -> None:
    expected_url = "http://grafana-2:3000/api/health"
    record = {
        "host": "h",
        "port": 3000,
        "status": "valid_credentials",
        "module": "grafana",
        "is_grafana": True,
        "show_datasources": True,
        "datasources": [{"name": "lab"}],
        "check_urls": [expected_url],
        "check_results": [
            {
                "target_url": expected_url,
                "create_ok": True,
                "create_status": 200,
                "create_error": None,
                "probe_ok": True,
                "probe_status": 200,
                "probe_error": None,
                "probe_proxy_path": "/api/datasources/proxy/uid/generated/api/health",
                "probe_sample": '{"database":"ok","version":"13.0.2"}',
                "cleanup_ok": True,
                "cleanup_error": None,
            }
        ],
    }
    json_path, log_path = _audit_json(tmp_path, label, json.dumps(record))
    rows = [
        _mk_row(
            module="grafana",
            label=label,
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_action_contracts(rows)
    record["check_urls"] = ["http://grafana-2:3000/wrong"]
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="check_urls"):
        _validate_action_contracts(rows)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("probe_ok", False, "clean HTTP 200"),
        ("probe_status", 404, "clean HTTP 200"),
        ("cleanup_ok", False, "cleanup failed"),
    ],
)
def test_validate_action_contracts_rejects_failed_grafana_ssrf_semantics(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    target_url = "http://grafana-2:3000/api/health"
    result = {
        "target_url": target_url,
        "create_ok": True,
        "create_status": 200,
        "create_error": None,
        "probe_ok": True,
        "probe_status": 200,
        "probe_error": None,
        "probe_proxy_path": "/api/datasources/proxy/uid/generated/api/health",
        "probe_sample": '{"database":"ok"}',
        "cleanup_ok": True,
        "cleanup_error": None,
    }
    result[field] = value
    record = {
        "host": "h",
        "port": 3000,
        "status": "valid_credentials",
        "module": "grafana",
        "is_grafana": True,
        "show_datasources": True,
        "datasources": [{"name": "lab"}],
        "check_urls": [target_url],
        "check_results": [result],
    }
    json_path, log_path = _audit_json(tmp_path, "grafana_ssrf_edge", json.dumps(record))
    rows = [
        _mk_row(
            module="grafana",
            label="grafana_ssrf_edge",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    with pytest.raises(SystemExit, match=message):
        _validate_action_contracts(rows)


def test_validate_action_contracts_require_passing_consul_ssrf_and_cleanup(tmp_path: Path) -> None:
    record = {
        "host": "h",
        "port": 8500,
        "status": "open_no_auth",
        "module": "consul",
        "is_consul": True,
        "ssrf_enabled": True,
        "checks_list_requested": True,
        "checks_list": [{"check_id": "seeded"}],
        "ssrf_results": [
            {
                "target_url": "http://consul:8500/v1/status/leader",
                "registered": True,
                "register_error": None,
                "status": "passing",
                "output": "HTTP GET http://consul:8500/v1/status/leader: 200 OK",
                "deregistered": True,
                "deregister_error": None,
            }
        ],
    }
    json_path, log_path = _audit_json(tmp_path, "consul_extended_ssrf_probe", json.dumps(record))
    rows = [
        _mk_row(
            module="consul",
            label="consul_extended_ssrf_probe",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_action_contracts(rows)
    record["ssrf_results"][0]["status"] = "critical"
    record["ssrf_results"][0]["output"] = "connection refused"
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="did not reach HTTP 200/passing"):
        _validate_action_contracts(rows)


def test_validate_action_contracts_require_successful_qdrant_callback_hit(tmp_path: Path) -> None:
    snapshot_path = "/demo_vectors-123.snapshot"
    target_url = f"http://host.docker.internal:19115{snapshot_path}"
    record = {
        "host": "h",
        "port": 6333,
        "status": "open_no_auth",
        "module": "qdrant",
        "is_qdrant": True,
        "ssrf_requested": True,
        "ssrf_collection": "demo_vectors",
        "ssrf_listener_started": True,
        "ssrf_hit_count": 1,
        "ssrf_hits": [{"method": "GET", "path": snapshot_path}],
        "ssrf_results": [
            {
                "target_url": target_url,
                "collection": "demo_vectors",
                "status": 200,
                "ok": True,
                "error": None,
                "response_raw": '{"result":true,"status":"ok"}',
            }
        ],
    }
    json_path, log_path = _audit_json(tmp_path, "qdrant_extended_ssrf_probe", json.dumps(record))
    rows = [
        _mk_row(
            module="qdrant",
            label="qdrant_extended_ssrf_probe",
            exit_code="0",
            json_path=str(json_path),
            log_path=str(log_path),
        )
    ]

    _validate_action_contracts(rows)
    record["ssrf_results"][0].update({"status": 500, "ok": False, "error": "restore failed"})
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="snapshot recovery did not succeed"):
        _validate_action_contracts(rows)

    record["ssrf_results"][0].update(
        {"status": 200, "ok": True, "error": None, "response_raw": '{"result":true,"status":"ok"}'}
    )
    record["ssrf_hit_count"] = 0
    record["ssrf_hits"] = []
    json_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="ssrf_hits is empty"):
        _validate_action_contracts(rows)


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
    log_path.write_text("[!] failed to parse --port: invalid port range '-1'\n", encoding="utf-8")

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
        "[!] failed to parse --port: invalid port range '-1'\nTraceback (most recent call last)\n",
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
    log_path.write_text("[!] failed to parse --port: invalid port range '-1'\n", encoding="utf-8")
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
        "[!] failed to parse --port: invalid port range '-1'\nRunning redposture against 1 target\n",
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


def _discover_manifest_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "expected_secret_types": ["password", "api_token"],
        "findings": [
            {
                "secret_type": "password",
                "value": "matrix-db-pass",
                "occurrence_count_min": 2,
                "locations": [
                    {
                        "source_kind": "document",
                        "object": "redposture-discover-corpus-v2/doc-password",
                        "index": "redposture-discover-corpus-v2",
                        "id": "doc-password",
                        "path": "/database/password",
                    }
                ],
            },
            {
                "secret_type": "api_token",
                "value": "matrix-api-token",
                "locations": [
                    {
                        "source_kind": "document",
                        "object": "redposture-discover-corpus-v2/doc-token",
                        "index": "redposture-discover-corpus-v2",
                        "id": "doc-token",
                        "path": "/client/api_token",
                    }
                ],
            },
        ],
        "forbidden_values": ["ordinary-finance-reference"],
        "expected_surfaces": {
            "mappings": {"allowed_statuses": ["complete"], "objects_scanned_min": 1},
            "ingest_pipelines": {"allowed_statuses": ["complete", "denied"], "objects_scanned_min": 0},
        },
    }


def _discover_record(*, vendor: str, scheme: str, auth_required: bool, username: str | None = None) -> dict:
    findings = []
    raw_findings = _discover_manifest_payload()["findings"]
    assert isinstance(raw_findings, list)
    for index, item in enumerate(raw_findings):
        assert isinstance(item, dict)
        findings.append(
            {
                "fingerprint": f"sha256:{index:064x}",
                "secret_type": item["secret_type"],
                "value": item["value"],
                "confidence": "high",
                "score": 85,
                "detectors": ["sensitive_field"],
                "occurrence_count": int(item.get("occurrence_count_min", 1)),
                "locations": item["locations"],
            }
        )
    return {
        "module": "elastic",
        "service": "elastic",
        "host": "127.0.0.1",
        "port": 29201 if scheme == "https" else 29200,
        "status": "valid_credentials" if auth_required else "open_no_auth",
        "vendor": vendor,
        "server_version": "2.19.1" if vendor == "opensearch" else "8.13.4",
        "scheme": scheme,
        "auth_required": auth_required,
        "auth_valid": True if auth_required else None,
        "effective_username": username,
        "is_elastic": True,
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": findings,
        "discover_results": [{"index": "redposture-discover-corpus-v2", "total_hits": 2}],
        "discover_error": None,
        "discover_error_detail": None,
        "discover_coverage": {
            "status": "complete",
            "complete": True,
            "indices_scanned": 1,
            "indices_failed": 0,
            "documents_scanned": 2,
            "timed_out": False,
            "truncated": False,
            "shard_failures": [],
            "surfaces": {
                "index_inventory": {"status": "complete", "objects_scanned": 1},
                "mappings": {"status": "complete", "objects_scanned": 1},
                "ingest_pipelines": {"status": "complete", "objects_scanned": 1},
            },
        },
    }


def _write_discover_contract_case(
    tmp_path: Path,
    *,
    label: str,
    record: dict,
) -> tuple[list[dict[str, str]], Path]:
    artifact = tmp_path / f"{label}.json"
    log_path = tmp_path / f"{label}.log"
    manifest_path = tmp_path / "discover_corpus_expected.json"
    artifact.write_text(json.dumps(record) + "\n", encoding="utf-8")
    log_path.write_text("", encoding="utf-8")
    manifest_path.write_text(json.dumps(_discover_manifest_payload()), encoding="utf-8")
    return (
        [
            _mk_row(
                module="elastic",
                label=label,
                expected_exit="0",
                exit_code="0",
                json_path=str(artifact),
                log_path=str(log_path),
            )
        ],
        manifest_path,
    )


@pytest.mark.parametrize(
    ("label", "vendor", "scheme", "auth_required", "username"),
    [
        ("elastic_open", "elasticsearch", "http", False, None),
        ("elastic_auth", "elasticsearch", "http", True, "elastic"),
        ("opensearch_open", "opensearch", "http", False, None),
        ("opensearch_auth", "opensearch", "https", True, "admin"),
        ("opensearch_observer", "opensearch", "https", True, "observer"),
    ],
)
def test_validate_discover_lab_contracts_accepts_both_vendors(
    tmp_path: Path,
    label: str,
    vendor: str,
    scheme: str,
    auth_required: bool,
    username: str | None,
) -> None:
    record = _discover_record(
        vendor=vendor,
        scheme=scheme,
        auth_required=auth_required,
        username=username,
    )
    if label == "opensearch_observer":
        record["discover_coverage"]["status"] = "partial"
        record["discover_coverage"]["complete"] = False
        record["discover_coverage"]["indices_denied"] = 1
        record["discover_coverage"]["surfaces"]["ingest_pipelines"] = {
            "status": "denied",
            "objects_scanned": 0,
        }
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label=label,
        record=record,
    )

    _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def test_validate_discover_lab_contracts_rejects_corpus_false_positive(tmp_path: Path) -> None:
    record = _discover_record(vendor="opensearch", scheme="http", auth_required=False)
    record["discover_findings"].append(
        {
            "fingerprint": "sha256:" + "f" * 64,
            "secret_type": "secret",
            "value": "ordinary-finance-reference",
            "confidence": "medium",
            "score": 60,
            "locations": [
                {
                    "source_kind": "document",
                    "object": "redposture-discover-corpus-v2/negative-finance",
                    "index": "redposture-discover-corpus-v2",
                    "id": "negative-finance",
                    "path": "/payment/reference",
                }
            ],
        }
    )
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label="opensearch_open",
        record=record,
    )

    with pytest.raises(SystemExit, match="corpus mismatch"):
        _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def test_validate_discover_lab_contracts_rejects_missing_location(tmp_path: Path) -> None:
    record = _discover_record(vendor="elasticsearch", scheme="http", auth_required=False)
    record["discover_findings"][0]["locations"][0]["path"] = "/wrong/path"
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label="elastic_open",
        record=record,
    )

    with pytest.raises(SystemExit, match="missing location"):
        _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def test_validate_discover_lab_contracts_rejects_wrong_server_version(tmp_path: Path) -> None:
    record = _discover_record(vendor="opensearch", scheme="https", auth_required=True, username="admin")
    record["server_version"] = "2.18.0"
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label="opensearch_auth",
        record=record,
    )

    with pytest.raises(SystemExit, match="server_version='2.18.0'"):
        _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def test_validate_discover_lab_contracts_rejects_lost_duplicate_occurrence(tmp_path: Path) -> None:
    record = _discover_record(vendor="elasticsearch", scheme="http", auth_required=False)
    record["discover_findings"][0]["occurrence_count"] = 1
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label="elastic_open",
        record=record,
    )

    with pytest.raises(SystemExit, match="occurrence_count=1"):
        _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def test_validate_discover_lab_contracts_rejects_truncation_and_surface_regression(tmp_path: Path) -> None:
    record = _discover_record(vendor="opensearch", scheme="https", auth_required=True, username="observer")
    record["discover_coverage"]["truncated"] = True
    record["discover_coverage"]["surfaces"]["mappings"]["status"] = "error"
    rows, manifest_path = _write_discover_contract_case(
        tmp_path,
        label="opensearch_observer",
        record=record,
    )

    with pytest.raises(SystemExit, match="timed out or truncated"):
        _validate_discover_lab_contracts(rows, manifest_path=manifest_path)


def _opensearch_defcreds_record() -> dict[str, object]:
    attempts: list[dict[str, object]] = []
    for index, (username, password) in enumerate(_OPENSEARCH_DEFAULT_CREDENTIALS):
        is_winner = index == 8
        attempts.append(
            {
                "username": username,
                "password": password,
                "source": "default",
                "status": "weak_default_creds" if is_winner else "auth_required",
                "error": None if is_winner else "authentication failed",
                "auth_probe_status": "verified" if is_winner else "rejected",
                "auth_probe_http_status": 200 if is_winner else 401,
                "auth_probe_endpoint": "/_plugins/_security/authinfo",
                "auth_error_detail": None if is_winner else {"status": 401, "reason": "Unauthorized"},
                "network_attempted": True,
                "verification_capability": "identity_endpoint_supported",
            }
        )
    return {
        "host": "127.0.0.1",
        "port": 29201,
        "module": "elastic",
        "service": "elastic",
        "status": "weak_default_creds",
        "vendor": "opensearch",
        "scheme": "https",
        "auth_required": True,
        "auth_valid": True,
        "effective_username": "logstash",
        "error": None,
        "attempted_credentials": attempts,
    }


def _write_opensearch_defcreds_row(tmp_path: Path, record: dict[str, object]) -> list[dict[str, str]]:
    artifact = tmp_path / "opensearch_defcreds.json"
    log_path = tmp_path / "opensearch_defcreds.log"
    artifact.write_text(json.dumps(record) + "\n", encoding="utf-8")
    log_path.write_text("", encoding="utf-8")
    return [
        _mk_row(
            module="elastic",
            label="opensearch_defcreds",
            expected_exit="0",
            exit_code="0",
            json_path=str(artifact),
            log_path=str(log_path),
        )
    ]


def test_validate_opensearch_defcreds_contract_accepts_exhaustive_ordered_attempts(tmp_path: Path) -> None:
    _validate_opensearch_defcreds_contract(_write_opensearch_defcreds_row(tmp_path, _opensearch_defcreds_record()))


def test_validate_opensearch_defcreds_contract_rejects_reordered_attempts(tmp_path: Path) -> None:
    record = _opensearch_defcreds_record()
    attempts = record["attempted_credentials"]
    assert isinstance(attempts, list)
    attempts[0], attempts[1] = attempts[1], attempts[0]

    with pytest.raises(SystemExit, match="order mismatch"):
        _validate_opensearch_defcreds_contract(_write_opensearch_defcreds_row(tmp_path, record))
