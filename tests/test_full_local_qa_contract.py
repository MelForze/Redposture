from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_postrun_verifier() -> object:
    path = ROOT / "scripts" / "verify_postrun.py"
    spec = importlib.util.spec_from_file_location("verify_postrun_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_full_docker_matrix_is_reproducible_and_local_only() -> None:
    script_path = ROOT / "scripts" / "run_full_local_qa.sh"
    script = script_path.read_text(encoding="utf-8")

    assert script.startswith("#!/usr/bin/env bash\nset -euo pipefail")
    assert "REDPOSTURE_MATRIX_PROFILE=extended" in script
    assert "run_lab_matrix_sequential.sh" in script
    assert "run_minio_kubeapi_lab.sh" in script
    assert "run_auth_service_matrix.sh" in script
    assert "run_real_cve_matrix.sh" in script
    assert "REDPOSTURE_CLI_PARAM_FUZZ=1" in script
    assert "--hypothesis-seed=20260928" in script
    assert "REDPOSTURE_HYPOTHESIS_PROFILE=redposture-local" in script
    for profile in (
        "test_local_output_audit.py",
        "test_concurrency_stress.py",
        "test_sigint_runtime.py",
        "test_soak_qa.py",
    ):
        assert profile in script
    assert "--junitxml=" in script

    workflows = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / ".github" / "workflows").glob("*.yml"))
    assert "run_full_local_qa.sh" not in workflows


def test_real_heavy_vendors_are_seeded_in_separate_matrix_blocks() -> None:
    script = (ROOT / "scripts/run_lab_matrix_sequential.sh").read_text()
    assert "qa_service_policy.py" in script
    assert "prepare_version.py" in script
    assert "run_service_block registry-harbor run_registry_harbor_cases" in script
    assert "run_service_block valkey run_valkey_cases" in script
    assert "scripts/bootstrap_gitlab_lab.py" in script
    assert "scripts/seed_real_vendors.py harbor" in script
    bootstrap = (ROOT / "scripts/bootstrap_gitlab_lab.py").read_text()
    assert '"gitlab-rails", "runner", "/qa/seed.rb"' in bootstrap
    assert "timeout=600" in bootstrap
    assert "glrt-lab-token" not in script
    registry_block = script.split("run_registry_cases() {", 1)[1].split("\n}", 1)[0]
    assert "registry_harbor" not in registry_block
    assert "registry_gitlab" not in registry_block


def test_real_gitlab_golden_ignores_activity_clock_but_preserves_role() -> None:
    verifier = _load_postrun_verifier()
    left = {
        "module": "gitlab",
        "token_user": {
            "username": "analyst",
            "is_admin": False,
            "last_activity_on": "2026-09-28",
            "local_time": "15:00",
        },
    }
    right = {
        "module": "gitlab",
        "token_user": {
            "username": "analyst",
            "is_admin": False,
            "last_activity_on": "2026-10-01",
            "local_time": "18:00",
        },
    }
    assert verifier._normalize_for_golden(left) == verifier._normalize_for_golden(right)
    right["token_user"]["is_admin"] = True
    assert verifier._normalize_for_golden(left) != verifier._normalize_for_golden(right)


def test_sequential_matrix_rejects_reused_artifact_directory(tmp_path: Path) -> None:
    (tmp_path / "stale-checkpoint").write_text("old run", encoding="utf-8")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "run_lab_matrix_sequential.sh"), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "matrix output directory is not empty" in result.stderr
    assert (tmp_path / "stale-checkpoint").read_text(encoding="utf-8") == "old run"


def test_extended_matrix_accounts_for_every_cli_option() -> None:
    from scripts.matrix_flag_coverage import build_coverage_report

    report = build_coverage_report(ROOT / "scripts" / "run_lab_matrix_sequential.sh")
    assert report["missing_actions"] == {}


def test_split_lab_compose_files_only_reference_paths_inside_current_checkout() -> None:
    compose_files = sorted((ROOT / "lab" / "services").glob("*/docker-compose.yml"))
    if not compose_files:
        pytest.skip("local lab is intentionally excluded from Git checkouts")
    for compose_file in compose_files:
        source = compose_file.read_text(encoding="utf-8")
        assert "stand/" not in source, compose_file
        assert "../../../stand" not in source, compose_file
        for line in source.splitlines():
            if line.strip().startswith("file:"):
                relative = line.split(":", 1)[1].strip()
                assert (compose_file.parent / relative).resolve().is_file(), (compose_file, relative)


def test_missing_target_fuzz_case_is_not_masked_by_unrelated_tls_file_errors() -> None:
    script = (ROOT / "scripts" / "run_lab_matrix_sequential.sh").read_text(encoding="utf-8")
    line = next(value for value in script.splitlines() if "fuzz_exporters_scan_missing_targets" in value)

    assert "exporters scan -p 9100 -ot excluded.invalid" in line
    assert "--tls-ca" not in line
    assert "--tls-cert" not in line
    assert "--tls-key" not in line

    callback_line = next(value for value in script.splitlines() if "fuzz_exporters_trigger_missing_callback" in value)
    assert "exporters trigger -t 127.0.0.1 -ot excluded.invalid --no-with-listen" in callback_line
    assert "--tls-ca" not in callback_line
    assert "--tls-cert" not in callback_line
    assert "--tls-key" not in callback_line


def test_clickhouse_invalid_port_case_is_not_masked_by_removed_flags() -> None:
    script = (ROOT / "scripts" / "run_lab_matrix_sequential.sh").read_text(encoding="utf-8")
    line = next(value for value in script.splitlines() if "fuzz_clickhouse_invalid_port" in value)

    assert "clickhouse -t 127.0.0.1 --port -1 --show-databases" in line
    assert "--show-secrets" not in line


def test_postrun_expected_https_labels_follow_successful_origin_fallback_cases() -> None:
    verifier = _load_postrun_verifier()

    for module in ("registry", "grafana", "etcd", "qdrant"):
        assert f"{module}_url_https_transport_fallback" in verifier._EXPECTED_LABELS
        assert f"{module}_url_https_transport_fail" not in verifier._EXPECTED_LABELS


def test_postrun_allows_only_the_documented_empty_trigger_event_stream(tmp_path: Path) -> None:
    verifier = _load_postrun_verifier()
    log = tmp_path / "trigger.log"
    artifact = tmp_path / "trigger.jsonl"
    log.write_text("[*] trigger complete: attempts=0\n", encoding="utf-8")
    artifact.write_text("", encoding="utf-8")
    row = {
        "module": "exporters",
        "label": "exporters_trigger_url_https_transport_mismatch",
        "exit_code": "0",
        "json_path": str(artifact),
        "log_path": str(log),
    }

    counts = verifier._validate_json_artifacts([row])

    assert counts["exporters"] == 1


@pytest.mark.parametrize("label", ["airflow_default", "minio_default", "rabbitmq_default"])
def test_postrun_knows_default_cases_that_explicitly_run_with_debug(label: str) -> None:
    verifier = _load_postrun_verifier()
    script = (ROOT / "scripts" / "run_lab_matrix_sequential.sh").read_text(encoding="utf-8")
    line = next(value for value in script.splitlines() if f" {label} " in value)

    assert "--debug" in line
    assert label in verifier._DEBUG_LABELS


def test_postrun_registry_capabilities_cover_typed_repository_actions() -> None:
    verifier = _load_postrun_verifier()

    fields = verifier._CAPABILITY_FIELDS_BY_MODULE["registry"]
    assert {"selected_repository_tags", "metadata_result", "inspections", "download_result"} <= set(fields)


def test_kubeapi_selector_contract_does_not_require_unrequested_exec() -> None:
    verifier = _load_postrun_verifier()
    script = (ROOT / "scripts" / "run_lab_matrix_sequential.sh").read_text(encoding="utf-8")
    line = next(value for value in script.splitlines() if "kubeapi_extended_selectors_basic_auth" in value)

    assert "--exec" not in line
    assert "exec_pod" not in verifier._ACTION_EXPECTED_VALUES["kubeapi_extended_selectors_basic_auth"]


def test_runtime_failures_keep_json_diagnostics_but_cli_validation_failures_do_not(tmp_path: Path) -> None:
    verifier = _load_postrun_verifier()
    log = tmp_path / "run.log"
    artifact = tmp_path / "run.json"
    log.write_text("[!] scan inconclusive: no exporter confirmed\n", encoding="utf-8")
    artifact.write_text('{"detected":false,"error":"TLS mismatch"}\n', encoding="utf-8")

    verifier._validate_expected_failure_outputs(
        [
            {
                "label": "exporters_scan_url_https_transport_fail",
                "expected_exit": "1",
                "log_path": str(log),
                "json_path": str(artifact),
            }
        ]
    )

    log.write_text("[!] scan requires -t/--targets\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="produced a non-empty JSON artifact"):
        verifier._validate_expected_failure_outputs(
            [
                {
                    "label": "fuzz_exporters_scan_missing_targets",
                    "expected_exit": "2",
                    "log_path": str(log),
                    "json_path": str(artifact),
                }
            ]
        )


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("minio_default", "partial_operational_failure"),
        ("minio_tls", "operational_failures_before_detection"),
        ("clickhouse_extended_query_columns", None),
    ],
)
def test_runtime_partial_and_inconclusive_cases_have_current_json_expectations(
    tmp_path: Path, label: str, reason: str | None
) -> None:
    verifier = _load_postrun_verifier()
    log = tmp_path / f"{label}.log"
    artifact = tmp_path / f"{label}.json"
    if reason is None:
        text = '{"requested_operation_failure": true}\n'
    else:
        text = f'{{"type":"summary","reason":"{reason}"}}\n'
    log.write_text(text, encoding="utf-8")
    artifact.write_text(text, encoding="utf-8")

    verifier._validate_expected_failure_outputs(
        [
            {
                "label": label,
                "expected_exit": "1",
                "log_path": str(log),
                "json_path": str(artifact),
            }
        ]
    )


def test_golden_normalization_preserves_fingerprints_and_ignores_lab_entropy() -> None:
    verifier = _load_postrun_verifier()
    rabbit_a = {"module": "rabbitmq", "cluster_id": "cluster-one", "is_rabbitmq": True}
    rabbit_b = {"module": "rabbitmq", "cluster_id": "cluster-two", "is_rabbitmq": True}
    assert verifier._normalize_for_golden(rabbit_a) == verifier._normalize_for_golden(rabbit_b)
    rabbit_b["is_rabbitmq"] = False
    assert verifier._normalize_for_golden(rabbit_a) != verifier._normalize_for_golden(rabbit_b)

    for module, field in (
        ("mongodb", "operation_results"),
        ("clickhouse", "rows"),
        ("elastic", "discover_findings"),
    ):
        left = {"module": module, field: [{"value": "alpha"}, {"value": "beta"}]}
        right = {"module": module, field: list(reversed(left[field]))}
        assert verifier._normalize_for_golden(left) == verifier._normalize_for_golden(right)


def test_golden_comparison_re_normalizes_older_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_postrun_verifier()
    old = [{"module": "rabbitmq", "cluster_id": "old-cluster", "is_rabbitmq": True}]
    (tmp_path / "rabbitmq_case.json").write_text(json.dumps(old), encoding="utf-8")
    current = [{"module": "rabbitmq", "cluster_id": "new-cluster", "is_rabbitmq": True}]
    normalized = verifier._normalize_for_golden(current, module="rabbitmq", label="rabbitmq_case")
    monkeypatch.setattr(verifier, "_GOLDEN_DIR", tmp_path)
    monkeypatch.setattr(verifier, "_golden_text_for_row", lambda _row: json.dumps(normalized, indent=2, sort_keys=True))

    verifier._validate_golden_snapshots([{"module": "rabbitmq", "label": "rabbitmq_case", "exit_code": "0"}])


def test_rabbitmq_golden_ignores_queue_depth_but_preserves_queue_metadata() -> None:
    verifier = _load_postrun_verifier()
    left = {
        "module": "rabbitmq",
        "enumeration": {
            "queues": {
                "items": [
                    {
                        "name": "work",
                        "messages": 14,
                        "messages_ready": 13,
                        "messages_unacknowledged": 1,
                        "consumers": 1,
                        "durable": True,
                    }
                ]
            }
        },
    }
    right = {
        "module": "rabbitmq",
        "enumeration": {
            "queues": {
                "items": [
                    {
                        "name": "work",
                        "messages": 13,
                        "messages_ready": 0,
                        "messages_unacknowledged": 13,
                        "consumers": 0,
                        "durable": True,
                    }
                ]
            }
        },
    }
    assert verifier._normalize_for_golden(left) == verifier._normalize_for_golden(right)
    right["enumeration"]["queues"]["items"][0]["durable"] = False
    assert verifier._normalize_for_golden(left) != verifier._normalize_for_golden(right)
