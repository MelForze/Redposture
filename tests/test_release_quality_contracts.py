"""Cross-module release contracts that protect the high-risk scan paths."""

from __future__ import annotations

import importlib
import json
import threading
import time
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.modules.minio.discover import Budget
from redposture_core.scheduler import SharedNestedScheduler
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec

_DEFCREDS_MODULES = (
    "redis",
    "postgres",
    "clickhouse",
    "etcd",
    "proxmox",
    "grafana",
    "minio",
    "rabbitmq",
    "airflow",
    "kafka",
    "zookeeper",
    "keeper",
    "elastic",
    "grpc",
    "mongodb",
    "oracle",
)


@pytest.mark.parametrize("module", _DEFCREDS_MODULES)
def test_every_defcreds_module_keeps_exhaustive_success_and_error_sweeps(module: str) -> None:
    """A transient candidate or an early success must not truncate --defcreds."""

    args = parse_args([module, "-t", "127.0.0.1", "--defcreds"])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    spec = getattr(stage, f"build_{module}_spec")(args)

    assert args.defcreds is True
    assert spec.continue_after_credential_error is True
    assert spec.continue_after_credential_success is True


@pytest.mark.parametrize(
    "module",
    (
        "airflow",
        "clickhouse",
        "etcd",
        "proxmox",
        "grafana",
        "minio",
        "rabbitmq",
        "kafka",
        "zookeeper",
        "keeper",
        "elastic",
        "grpc",
        "redis",
    ),
)
def test_defcreds_plans_prioritize_explicit_pair_and_deduplicate_defaults(module: str) -> None:
    args = parse_args([module, "-t", "127.0.0.1", "-u", "admin", "-p", "admin", "--defcreds"])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    prepare = getattr(stage, f"_prepare_{module}_credential_runs", None)
    if callable(prepare):
        prepare(args)
    plan = getattr(stage, f"build_{module}_plan")(args)
    identities = [(run.username, run.password, run.token) for run in plan.credential_runs]

    assert len(plan.credential_runs) > 1
    assert plan.credential_runs[0].source in {"provided", "token"}
    assert identities.count(("admin", "admin", None)) == 1
    assert len(identities) == len(set(identities))


def _mixed_target_spec(module: str) -> ModuleAuditSpec:
    failures = {
        "foreign-http": (f"not_{module}", f"service is not {module}"),
        "ssh": (f"not_{module}", "SSH-2.0-OpenSSH_9.2p1 Debian"),
        "tls-eof": ("fail", "TLS/SSL connection has been closed (EOF)"),
        "mtls": ("fail", "TLSV13_ALERT_CERTIFICATE_REQUIRED: certificate required"),
    }

    def detect(ctx: object) -> AuditRecord:
        if ctx.host == "real-service":
            return AuditRecord.from_mapping(
                {
                    "host": ctx.host,
                    "port": ctx.port,
                    "status": "auth_required",
                    "auth_required": True,
                    "confirmed": True,
                },
                module=module,
                service=module,
            )
        status, error = failures[ctx.host]
        return AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "status": status, "confirmed": False, "error": error},
            module=module,
            service=module,
        )

    return ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=1234,
        detect=detect,
        is_detected=lambda record: record.extra.get("confirmed") is True,
        render=lambda record: [
            f"{module.upper()} {record.host} {record.port} {record.status} {record.extra.get('error') or ''}".rstrip()
        ],
    )


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_audit_module_obeys_mixed_target_output_contract(module: str) -> None:
    targets = ("real-service", "foreign-http", "ssh", "tls-eof", "mtls")
    plan = AuditCommandPlan(targets_by_port={1234: targets}, workers=5, output_format="txt")
    callbacks: list[dict[str, object]] = []
    plain_lines: list[str] = []
    plain = AuditCommandRunner(
        args=SimpleNamespace(debug=False, record_callback=callbacks.append),
        spec=_mixed_target_spec(module),
        emit_line=plain_lines.append,
    ).run_plan(plan)

    assert plain.detected_count == 1
    assert plain.suppressed_records == 4
    assert plain_lines == [f"{module.upper()} real-service 1234 auth_required"]
    assert len(callbacks) == len(targets)
    assert {str(item["host"]) for item in callbacks} == set(targets)

    debug_lines: list[str] = []
    AuditCommandRunner(
        args=SimpleNamespace(debug=True),
        spec=_mixed_target_spec(module),
        emit_line=debug_lines.append,
    ).run_plan(plan)
    assert len(debug_lines) == len(targets)
    assert any("SSH-2.0-OpenSSH" in line for line in debug_lines)
    assert any("CERTIFICATE_REQUIRED" in line for line in debug_lines)

    json_lines: list[str] = []
    json_result = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=_mixed_target_spec(module),
        emit_line=json_lines.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: targets}, workers=5, output_format="json"))
    payloads = [json.loads(line) for line in json_lines]
    records = [item for item in payloads if item.get("type") != "summary"]
    summaries = [item for item in payloads if item.get("type") == "summary"]
    assert json_result.suppressed_records == 0
    assert len(records) == len(targets)
    assert summaries == [
        {
            "type": "summary",
            "module": module,
            "service": module,
            "status": "partial",
            "requested_targets": len(targets),
            "processed_targets": len(targets),
            "record_count": len(targets),
            "detected_count": 1,
            "operational_failure_count": 2,
            "conclusive_negative_count": 3,
            "reason": "partial_operational_failure",
        }
    ]


def test_default_discovery_budget_has_exact_fifty_mib_boundary_without_allocating_payload() -> None:
    limit = 50 * 1024 * 1024
    budget = Budget()

    assert budget.max_total_bytes == limit
    assert budget.claim(limit - 1) == limit - 1
    budget.release(0)
    assert budget.claim(2) == 1
    budget.release(0)
    assert budget.byte_limit_reached() is True
    assert budget.claim(1) == 0


def test_shared_nested_scheduler_worker_exception_cancels_queue_and_joins_threads() -> None:
    baseline = {thread.ident for thread in threading.enumerate() if thread.name.startswith("redposture-nested-")}
    scheduler = SharedNestedScheduler(max_workers=3)
    release = threading.Event()
    started: list[int] = []
    lock = threading.Lock()

    def worker(value: int) -> int:
        with lock:
            started.append(value)
        if value == 0:
            raise RuntimeError("nested worker failed")
        release.wait(timeout=2)
        return value

    try:
        with pytest.raises(RuntimeError, match="nested worker failed"):
            list(scheduler.iter_completed(range(100), worker, key="target", per_key_limit=3))
    finally:
        release.set()
        scheduler.close()

    time.sleep(0.05)
    leaked = [
        thread.name
        for thread in threading.enumerate()
        if thread.name.startswith("redposture-nested-") and thread.ident not in baseline and thread.is_alive()
    ]
    assert not leaked
    assert len(started) < 100
