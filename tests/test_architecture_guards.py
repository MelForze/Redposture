from __future__ import annotations

import ast
import importlib
import inspect
import re
from pathlib import Path

from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import _HOST_STAGE_RUNTIME_ARGUMENTS, build_basic_audit_plan

_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "redposture_core"


def _stage_and_scanner_sources() -> list[Path]:
    return sorted([*_CORE.glob("stage_*.py"), _CORE / "scanner.py"])


def _runtime_sources() -> list[Path]:
    return sorted([*_CORE.glob("stage_*.py"), _CORE / "scanner.py", *(_CORE / "exporters").glob("*.py")])


def test_stage_and_scanner_code_do_not_use_raw_threadpool_executor() -> None:
    offenders: list[str] = []
    for path in _runtime_sources():
        text = path.read_text(encoding="utf-8")
        if "ThreadPoolExecutor" in text or "as_completed" in text:
            offenders.append(str(path.relative_to(_ROOT)))

    assert offenders == []


def test_production_code_does_not_reference_threadpool_executor() -> None:
    offenders: list[str] = []
    for path in _CORE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            (isinstance(node, ast.Name) and node.id == "ThreadPoolExecutor")
            or (isinstance(node, ast.Attribute) and node.attr == "ThreadPoolExecutor")
            or (isinstance(node, ast.ImportFrom) and any(alias.name == "ThreadPoolExecutor" for alias in node.names))
            for node in ast.walk(tree)
        ):
            offenders.append(str(path.relative_to(_ROOT)))

    assert offenders == []


def test_fixed_action_modules_use_complete_strict_host_stage_specs() -> None:
    for module in ("clickhouse", "gitlab", "kubeapi", "grpc", "consul", "grafana", "elastic", "proxmox"):
        args = parse_args([module, "-t", "127.0.0.1"])
        stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
        spec = getattr(stage, f"build_{module}_spec")(args)
        options = spec.host_stage_options

        assert options is not None, module
        parameters = set(inspect.signature(spec.host_stage).parameters)
        assert set(options) <= parameters, module
        assert parameters - _HOST_STAGE_RUNTIME_ARGUMENTS == set(options), module


def test_basic_audit_plan_does_not_call_credential_tcp_prefilter() -> None:
    tree = ast.parse(inspect.getsource(build_basic_audit_plan))

    assert not any(
        isinstance(node, ast.Name) and node.id == "filter_open_tcp_hosts_for_credential_file" for node in ast.walk(tree)
    )


def test_legacy_target_fake_harness_is_absent() -> None:
    helper_name = "patch_runner_for_legacy_target_fake"
    offenders = [
        str(path.relative_to(_ROOT))
        for path in (_ROOT / "tests").rglob("*.py")
        if path != Path(__file__) and helper_name in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_stage_and_scanner_code_do_not_instantiate_progress_bar_directly() -> None:
    offenders: list[str] = []
    for path in _runtime_sources():
        text = path.read_text(encoding="utf-8")
        if "ProgressBar(" in text:
            offenders.append(str(path.relative_to(_ROOT)))

    assert offenders == []


def test_stage_color_renderers_use_structured_marker_renderer() -> None:
    offenders: list[str] = []
    for path in _CORE.glob("stage_*.py"):
        text = path.read_text(encoding="utf-8")
        if "render_module_marker_line(" in text:
            offenders.append(str(path.relative_to(_ROOT)))

    assert offenders == []


def test_scanner_does_not_own_exporter_http_pool_implementation() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")

    assert "class _HTTPConnectionPool" not in scanner_source
    assert "_ACTIVE_HTTP_POOL_LOCK" not in scanner_source
    assert "from .exporters.http_pool import" in scanner_source


def test_scanner_does_not_own_exporter_output_formatters() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")
    discover_source = (_CORE / "exporters" / "discover.py").read_text(encoding="utf-8")
    collect_source = (_CORE / "exporters" / "collect.py").read_text(encoding="utf-8")

    assert "def _format_scan_record" not in scanner_source
    assert "def _format_collect_record" not in scanner_source
    assert "from .output import" in discover_source
    assert "from .output import" in collect_source


def test_scanner_does_not_own_exporter_artifact_writers() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")
    collect_source = (_CORE / "exporters" / "collect.py").read_text(encoding="utf-8")

    assert "def _save_collect_body" not in scanner_source
    assert "def _safe_fs_part" not in scanner_source
    assert "from .artifacts import" in collect_source


def test_scanner_does_not_own_exporter_detection_helpers() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")
    discover_source = (_CORE / "exporters" / "discover.py").read_text(encoding="utf-8")

    assert "def _looks_like_prometheus_metrics" not in scanner_source
    assert "def _build_scan_error_record" not in scanner_source
    assert "PROMETHEUS_METRIC_LINE_RE" not in scanner_source
    assert "from .detection import" in discover_source


def test_scanner_does_not_own_exporter_http_client_implementation() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")

    assert "def _should_retry_http_exception" not in scanner_source
    assert "def _unwrap_network_error" not in scanner_source
    assert "with urllib.request.urlopen" not in scanner_source
    assert "from .exporters.http_client import" in scanner_source


def test_scanner_does_not_own_exporter_trigger_pipeline() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")

    assert "def _detect_trigger_exporter_task" not in scanner_source
    assert "def _trigger_detected_exporter_task" not in scanner_source
    assert "from .exporters.trigger import" in scanner_source


def test_scanner_does_not_own_exporter_workflow_policy_helpers() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")
    discover_source = (_CORE / "exporters" / "discover.py").read_text(encoding="utf-8")
    collect_source = (_CORE / "exporters" / "collect.py").read_text(encoding="utf-8")

    assert "def _build_collect_targets" not in scanner_source
    assert "def _dedupe_collect_targets" not in scanner_source
    assert "def _sort_collect_targets" not in scanner_source
    assert "def _scan_max_inflight" not in scanner_source
    assert "def _build_scan_work_items" not in scanner_source
    assert "from .workflows import" in discover_source
    assert "from .workflows import" in collect_source


def test_scanner_does_not_own_exporter_discovery_scoring_helpers() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")
    discover_source = (_CORE / "exporters" / "discover.py").read_text(encoding="utf-8")

    assert "def _score_metrics_candidate" not in scanner_source
    assert "def _needs_fingerprint_tiebreak" not in scanner_source
    assert "def _score_fingerprint_candidate" not in scanner_source
    assert "def _resolve_prometheus_port_fallback" not in scanner_source
    assert "from .discovery_logic import" in discover_source


def test_scanner_is_exporter_compatibility_facade_not_runtime_owner() -> None:
    scanner_source = (_CORE / "scanner.py").read_text(encoding="utf-8")

    assert "from .exporters.discover import" in scanner_source
    assert "from .exporters.collect import" in scanner_source
    assert "def scan_exporter_presence" in scanner_source
    assert "def collect_exporter_debug_data" in scanner_source
    assert "BoundedScheduler(" not in scanner_source
    assert "format_scan_record(" not in scanner_source
    assert "format_collect_record(" not in scanner_source


def test_collect_stage_does_not_own_validate_artifact_writers() -> None:
    collect_source = (_CORE / "stage_collect.py").read_text(encoding="utf-8")
    artifacts_source = (_CORE / "validate" / "artifacts.py").read_text(encoding="utf-8")

    assert "def _write_unique_lines" not in collect_source
    assert "def _markdown_cell" not in collect_source
    assert "def _write_vulnerable_findings_markdown" not in collect_source
    assert "from .validate.artifacts import write_vulnerable_targets_files" in collect_source
    assert "def write_vulnerable_targets_files" in artifacts_source


def test_stage_runtime_reexports_models_but_does_not_own_model_definitions() -> None:
    runtime_source = (_CORE / "stage_runtime.py").read_text(encoding="utf-8")
    model_source = (_CORE / "audit_models.py").read_text(encoding="utf-8")

    assert "class AuditRecord" not in runtime_source
    assert "class StageTrace" not in runtime_source
    assert "from . import audit_models" in runtime_source
    assert "class AuditRecord" in model_source
    assert "class StageTrace" in model_source
    assert "class TargetSpec" in model_source
    assert "class RenderEvent" in model_source
    assert "class AuditCommandRunner" in runtime_source
    assert "typed_records: list[AuditRecord]" in runtime_source
    assert "def _record_to_model" in runtime_source


def test_cli_dispatch_and_parser_are_registry_backed() -> None:
    cli_source = (_CORE / "cli.py").read_text(encoding="utf-8")
    cli_args_source = (_CORE / "cli_args.py").read_text(encoding="utf-8")
    registry_source = (_CORE / "module_registry.py").read_text(encoding="utf-8")

    assert "from .module_registry import" in cli_source
    assert "COMMAND_SPECS_BY_NAME" in cli_source
    assert "resolve_command_runner" in cli_source
    assert "from .stage_" not in cli_source
    assert "globals().get(spec.runner_attr)" not in cli_source
    assert "_RUNNER_COMPATIBILITY_EXPORTS" not in cli_source
    assert "configure_cli_subcommands(" in cli_args_source
    assert "configure_redis_parser(" not in cli_args_source
    assert "class CommandSpec" in registry_source
    assert "EXPORTERS_ACTION_SPECS" in registry_source
    assert "def resolve_command_runner" in registry_source


def test_audit_module_names_match_module_directories() -> None:
    dir_names = {
        entry.name for entry in (_CORE / "modules").iterdir() if entry.is_dir() and not entry.name.startswith("__")
    }
    assert set(AUDIT_MODULE_NAMES) == dir_names


def test_module_runtime_dispatch_uses_module_package_boundaries() -> None:
    registry_source = (_CORE / "module_registry.py").read_text(encoding="utf-8")
    for module in AUDIT_MODULE_NAMES:
        package_stage = _CORE / "modules" / module / "stage.py"
        assert package_stage.is_file(), module
        assert f"redposture_core.modules.{module}.stage" in registry_source


def test_module_stage_files_are_runtime_entrypoint_facades() -> None:
    forbidden_tokens = (
        "TwoPassAuditRunner",
        "start_command_progress",
        "filter_open_tcp_hosts_for_credential_file",
        "def audit_",
        "def _audit_",
        "ThreadPoolExecutor",
        "as_completed",
        "output_written",
    )
    for module in AUDIT_MODULE_NAMES:
        source = (_CORE / "modules" / module / "stage.py").read_text(encoding="utf-8")
        assert f"Runtime entrypoint for the {module} audit module" in source
        assert f"run_{module}_stage" in source
        assert "run_legacy_command" not in source
        # Stage files must drive the staged runtime — either directly
        # (AuditCommandRunner + run_plan) or via the shared run_basic_host_audit
        # helper that wraps exactly that for modules with no custom pre/post logic.
        uses_runner = "AuditCommandRunner" in source and ".run_plan(" in source
        uses_helper = "run_basic_host_audit" in source
        assert uses_runner or uses_helper, module
        offenders = [token for token in forbidden_tokens if token in source]
        assert offenders == [], module


def test_module_legacy_files_are_removed() -> None:
    assert not (_CORE / "_module_runtime_impls").exists()
    for module_dir in (_CORE / "modules").iterdir():
        if not module_dir.is_dir() or module_dir.name.startswith("__"):
            continue
        assert not (module_dir / "legacy.py").exists(), module_dir.name
        assert not (module_dir / "runtime.py").exists(), module_dir.name
    runtime_source = (_CORE / "stage_runtime.py").read_text(encoding="utf-8")
    assert "run_external_stage" not in runtime_source
    assert "run_legacy_command" not in runtime_source


def test_module_packages_do_not_import_command_runtime_primitives() -> None:
    forbidden_tokens = (
        "TwoPassAuditRunner",
        "start_command_progress",
        "LineOutputSink",
        "filter_open_tcp_hosts_for_credential_file",
        "def audit_",
    )
    offenders: list[str] = []
    for path in (_CORE / "modules").glob("*/*.py"):
        if path.parent.name.startswith("__"):
            continue
        source = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                offenders.append(f"{path.relative_to(_ROOT)}:{token}")

    assert offenders == []


def test_module_package_split_boundaries_exist() -> None:
    for module_dir in (_CORE / "modules").iterdir():
        if not module_dir.is_dir() or module_dir.name.startswith("__"):
            continue
        for filename in ("stage.py", "actions.py", "policy.py", "render.py", "types.py"):
            assert (module_dir / filename).is_file(), f"{module_dir.name}/{filename}"
        assert not (module_dir / "runtime.py").exists(), f"{module_dir.name}/runtime.py"


def test_module_actions_are_typed_hook_facades_not_command_runtimes() -> None:
    forbidden_tokens = (
        "TwoPassAuditRunner",
        "start_command_progress",
        "LineOutputSink",
        "filter_open_tcp_hosts_for_credential_file",
        "append_output",
        "show_progress",
        "def run_",
        "def audit_",
    )
    for module_dir in (_CORE / "modules").iterdir():
        if not module_dir.is_dir() or module_dir.name.startswith("__"):
            continue
        source = (module_dir / "actions.py").read_text(encoding="utf-8")
        # Modules expose only their real host action; the runner owns the
        # detect/auth/capabilities/data lifecycle. The per-module hook copy and
        # the `_invoke_module_host_stage` indirection must be gone.
        assert "host_stage = " in source, module_dir.name
        for copied in (
            "def detect(ctx: AuditHookContext)",
            "def auth(ctx: AuditHookContext",
            "def capabilities(ctx: AuditHookContext",
            "def data(ctx: AuditHookContext",
            "_invoke_module_host_stage",
        ):
            assert copied not in source, f"{module_dir.name}: {copied}"
        offenders = [token for token in forbidden_tokens if token in source]
        assert offenders == [], module_dir.name


def test_proxmox_uses_shared_proxy_transport_only() -> None:
    offenders: list[str] = []
    for path in (_CORE / "modules" / "proxmox").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in (
            "_parse_proxy_config",
            "_ProxyConfig",
            "_socks5_open_tunnel",
            "_request_via_socks_proxy",
            "_request_via_http_proxy",
            "http.client",
            "socket.create_connection",
        ):
            if token in source:
                offenders.append(f"{path.name}:{token}")

    assert offenders == []


def test_module_split_boundary_modules_are_importable() -> None:
    for module_dir in (_CORE / "modules").iterdir():
        if not module_dir.is_dir() or module_dir.name.startswith("__"):
            continue
        for submodule in ("policy", "render", "types"):
            imported = importlib.import_module(f"redposture_core.modules.{module_dir.name}.{submodule}")
            assert imported is not None


def test_root_audit_stage_files_are_compatibility_facades_only() -> None:
    forbidden_tokens = (
        "TwoPassAuditRunner",
        "start_command_progress",
        "filter_open_tcp_hosts_for_credential_file",
        "def audit_",
        "def _audit_",
        "ThreadPoolExecutor",
        "as_completed",
        "output_written",
    )
    for module in (
        "redis",
        "postgres",
        "kafka",
        "elastic",
        "grafana",
        "gitlab",
        "consul",
        "qdrant",
        "kubeapi",
        "registry",
        "proxmox",
        "etcd",
        "mongodb",
        "docker",
        "oracle",
        "grpc",
        "clickhouse",
        "zookeeper",
        "keeper",
    ):
        source = (_CORE / f"stage_{module}.py").read_text(encoding="utf-8")
        assert f"Compatibility facade for :mod:`redposture_core.modules.{module}`" in source
        assert f"from .modules.{module} import actions as _actions" in source
        assert f"from .modules.{module} import render as _render" in source
        assert f"from .modules.{module} import stage as _stage" in source
        assert "sys.modules[__name__] = _stage" not in source
        assert "._module_runtime_impls" not in source
        assert f"run_{module}_stage" in source
        offenders = [token for token in forbidden_tokens if token in source]
        assert offenders == [], module


def test_no_legacy_audit_target_command_boundaries_remain_in_core() -> None:
    offenders: list[str] = []
    for path in _CORE.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for token in ("run_compat_audit_targets", "run_external_stage", "run_legacy_command", "def audit_"):
            if token in source:
                offenders.append(f"{path.relative_to(_ROOT)}:{token}")
        if re.search(r"\baudit_[a-z0-9_]+_targets\b", source):
            offenders.append(f"{path.relative_to(_ROOT)}:audit_*_targets")
    assert offenders == []


def test_shared_http_api_client_exists_and_migrated_modules_use_it() -> None:
    client_source = (_CORE / "clients" / "http_api.py").read_text(encoding="utf-8")
    grafana_source = (_CORE / "modules" / "grafana" / "actions.py").read_text(encoding="utf-8")
    etcd_source = (_CORE / "modules" / "etcd" / "actions.py").read_text(encoding="utf-8")

    assert "class HttpApiClient" in client_source
    assert "class HttpRequest" in client_source
    assert "class HttpResponse" in client_source
    assert "from ...clients.http_api import" in grafana_source
    assert "from ...clients.http_api import" in etcd_source
    assert "urllib.request.urlopen" not in grafana_source
    assert "urllib.request.urlopen" not in etcd_source


def test_http_api_stage_modules_do_not_own_direct_urllib_transport() -> None:
    offenders: list[str] = []
    for module in (
        "grafana",
        "gitlab",
        "consul",
        "qdrant",
        "kubeapi",
        "elastic",
        "registry",
        "etcd",
        "proxmox",
    ):
        source = (_CORE / "modules" / module / "actions.py").read_text(encoding="utf-8")
        for token in ("urllib.request.urlopen", "urllib.request.build_opener", "http.client.HTTPConnection"):
            if token in source:
                offenders.append(f"{module}:{token}")

    assert offenders == []


def test_stage_validate_is_compatibility_facade_not_validation_engine() -> None:
    stage_source = (_CORE / "stage_validate.py").read_text(encoding="utf-8")

    assert "from .validate.engine import" in stage_source
    assert "def _detect_hits_in_text" not in stage_source
    assert "def _score_and_gate_hit" not in stage_source
    assert "def _render_validate_row" not in stage_source
    assert "_TEXT_KV_RE" not in stage_source


def test_validate_submodules_exist_for_parser_scoring_context_render_boundaries() -> None:
    for relative_path in (
        "validate/context.py",
        "validate/parsers.py",
        "validate/scoring.py",
        "validate/render.py",
        "validate/artifacts.py",
        "validate/engine.py",
    ):
        assert (_CORE / relative_path).is_file(), relative_path


def test_validate_engine_is_orchestrator_not_parser_scoring_renderer_owner() -> None:
    engine_source = (_CORE / "validate" / "engine.py").read_text(encoding="utf-8")

    forbidden_tokens = (
        "_TEXT_KV_RE =",
        "_URL_CANDIDATE_RE =",
        "_AUTH_BASIC_RE =",
        "_DEFAULT_VALIDATE_SUPPRESS_RULES =",
        "def _detect_hits_in_text",
        "def _scan_body_hits",
        "def _score_and_gate_hit",
        "def _render_validate_row",
        "def _render_validate_complete_row",
    )
    offenders = [token for token in forbidden_tokens if token in engine_source]

    assert offenders == []


def test_validate_submodules_own_their_runtime_boundaries() -> None:
    context_source = (_CORE / "validate" / "context.py").read_text(encoding="utf-8")
    parser_source = (_CORE / "validate" / "parsers.py").read_text(encoding="utf-8")
    scoring_source = (_CORE / "validate" / "scoring.py").read_text(encoding="utf-8")
    render_source = (_CORE / "validate" / "render.py").read_text(encoding="utf-8")

    assert "def _value_looks_secret_for_key" in context_source
    assert "_TEXT_KV_RE =" in parser_source
    assert "def _scan_body_hits" in parser_source
    assert "def _score_and_gate_hit" in scoring_source
    assert "def _render_validate_row" in render_source


def test_protocol_stage_modules_do_not_own_raw_socket_frame_clients() -> None:
    forbidden_tokens = (
        "import socket",
        "import struct",
        "socket.create_connection",
        "struct.pack",
        "struct.unpack",
        "H2Connection",
        ".sendall(",
        ".recv(",
    )
    offenders: list[str] = []
    for module in ("grpc", "kafka", "zookeeper"):
        text = (_CORE / "modules" / module / "actions.py").read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in text:
                offenders.append(f"{module}:{token}")

    assert offenders == []


def test_protocol_clients_own_raw_protocol_transport_helpers() -> None:
    grpc_client = (_CORE / "clients" / "grpc.py").read_text(encoding="utf-8")
    kafka_client = (_CORE / "clients" / "kafka.py").read_text(encoding="utf-8")
    zookeeper_client = (_CORE / "clients" / "zookeeper.py").read_text(encoding="utf-8")

    assert "def _grpc_call" in grpc_client
    assert "H2Connection" in grpc_client
    assert "def _send_kafka_request" in kafka_client
    assert "def _recv_kafka_frame" in kafka_client
    assert "class _ZkClient" in zookeeper_client
    assert "def _recv_frame" in zookeeper_client
    assert "def query_four_letter_word" in zookeeper_client
    assert "fingerprint_zookeeper_implementation" in zookeeper_client
