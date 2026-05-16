from __future__ import annotations

from pathlib import Path

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
    for relative_path in ("stage_grpc.py", "stage_kafka.py", "stage_zookeeper.py"):
        text = (_CORE / relative_path).read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in text:
                offenders.append(f"{relative_path}:{token}")

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
