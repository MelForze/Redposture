"""Argparse handlers for DB subsystem."""

from __future__ import annotations

import json
import sys
from argparse import Namespace
from collections.abc import Iterator
from contextlib import contextmanager

from ..console import Console
from ..stage_clickhouse import _render_colored_clickhouse_line
from ..stage_consul import _render_colored_consul_line
from ..stage_etcd import _render_colored_etcd_line
from ..stage_gitlab import _render_colored_gitlab_line
from ..stage_grafana import _render_colored_grafana_line
from ..stage_kafka import _render_colored_kafka_line
from ..stage_kubeapi import _render_colored_kubeapi_line
from ..stage_postgres import _render_colored_postgres_line
from ..stage_proxmox import _render_colored_proxmox_line
from ..stage_qdrant import _render_colored_qdrant_line
from ..stage_redis import _render_colored_redis_line
from ..stage_registry import _render_colored_registry_line
from ..stage_zookeeper import _render_colored_zookeeper_line
from .config import resolve_database_settings
from .dto.query import FindingFilter
from .services import (
    DatabaseService,
    ExportService,
    IngestService,
    QueryService,
    WorkspaceService,
    initialize_runtime_database,
)

DB_SHOW_MODULES = (
    "exporters",
    "registry",
    "grafana",
    "proxmox",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "kafka",
    "zookeeper",
)

_MODULE_TAG_ALIASES = {
    "proxmox": "PVE",
}

_MODULE_STAGE_RENDERERS = {
    "registry": _render_colored_registry_line,
    "grafana": _render_colored_grafana_line,
    "proxmox": _render_colored_proxmox_line,
    "gitlab": _render_colored_gitlab_line,
    "consul": _render_colored_consul_line,
    "kubeapi": _render_colored_kubeapi_line,
    "postgres": _render_colored_postgres_line,
    "clickhouse": _render_colored_clickhouse_line,
    "redis": _render_colored_redis_line,
    "etcd": _render_colored_etcd_line,
    "qdrant": _render_colored_qdrant_line,
    "kafka": _render_colored_kafka_line,
    "zookeeper": _render_colored_zookeeper_line,
}


def _services(db_url: str) -> tuple[DatabaseService, WorkspaceService, IngestService, QueryService, ExportService]:
    db = DatabaseService(db_url)
    return (
        db,
        WorkspaceService(db.session_factory),
        IngestService(db.session_factory),
        QueryService(db.session_factory),
        ExportService(db.session_factory),
    )


@contextmanager
def _service_scope(
    db_url: str,
) -> Iterator[tuple[DatabaseService, WorkspaceService, IngestService, QueryService, ExportService]]:
    services = _services(db_url)
    try:
        yield services
    finally:
        services[0].close()


def _workspace_id_or_die(workspace_service: WorkspaceService) -> tuple[int, str]:
    return workspace_service.resolve_workspace_id()


def _cell_text(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _format_rows(rows: list[dict[str, object]], columns: list[str], *, empty_label: str = "No rows") -> str:
    if not rows:
        return empty_label
    widths = {column: len(column) for column in columns}
    for row in rows:
        for column in columns:
            widths[column] = max(widths[column], len(_cell_text(row.get(column, ""))))
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    separator = "  ".join("-" * widths[column] for column in columns)
    lines = [header, separator]
    for row in rows:
        lines.append("  ".join(_cell_text(row.get(column, "")).ljust(widths[column]) for column in columns))
    return "\n".join(lines)


def _emit_rows(
    rows: list[dict[str, object]],
    columns: list[str],
    *,
    as_json: bool,
    empty_label: str = "No rows",
) -> None:
    if as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
        return
    print(_format_rows(rows, columns, empty_label=empty_label))


def _emit_dashboard_section(title: str, rows: list[dict[str, object]], columns: list[str], *, empty_label: str) -> None:
    print(title)
    print(_format_rows(rows, columns, empty_label=empty_label))
    print()


def _clip_text(value: str | None, width: int) -> str:
    text = str(value or "")
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _severity_color(value: str | None) -> str:
    severity = str(value or "").strip().lower()
    if severity in {"critical", "high"}:
        return "red"
    if severity == "medium":
        return "orange"
    if severity in {"low", "info"}:
        return "cyan"
    return "white"


def _status_color(value: str | None) -> str:
    status = str(value or "").strip().lower()
    if status in {"success", "completed", "open"}:
        return "green"
    if status in {"failed", "error", "closed"}:
        return "red"
    if status in {"running", "pending"}:
        return "cyan"
    return "white"


def _marker_for_status(value: str | None) -> tuple[str, str]:
    status = str(value or "").strip().lower()
    if status in {"success", "completed"}:
        return "[+]", "green"
    if status in {"failed", "error"}:
        return "[!]", "red"
    if status in {"open"}:
        return "[!]", "orange"
    if status in {"closed"}:
        return "[-]", "cyan"
    return "[*]", "blue"


def _marker_for_severity(value: str | None) -> tuple[str, str]:
    severity = str(value or "").strip().lower()
    if severity in {"critical", "high"}:
        return "[!]", "red"
    if severity == "medium":
        return "[!]", "orange"
    if severity in {"low", "info"}:
        return "[*]", "cyan"
    return "[*]", "white"


def _module_tag(module_name: str | None) -> str:
    normalized = str(module_name or "").strip().lower()
    if not normalized:
        return "MODULE"
    return _MODULE_TAG_ALIASES.get(normalized, normalized.upper())


def _paint_tag(console: Console, label: str, *, width: int = 11) -> str:
    return console._paint(_clip_text(label, width).ljust(width), "blue", sys.stdout)


def _paint_text(console: Console, value: object, color: str = "white", *, width: int | None = None) -> str:
    text = _cell_text(value)
    if width is not None:
        text = _clip_text(text, width)
    return console._paint(text, color, sys.stdout)


def _paint_kv(
    console: Console, key: str, value: object, value_color: str = "white", *, width: int | None = None
) -> str:
    rendered_value = _paint_text(console, value, value_color, width=width)
    return f"{console._paint(f'{key}=', 'white', sys.stdout)}{rendered_value}"


def _timestamp_text(value: object) -> str:
    text = _cell_text(value).strip()
    if not text:
        return "-"
    normalized = text.replace("T", " ")
    if "." in normalized:
        normalized = normalized.split(".", 1)[0]
    if normalized.endswith("+00:00"):
        normalized = normalized[:-6]
    return normalized


def _compact_bytes(value: object) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return _cell_text(value) or "-"
    units = ("B", "KB", "MB", "GB")
    amount = float(size)
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return f"{int(amount)}{unit}"
    return f"{amount:.1f}{unit}"


def _normalized_ports(values: list[str]) -> list[str]:
    unique = {item.strip() for item in values if item and item.strip() and item.strip() != "-"}
    if not unique:
        return []

    def _port_key(value: str) -> tuple[int, int | str]:
        try:
            return (0, int(value))
        except ValueError:
            return (1, value)

    return sorted(unique, key=_port_key)


def _attach_host_port_summaries(
    host_rows: list[dict[str, object]],
    endpoint_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    endpoint_ports_by_key: dict[str, list[str]] = {}
    for endpoint in endpoint_rows:
        port_text = _cell_text(endpoint.get("port")).strip()
        if not port_text or port_text == "-":
            continue
        for key in (_cell_text(endpoint.get("host")).strip(), _cell_text(endpoint.get("ip")).strip()):
            if key:
                endpoint_ports_by_key.setdefault(key, []).append(port_text)

    enriched: list[dict[str, object]] = []
    for row in host_rows:
        item = dict(row)
        keys = {
            _cell_text(row.get("ip_address")).strip(),
            _cell_text(row.get("fqdn")).strip(),
            _cell_text(row.get("hostname")).strip(),
            _cell_text(row.get("canonical_key")).strip(),
        }
        ports: list[str] = []
        for key in keys:
            if key:
                ports.extend(endpoint_ports_by_key.get(key, []))
        normalized_ports = _normalized_ports(ports)
        item["ports_values"] = normalized_ports
        item["ports_text"] = ",".join(normalized_ports) if normalized_ports else "-"
        enriched.append(item)
    return enriched


def _render_module_summary_line(console: Console, row: dict[str, object], *, include_records: bool = False) -> None:
    rendered = (
        f"{_paint_tag(console, _module_tag(_cell_text(row.get('module'))))} "
        f"{_paint_kv(console, 'hosts', row.get('hosts_count'), 'white')} "
        f"{_paint_kv(console, 'endpoints', row.get('endpoints_count'), 'white')} "
        f"{_paint_kv(console, 'findings', row.get('findings_count'), 'orange')} "
        f"{_paint_kv(console, 'runs', row.get('runs_count'), 'cyan')} "
        f"{_paint_kv(console, 'artifacts', row.get('artifacts_count'), 'magenta')} "
    )
    if include_records:
        rendered += f"{_paint_kv(console, 'records', row.get('records_count'), 'white')} "
    rendered += _paint_kv(console, "seen", _timestamp_text(row.get("last_seen_at")), "white", width=19)
    console.plain(rendered)


def _render_database_totals(console: Console, row: dict[str, object]) -> None:
    rendered = (
        f"{_paint_tag(console, 'DB')} "
        f"{_paint_kv(console, 'hosts', row.get('hosts_count'), 'white')} "
        f"{_paint_kv(console, 'endpoints', row.get('endpoints_count'), 'white')} "
        f"{_paint_kv(console, 'findings', row.get('findings_count'), 'orange')} "
        f"{_paint_kv(console, 'runs', row.get('runs_count'), 'cyan')} "
        f"{_paint_kv(console, 'artifacts', row.get('artifacts_count'), 'magenta')} "
        f"{_paint_kv(console, 'imports', row.get('import_jobs_count'), 'white')} "
        f"{_paint_kv(console, 'exports', row.get('export_jobs_count'), 'white')} "
        f"{_paint_kv(console, 'seen', _timestamp_text(row.get('last_seen_at')), 'white', width=19)}"
    )
    console.plain(rendered)


def _render_host_row(console: Console, row: dict[str, object]) -> None:
    primary = (
        _cell_text(row.get("ip_address"))
        or _cell_text(row.get("fqdn"))
        or _cell_text(row.get("hostname"))
        or _cell_text(row.get("canonical_key"))
        or "-"
    )
    details: list[str] = []
    hostname = _cell_text(row.get("hostname"))
    fqdn = _cell_text(row.get("fqdn"))
    canonical_key = _cell_text(row.get("canonical_key"))
    if hostname and hostname != primary:
        details.append(_paint_kv(console, "host", hostname, "white", width=24))
    if fqdn and fqdn != primary and fqdn != hostname:
        details.append(_paint_kv(console, "fqdn", fqdn, "white", width=32))
    if canonical_key and canonical_key not in {primary, hostname, fqdn}:
        details.append(_paint_kv(console, "key", canonical_key, "white", width=40))
    details.append(_paint_kv(console, "seen", _timestamp_text(row.get("last_seen_at")), "white", width=19))
    rendered = f"{_paint_tag(console, 'HOST')} {_paint_text(console, primary, 'white', width=34)} {' '.join(details)}"
    console.plain(rendered.rstrip())


def _render_module_host_row(console: Console, row: dict[str, object], *, module_name: str) -> None:
    primary = (
        _cell_text(row.get("ip_address"))
        or _cell_text(row.get("fqdn"))
        or _cell_text(row.get("hostname"))
        or _cell_text(row.get("canonical_key"))
        or "-"
    )
    tag = _paint_tag(console, _module_tag(module_name))
    seen = _paint_kv(console, "seen", _timestamp_text(row.get("last_seen_at")), "white", width=19)
    ports_values = row.get("ports_values")
    if isinstance(ports_values, list) and ports_values:
        for port in [_cell_text(item) for item in ports_values if _cell_text(item)]:
            console.plain(
                " ".join(
                    [
                        tag,
                        console._paint(primary, "white", sys.stdout),
                        _paint_kv(console, "ports", port, "white"),
                        seen,
                    ]
                )
            )
        return
    ports_text = _cell_text(row.get("ports_text")).strip()
    if ports_text and ports_text != "-":
        console.plain(
            " ".join(
                [
                    tag,
                    console._paint(primary, "white", sys.stdout),
                    _paint_kv(console, "ports", ports_text, "white"),
                    seen,
                ]
            )
        )
        return
    console.plain(" ".join([tag, console._paint(primary, "white", sys.stdout), seen]))


def _render_endpoint_row(console: Console, row: dict[str, object], *, verbose: bool = False) -> None:
    target = _cell_text(row.get("canonical_key")) or "-"
    console.plain(f"{_paint_tag(console, 'ENDPOINT')} {_paint_text(console, target, 'orange', width=82)}")
    if not verbose:
        return
    rendered = (
        " " * 12
        + _paint_kv(console, "scheme", row.get("scheme") or "-", "white", width=8)
        + " "
        + _paint_kv(console, "host", row.get("host") or "-", "white", width=32)
        + " "
        + _paint_kv(console, "ip", row.get("ip") or "-", "white", width=24)
        + " "
        + _paint_kv(console, "port", row.get("port") or "-", "white", width=6)
        + " "
        + _paint_kv(console, "path", row.get("path") or "-", "white")
    )
    console.plain(rendered)


def _render_module_endpoint_row(
    console: Console,
    row: dict[str, object],
    *,
    module_name: str,
    verbose: bool = False,
) -> None:
    target = _cell_text(row.get("canonical_key")) or "-"
    console.plain(f"{_paint_tag(console, _module_tag(module_name))} {console._paint(target, 'orange', sys.stdout)}")
    if not verbose:
        return
    details = (
        " " * 12
        + _paint_kv(console, "scheme", row.get("scheme") or "-", "white")
        + " "
        + _paint_kv(console, "host", row.get("host") or "-", "white")
        + " "
        + _paint_kv(console, "ip", row.get("ip") or "-", "white")
        + " "
        + _paint_kv(console, "port", row.get("port") or "-", "white")
        + " "
        + _paint_kv(console, "path", row.get("path") or "-", "white")
    )
    console.plain(details)


def _render_finding_row(console: Console, row: dict[str, object], *, module_name: str | None = None) -> None:
    tag = _module_tag(module_name or _cell_text(row.get("module_name")))
    marker_text, marker_color = _marker_for_severity(_cell_text(row.get("severity")))
    title = _clip_text(_cell_text(row.get("title")) or "-", 92)
    rendered = (
        f"{_paint_tag(console, tag)} "
        f"{console._paint(marker_text, marker_color, sys.stdout)} "
        f"{console._paint(title, 'white', sys.stdout)}"
    )
    console.plain(rendered)
    details = (
        " " * 12
        + _paint_kv(console, "type", row.get("finding_type") or "-", "orange", width=26)
        + " "
        + _paint_kv(console, "protocol", row.get("protocol") or "-", "white", width=16)
        + " "
        + _paint_kv(
            console, "severity", row.get("severity") or "-", _severity_color(_cell_text(row.get("severity"))), width=10
        )
        + " "
        + _paint_kv(console, "status", row.get("status") or "-", _status_color(_cell_text(row.get("status"))), width=10)
        + " "
        + _paint_kv(console, "seen", _timestamp_text(row.get("last_seen_at")), "white", width=19)
    )
    console.plain(details)


def _render_module_recent_hit(console: Console, row: dict[str, object]) -> None:
    module_name = _cell_text(row.get("module")) or "module"
    tag_text = _module_tag(module_name)
    target = _clip_text(_cell_text(row.get("target") or "-"), 52)
    subject = _clip_text(_cell_text(row.get("subject") or module_name), 28)
    finding_type = _cell_text(row.get("finding_type")).strip()
    status = _cell_text(row.get("status")).strip()
    severity = _cell_text(row.get("severity")).strip()
    seen_at = _timestamp_text(row.get("seen_at"))
    phase = _cell_text(row.get("phase") or "-") or "-"

    if finding_type:
        marker_text, marker_color = _marker_for_severity(severity)
        status_label = "finding"
        status_value = finding_type
        status_color = _severity_color(severity)
    else:
        marker_text, marker_color = _marker_for_status(status)
        status_label = "status"
        status_value = status or "-"
        status_color = _status_color(status)

    console.plain(
        f"{_paint_tag(console, tag_text)} "
        f"{console._paint(target.ljust(54), 'white', sys.stdout)} "
        f"{console._paint(marker_text, marker_color, sys.stdout)} "
        f"{console._paint(subject, 'orange', sys.stdout)}"
    )

    details = (
        " " * 12
        + _paint_kv(console, "phase", phase, "cyan", width=12)
        + " "
        + _paint_kv(console, status_label, status_value, status_color)
        + " "
        + _paint_kv(console, "severity", severity or "-", _severity_color(severity), width=10)
        + " "
        + _paint_kv(console, "seen", seen_at, "white", width=19)
    )
    console.plain(details)

    location_value = _cell_text(row.get("endpoint_or_resource")).strip()
    location_label = _cell_text(row.get("endpoint_or_resource_label")).strip() or "resource"
    if location_value:
        console.plain(" " * 12 + _paint_kv(console, location_label, location_value, "white"))

    detail_value = _cell_text(row.get("detail")).strip()
    detail_label = _cell_text(row.get("detail_label")).strip() or "detail"
    if detail_value:
        console.plain(" " * 12 + _paint_kv(console, detail_label, detail_value, "orange"))

    title = _cell_text(row.get("title") or "-") or "-"
    console.plain(f"            {console._paint(title, 'white', sys.stdout)}")


def _render_module_finding_row(console: Console, row: dict[str, object], *, module_name: str) -> None:
    _render_module_recent_hit(
        console,
        {
            "module": module_name,
            "target": row.get("target") or row.get("endpoint"),
            "subject": row.get("finding_type") or row.get("protocol") or module_name,
            "phase": "finding",
            "finding_type": row.get("finding_type"),
            "status": row.get("status"),
            "severity": row.get("severity"),
            "seen_at": row.get("last_seen_at"),
            "endpoint_or_resource": row.get("endpoint"),
            "endpoint_or_resource_label": "endpoint" if row.get("endpoint") else None,
            "detail": row.get("description"),
            "detail_label": "detail" if row.get("description") else None,
            "title": row.get("title") or "-",
        },
    )


def _render_run_row(console: Console, row: dict[str, object], *, module_name: str | None = None) -> None:
    tag = _module_tag(module_name or _cell_text(row.get("module_name")))
    marker_text, marker_color = _marker_for_status(_cell_text(row.get("execution_status")))
    phase = _cell_text(row.get("source_type")) or "-"
    protocol = _cell_text(row.get("protocol")) or "-"
    rendered = (
        f"{_paint_tag(console, tag)} "
        f"{console._paint(marker_text, marker_color, sys.stdout)} "
        f"{_paint_kv(console, 'phase', phase, 'cyan', width=12)} "
        f"{_paint_kv(console, 'protocol', protocol, 'white', width=16)} "
        f"{_paint_kv(console, 'status', row.get('execution_status') or '-', _status_color(_cell_text(row.get('execution_status'))), width=10)} "
        f"{_paint_kv(console, 'start', _timestamp_text(row.get('started_at')), 'white', width=19)} "
        f"{_paint_kv(console, 'finish', _timestamp_text(row.get('finished_at')), 'white', width=19)}"
    )
    console.plain(rendered)


def _render_module_run_row(console: Console, row: dict[str, object], *, module_name: str) -> None:
    marker_text, marker_color = _marker_for_status(_cell_text(row.get("execution_status")))
    protocol = _cell_text(row.get("protocol")) or "-"
    console.plain(
        f"{_paint_tag(console, _module_tag(module_name))} "
        f"{console._paint(marker_text, marker_color, sys.stdout)} "
        f"{console._paint(protocol, 'white', sys.stdout)}"
    )
    details = (
        " " * 12
        + _paint_kv(console, "phase", row.get("source_type") or "-", "cyan")
        + " "
        + _paint_kv(
            console,
            "status",
            row.get("execution_status") or "-",
            _status_color(_cell_text(row.get("execution_status"))),
        )
        + " "
        + _paint_kv(console, "start", _timestamp_text(row.get("started_at")), "white", width=19)
        + " "
        + _paint_kv(console, "finish", _timestamp_text(row.get("finished_at")), "white", width=19)
    )
    console.plain(details)


def _render_artifact_row(console: Console, row: dict[str, object]) -> None:
    sha_value = _cell_text(row.get("sha256"))
    preview = _clip_text(_cell_text(row.get("sanitized_preview_text")) or "-", 108)
    rendered = (
        f"{_paint_tag(console, 'ARTIFACT')} "
        f"{_paint_kv(console, 'role', row.get('artifact_role') or '-', 'cyan', width=18)} "
        f"{_paint_kv(console, 'mime', row.get('mime_type') or '-', 'white', width=24)} "
        f"{_paint_kv(console, 'enc', row.get('content_encoding') or '-', 'white', width=8)} "
        f"{_paint_kv(console, 'size', _compact_bytes(row.get('size_bytes')), 'white', width=10)} "
        f"{_paint_kv(console, 'sha', sha_value[:12] if sha_value else '-', 'white', width=12)}"
    )
    console.plain(rendered)
    console.plain(" " * 12 + _paint_kv(console, "preview", preview, "white", width=108))


def _render_module_artifact_row(console: Console, row: dict[str, object], *, module_name: str) -> None:
    sha_value = _cell_text(row.get("sha256"))
    preview = _cell_text(row.get("sanitized_preview_text")) or "-"
    console.plain(
        f"{_paint_tag(console, _module_tag(module_name))} "
        f"{console._paint(_cell_text(row.get('artifact_role')) or '-', 'cyan', sys.stdout)}"
    )
    details = (
        " " * 12
        + _paint_kv(console, "mime", row.get("mime_type") or "-", "white")
        + " "
        + _paint_kv(console, "enc", row.get("content_encoding") or "-", "white")
        + " "
        + _paint_kv(console, "size", _compact_bytes(row.get("size_bytes")), "white")
        + " "
        + _paint_kv(console, "sha", sha_value[:12] if sha_value else "-", "white")
    )
    console.plain(details)
    console.plain(" " * 12 + _paint_kv(console, "preview", preview, "white"))


def _emit_line_section(
    console: Console,
    title: str,
    rows: list[dict[str, object]],
    renderer,
    *,
    empty_label: str,
) -> None:
    console.info(f"{title}: shown={len(rows)}")
    if not rows:
        console.warn(empty_label)
        console.plain("")
        return
    for row in rows:
        renderer(console, row)
    console.plain("")


def _emit_module_recent_hits(
    console: Console,
    module_name: str,
    payload: dict[str, object],
) -> None:
    hits = list(payload["recent_hits"])
    console.info(f"recent {module_name} hits/results: shown={len(hits)} limit={payload['limit']}")
    if not hits:
        console.warn(f"no recent {module_name} hits/results")
        return
    for row in hits:
        _render_module_recent_hit(console, row)


def _render_exporter_stage_row(console: Console, row: dict[str, object]) -> None:
    phase_tag = _cell_text(row.get("phase_tag") or "COLLECT").upper()
    host = _cell_text(row.get("host") or "-") or "-"
    port_value = row.get("port")
    port_text = _cell_text(port_value) if port_value not in (None, "") else "-"
    exporter_name = _cell_text(row.get("exporter_display_name") or "Exporter")
    endpoint = _cell_text(row.get("endpoint")).strip()
    url = _cell_text(row.get("url")).strip()
    reason = _cell_text(row.get("reason") or "-") or "-"
    sample = _cell_text(row.get("sample")).strip()
    detail = _cell_text(row.get("detail")).strip()

    tag = f"{phase_tag:<8}"
    prefix = f"\t{host}\t{port_text}\t"
    first_line_body = exporter_name
    if phase_tag == "COLLECT" and url:
        first_line_body += f" url={url}"
    line = (
        f"{console._paint(tag, 'blue', sys.stdout)}"
        f"{console._paint(prefix, 'white', sys.stdout)}"
        f" {console._paint('[+]', 'green', sys.stdout)} "
        f"{console._paint(first_line_body, 'white', sys.stdout)}"
    )
    console.plain(line)

    validate_tag = f"{'VALIDATE':<8}"
    validate_prefix = f"\t{host}\t{port_text}\t"
    header = (
        f"{console._paint(validate_tag, 'blue', sys.stdout)}"
        f"{console._paint(validate_prefix, 'white', sys.stdout)}"
        f" {console._paint('[*]', 'blue', sys.stdout)} "
        f"{console._paint(f'Dump Validate {exporter_name}', 'white', sys.stdout)}"
    )
    console.plain(header)

    reason_body = f"reason={reason}"
    if endpoint:
        reason_body += f" endpoint={endpoint}"
    reason_line = (
        f"{console._paint(validate_tag, 'blue', sys.stdout)}"
        f"{console._paint(validate_prefix, 'white', sys.stdout)}"
        f" {console._paint(reason_body, 'orange', sys.stdout)}"
    )
    console.plain(reason_line)

    evidence = sample or detail
    if evidence:
        evidence_line = (
            f"{console._paint(validate_tag, 'blue', sys.stdout)}"
            f"{console._paint(validate_prefix, 'white', sys.stdout)}"
            f" {console._paint(evidence, 'orange', sys.stdout)}"
        )
        console.plain(evidence_line)


def _emit_exporter_stage_rows(console: Console, rows: list[dict[str, object]]) -> None:
    if not rows:
        console.warn("no recent exporter results")
        return
    for row in rows:
        _render_exporter_stage_row(console, row)


def _render_exporter_stage_line(console: Console, line: str) -> bool:
    if not line.startswith(("COLLECT ", "TRIGGER ", "VALIDATE")):
        return False
    parts = line.split("\t", 3)
    if len(parts) != 4:
        console.plain(line)
        return True
    tag_text, host, port, tail = parts
    prefix = f"\t{host}\t{port}\t"
    if tail.startswith(" [+] "):
        marker = "[+]"
        body = tail[len(" [+] ") :]
        body_color = "white"
    elif tail.startswith(" [*] "):
        marker = "[*]"
        body = tail[len(" [*] ") :]
        body_color = "white"
    else:
        marker = None
        body = tail.strip()
        body_color = "orange"

    rendered = f"{console._paint(tag_text, 'blue', sys.stdout)}{console._paint(prefix, 'white', sys.stdout)}"
    if marker is not None:
        marker_color = "green" if marker == "[+]" else "blue"
        rendered += (
            f" {console._paint(marker, marker_color, sys.stdout)} {console._paint(body, body_color, sys.stdout)}"
        )
    else:
        rendered += f" {console._paint(body, body_color, sys.stdout)}"
    console.plain(rendered)
    return True


def _emit_module_stage_line(console: Console, module_name: str, line: str) -> None:
    if module_name == "exporters":
        if _render_exporter_stage_line(console, line):
            return
        console.plain(line)
        return
    renderer = _MODULE_STAGE_RENDERERS.get(module_name)
    if renderer is not None and renderer(console, line):
        return
    module_tag = str(module_name or "").strip().upper()
    if (
        module_tag
        and line.startswith(module_tag)
        and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] "))
    ):
        if console.render_tagged_payload_line(line, module_tag, payload_color="orange"):
            return
    console.plain(line)


def _emit_module_stage_records(console: Console, module_name: str, rows: list[dict[str, object]]) -> None:
    if not rows:
        if module_name == "exporters":
            console.warn("no recent exporter results")
            return
        console.warn(f"no recent {module_name} results")
        return
    for row in rows:
        _emit_module_stage_line(console, module_name, _cell_text(row.get("primary_line")))
        for detail_line in row.get("detail_lines") or []:
            _emit_module_stage_line(console, module_name, _cell_text(detail_line))


def _emit_module_dashboard(
    console: Console, module_name: str, dashboard: dict[str, object], *, verbose: bool = False
) -> None:
    summary = dict(dashboard["summary"])
    console.info(
        f"{module_name} summary: "
        f"hosts={summary['hosts_count']} "
        f"endpoints={summary['endpoints_count']} "
        f"findings={summary['findings_count']} "
        f"runs={summary['runs_count']} "
        f"artifacts={summary['artifacts_count']} "
        f"seen={_timestamp_text(summary.get('last_seen_at'))}"
    )
    _emit_line_section(
        console,
        "recent findings",
        list(dashboard["findings"]),
        lambda out, row: _render_finding_row(out, row, module_name=module_name),
        empty_label="no recent findings",
    )
    _emit_line_section(
        console,
        "recent hosts",
        list(dashboard["hosts"]),
        lambda out, row: _render_module_host_row(out, row, module_name=module_name),
        empty_label="no recent hosts",
    )
    _emit_line_section(
        console,
        "recent endpoints",
        list(dashboard["endpoints"]),
        lambda out, row: _render_module_endpoint_row(out, row, module_name=module_name, verbose=verbose),
        empty_label="no recent endpoints",
    )
    _emit_line_section(
        console,
        "recent runs",
        list(dashboard["runs"]),
        lambda out, row: _render_module_run_row(out, row, module_name=module_name),
        empty_label="no recent runs",
    )


def _handle_show_module_dashboard(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    exporter_phase_filter: str | None = None
    exporter_host_filter: str | None = None
    if args.module_name == "exporters":
        if bool(getattr(args, "exporters_collect_only", False)):
            exporter_phase_filter = "collect"
        elif bool(getattr(args, "exporters_trigger_only", False)):
            exporter_phase_filter = "trigger"
        exporter_host_filter = str(getattr(args, "exporters_host_filter", "") or "").strip() or None
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        if args.module_name == "exporters":
            hits = query_service.list_recent_exporter_hits(
                workspace_id=workspace_id,
                limit=query_service.MODULE_RECENT_HITS_LIMIT,
                phase_filter=exporter_phase_filter,
                host_filter=exporter_host_filter,
            )
        else:
            hits = query_service.list_recent_module_hits(
                workspace_id=workspace_id,
                module_name=args.module_name,
                limit=query_service.MODULE_RECENT_HITS_LIMIT,
            )
        payload = {
            "module": args.module_name,
            "recent_hits": [item.model_dump() for item in hits],
            "shown": len(hits),
            "limit": query_service.MODULE_RECENT_HITS_LIMIT,
        }
        stage_rows: list[dict[str, object]] = []
        if not args.as_json:
            stage_rows = [
                item.model_dump()
                for item in query_service.list_module_stage_records(
                    workspace_id=workspace_id,
                    module_name=args.module_name,
                    limit=query_service.MODULE_RECENT_HITS_LIMIT,
                    phase_filter=exporter_phase_filter,
                    host_filter=exporter_host_filter,
                )
            ]
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return 0
    console = Console(debug=False)
    _emit_module_stage_records(console, args.module_name, stage_rows)
    return 0


def _handle_show_overview(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        overview = query_service.get_database_overview(workspace_id=workspace_id, modules=DB_SHOW_MODULES)
    if args.as_json:
        print(json.dumps(overview.model_dump(), ensure_ascii=False, indent=2, default=str))
        return 0
    console = Console(debug=False)
    console.info("database totals")
    _render_database_totals(console, overview.totals.model_dump())
    console.info(f"modules: shown={len(overview.modules)}")
    if not overview.modules:
        console.warn("no module rows")
        return 0
    for item in overview.modules:
        _render_module_summary_line(console, item.model_dump(), include_records=True)
    return 0


def _settings_from_args(args: Namespace) -> str:
    settings = resolve_database_settings(db_url=getattr(args, "db_url", None))
    return settings.db_url


def _ensure_db_ready(args: Namespace) -> None:
    initialize_runtime_database(_settings_from_args(args))


def _handle_db_init(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    db = DatabaseService(db_url)
    try:
        db.init_database()
        print(f"initialized {db_url}")
    finally:
        db.close()
    return 0


def _handle_db_migrate(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    db = DatabaseService(db_url)
    try:
        db.migrate()
        print(f"migrated {db_url}")
    finally:
        db.close()
    return 0


def _handle_ingest(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, _, ingest_service, _, _):
        stats = ingest_service.ingest_file(
            workspace_slug=None,
            module_name=args.module,
            json_file=args.json_file,
        )
    if args.as_json:
        print(json.dumps(stats, ensure_ascii=False, indent=2, default=str))
        return 0
    for key, value in stats.items():
        print(f"{key}: {value}")
    return 0


def _handle_show_hosts(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = [
            item.model_dump()
            for item in query_service.list_hosts(workspace_id=workspace_id, module_name=args.module_name)
        ]
        if args.module_name:
            endpoint_rows = [
                item.model_dump()
                for item in query_service.list_endpoints(workspace_id=workspace_id, module_name=args.module_name)
            ]
            rows = _attach_host_port_summaries(rows, endpoint_rows)
    if args.as_json:
        _emit_rows(rows, ["id", "canonical_key", "hostname", "fqdn", "ip_address", "last_seen_at"], as_json=True)
        return 0
    console = Console(debug=False)
    title = "hosts" if not args.module_name else f"{args.module_name} hosts"
    renderer = _render_host_row
    if args.module_name:

        def _module_host_renderer(out: Console, row: dict[str, object]) -> None:
            _render_module_host_row(out, row, module_name=args.module_name)

        renderer = _module_host_renderer
    _emit_line_section(console, title, rows, renderer, empty_label="no hosts")
    return 0


def _handle_show_module_summary(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        summary = query_service.get_module_summary(
            workspace_id=workspace_id,
            module_name=args.module_name,
        )
    if args.as_json:
        _emit_rows(
            [summary.model_dump()],
            [
                "module",
                "hosts_count",
                "endpoints_count",
                "findings_count",
                "runs_count",
                "artifacts_count",
                "last_seen_at",
            ],
            as_json=True,
        )
        return 0
    console = Console(debug=False)
    console.info(f"{args.module_name} summary")
    _render_module_summary_line(console, summary.model_dump())
    return 0


def _handle_show_endpoints(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = [
            item.model_dump()
            for item in query_service.list_endpoints(
                workspace_id=workspace_id,
                host_id=args.host_id,
                module_name=args.module_name,
            )
        ]
    if args.as_json:
        _emit_rows(rows, ["id", "canonical_key", "scheme", "host", "ip", "port", "path"], as_json=True)
        return 0
    console = Console(debug=False)
    title = "endpoints" if not args.module_name else f"{args.module_name} endpoints"
    verbose = bool(getattr(args, "debug", False))

    def _endpoint_renderer(out: Console, row: dict[str, object]) -> None:
        _render_endpoint_row(out, row, verbose=verbose)

    renderer = _endpoint_renderer
    if args.module_name:

        def _module_endpoint_renderer(out: Console, row: dict[str, object]) -> None:
            _render_module_endpoint_row(out, row, module_name=args.module_name, verbose=verbose)

        renderer = _module_endpoint_renderer
    _emit_line_section(console, title, rows, renderer, empty_label="no endpoints")
    return 0


def _handle_show_findings(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = query_service.list_findings(
            workspace_id=workspace_id,
            filters=FindingFilter(
                module_name=args.module_name,
                protocol=args.protocol,
                severity=args.severity,
                status=args.status,
                tag=args.tag,
                date_from=args.date_from,
                date_to=args.date_to,
            ),
        )
        payload_rows = [item.model_dump() for item in rows]
    if args.as_json:
        _emit_rows(
            payload_rows,
            ["id", "title", "finding_type", "protocol", "module_name", "severity", "status", "last_seen_at"],
            as_json=True,
        )
        return 0
    console = Console(debug=False)
    title = "findings" if not args.module_name else f"{args.module_name} findings"
    renderer = _render_finding_row
    if args.module_name:

        def _module_finding_renderer(out: Console, row: dict[str, object]) -> None:
            _render_module_finding_row(out, row, module_name=args.module_name)

        renderer = _module_finding_renderer
    _emit_line_section(console, title, payload_rows, renderer, empty_label="no findings")
    return 0


def _handle_show_runs(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = [
            item.model_dump()
            for item in query_service.list_runs(
                workspace_id=workspace_id,
                target_text=args.target,
                module_name=args.module_name,
            )
        ]
    if args.as_json:
        _emit_rows(
            rows,
            ["id", "module_name", "protocol", "source_type", "execution_status", "started_at", "finished_at"],
            as_json=True,
        )
        return 0
    console = Console(debug=False)
    title = "runs" if not args.module_name else f"{args.module_name} runs"
    renderer = _render_run_row
    if args.module_name:

        def _module_run_renderer(out: Console, row: dict[str, object]) -> None:
            _render_module_run_row(out, row, module_name=args.module_name)

        renderer = _module_run_renderer
    _emit_line_section(console, title, rows, renderer, empty_label="no runs")
    return 0


def _handle_show_artifacts(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = [
            item.model_dump()
            for item in query_service.list_artifacts(
                workspace_id=workspace_id,
                module_run_id=args.run_id,
                module_name=args.module_name,
            )
        ]
    if args.as_json:
        _emit_rows(
            rows,
            ["id", "artifact_role", "mime_type", "content_encoding", "sha256", "size_bytes", "sanitized_preview_text"],
            as_json=True,
        )
        return 0
    console = Console(debug=False)
    title = "artifacts" if not args.module_name else f"{args.module_name} artifacts"
    renderer = _render_artifact_row
    if args.module_name:

        def _module_artifact_renderer(out: Console, row: dict[str, object]) -> None:
            _render_module_artifact_row(out, row, module_name=args.module_name)

        renderer = _module_artifact_renderer
    _emit_line_section(console, title, rows, renderer, empty_label="no artifacts")
    return 0


def _handle_export_findings(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, _, export_service):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        print(
            export_service.export_findings(
                workspace_id=workspace_id,
                output_format=args.output_format,
                output_path=args.output,
                module_name=args.module_name,
            )
        )
    return 0


def _handle_export_database(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    db = DatabaseService(db_url)
    try:
        output_path = db.export_database(args.output)
        print(output_path)
    finally:
        db.close()
    return 0


def _handle_import_database(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    db = DatabaseService(db_url)
    try:
        target_path = db.import_database(args.input)
        print(target_path)
    finally:
        db.close()
    return 0


def _handle_export_hosts(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, _, export_service):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        print(
            export_service.export_hosts(
                workspace_id=workspace_id,
                output_format=args.output_format,
                output_path=args.output,
                module_name=args.module_name,
            )
        )
    return 0


def _handle_search(args: Namespace) -> int:
    db_url = _settings_from_args(args)
    with _service_scope(db_url) as (_, workspace_service, _, query_service, _):
        workspace_id, _ = _workspace_id_or_die(workspace_service)
        rows = query_service.search(workspace_id=workspace_id, query=args.query)
        rows = [{key: value for key, value in row.items() if key != "workspace_id"} for row in rows]
    _emit_rows(rows, ["entity_type", "entity_id", "title", "body", "tags_text"], as_json=bool(args.as_json))
    return 0


_DB_HANDLERS = {
    "init": _handle_db_init,
    "migrate": _handle_db_migrate,
    "ingest": _handle_ingest,
    "show_overview": _handle_show_overview,
    "show_hosts": _handle_show_hosts,
    "show_module_dashboard": _handle_show_module_dashboard,
    "show_module_summary": _handle_show_module_summary,
    "show_endpoints": _handle_show_endpoints,
    "show_findings": _handle_show_findings,
    "show_runs": _handle_show_runs,
    "show_artifacts": _handle_show_artifacts,
    "export_database": _handle_export_database,
    "export_findings": _handle_export_findings,
    "export_hosts": _handle_export_hosts,
    "import_database": _handle_import_database,
    "search": _handle_search,
}


def run_db_command(args: Namespace) -> int:
    handler_name = getattr(args, "db_handler_name", None)
    handler = _DB_HANDLERS.get(handler_name)
    if handler is None:
        print("[error] unsupported db command", file=sys.stderr)
        return 2
    if handler_name not in {"init", "migrate", "import_database"}:
        try:
            _ensure_db_ready(args)
        except Exception as exc:
            print(f"[error] failed to initialize db: {exc}", file=sys.stderr)
            return 2
    try:
        return int(handler(args))
    except (FileNotFoundError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
