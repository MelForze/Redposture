"""Output formatting helpers for exporter scan/collect flows."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

EXPORTER_DISPLAY_NAMES = {
    "nats_exporter": "NATS Exporter",
    "statsd_exporter": "StatsD Exporter",
    "mysqld_exporter": "MySQLd Exporter",
    "blackbox_exporter": "Blackbox Exporter",
    "elasticsearch_exporter": "Elasticsearch Exporter",
    "nginx_exporter": "Nginx Exporter",
    "haproxy_exporter": "HAProxy Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "memcached_exporter": "Memcached Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "snmp_exporter": "SNMP Exporter",
    "apache_exporter": "Apache Exporter",
    "bind_exporter": "BIND Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "pgbackrest_exporter": "pgBackRest Exporter",
    "victoriametrics_exporter": "VictoriaMetrics Exporter",
    "ceph_exporter": "Ceph Exporter",
    "varnish_exporter": "Varnish Exporter",
    "windows_exporter": "Windows Exporter",
    "ipmi_exporter": "IPMI Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "sql_exporter": "SQL Exporter",
    "ping_exporter": "Ping Exporter",
    "rabbitmq_exporter": "RabbitMQ Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}


def clip(value: Any, width: int) -> str:
    text = str(value if value is not None else "-").replace("\n", "\\n")
    if width <= 3 or len(text) <= width:
        return text[:width]
    return text[: width - 3] + "..."


def status_value(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def extract_display_port(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "-"
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    if parsed.port is not None:
        return str(parsed.port)
    scheme = parsed.scheme.lower()
    if scheme == "http":
        return "80"
    if scheme == "https":
        return "443"
    return "-"


def scan_nxc_prefix(record: dict[str, Any]) -> str:
    host = clip(record.get("host") or "-", 64)
    port = status_value(record.get("port"))
    return f"{'SCAN':<8}\t{host}\t{port}\t"


def exporter_display_name(value: str) -> str:
    key = (value or "").strip().lower()
    return EXPORTER_DISPLAY_NAMES.get(key, value)


def format_scan_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    if record.get("type") == "summary":
        output_path = record.get("output_path")
        output_suffix = f" output={output_path}" if output_path else ""
        return (
            f"{'SCAN':<8}\tsummary\t-\t[*] "
            f"hosts={record.get('hosts')} checks={record.get('checks')} found={record.get('found')}{output_suffix}"
        )

    prefix = scan_nxc_prefix(record)
    exporter = clip(record.get("exporter") or "-", 24)
    method = clip(record.get("method") or "-", 12)
    marker = clip(record.get("marker_hit") or "-", 28)
    error = clip(record.get("error") or "-", 64)

    if bool(record.get("detected")):
        display_name = exporter_display_name(str(record.get("exporter") or "-"))
        return f"{prefix} [+] {display_name}"

    if error != "-":
        return f"{prefix} [!] exporter={exporter} request failed err={error}"

    return f"{prefix} [-] exporter={exporter} not detected via={method} marker={marker}"


def format_collect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    if record.get("type") == "summary":
        output_path = record.get("output_path")
        output_suffix = f" output={output_path}" if output_path else ""
        return (
            f"{'COLLECT':<8}\tsummary\t-\t[*] "
            f"hosts={record.get('hosts')} requests={record.get('requests')} "
            f"success={record.get('success')}{output_suffix}"
        )

    host = clip(record.get("host") or "-", 64)
    port = status_value(record.get("port"))
    prefix = f"{'COLLECT':<8}\t{host}\t{port}\t"
    exporter_name = exporter_display_name(str(record.get("exporter") or "-"))
    endpoint = clip(record.get("endpoint") or "-", 30)
    url = str(record.get("url") or "-")
    error = clip(record.get("error") or "-", 64)

    if bool(record.get("ok")):
        return f"{prefix} [+] {exporter_name} url={url}"

    if error != "-":
        return f"{prefix} [!] {exporter_name} url={url} err={error}"

    return f"{prefix} [-] {exporter_name} url={url} endpoint={endpoint}"


def emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


__all__ = [
    "EXPORTER_DISPLAY_NAMES",
    "clip",
    "emit_line",
    "exporter_display_name",
    "extract_display_port",
    "format_collect_record",
    "format_scan_record",
    "scan_nxc_prefix",
    "status_value",
]
