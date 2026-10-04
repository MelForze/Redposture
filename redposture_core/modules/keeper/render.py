"""Render helpers for the ClickHouse Keeper audit module."""

from __future__ import annotations

from typing import Any

from ...exporters.output import emit_line as _emit_line
from .actions import (
    _format_credential_attempts_records,
    _format_credential_verification_records,
    _format_detect_record,
    _format_record,
    _format_znode_capability_records,
    _format_znodes_detail_records,
    _nxc_prefix,
    _render_colored_keeper_line,
)


def _ddl_target_context(result: dict[str, Any]) -> str:
    cluster = str(result.get("cluster") or "-")
    raw_hosts = result.get("hosts")
    hosts = [str(host) for host in raw_hosts] if isinstance(raw_hosts, list) else []
    return f"(cluster:{cluster}) (hosts:{len(hosts)}:{','.join(hosts) if hosts else '-'})"


def _ddl_creation_line(prefix: str, username: str, result: dict[str, Any]) -> str:
    status = str(result.get("status") or "unavailable")
    wording = {
        "created": "created",
        "partial": "partially created",
        "unverified": "creation unverified",
    }.get(status, "not created")
    marker = "[+]" if status == "created" else "[-]"
    line = f'{prefix} {marker} ClickHouse user "{username}" {wording} {_ddl_target_context(result)}'
    reason = result.get("reason")
    if reason and status in {"failed", "unavailable"}:
        line += f" (reason:{reason})"
    return line


def _ddl_grant_line(prefix: str, result: dict[str, Any]) -> str | None:
    status = str(result.get("admin_status") or "not_requested")
    if status in {"not_requested", "not_attempted"}:
        return None
    wording = {
        "granted": "granted",
        "partial": "partially granted",
        "unverified": "grant unverified",
    }.get(status, "not granted")
    marker = "[+]" if status == "granted" else "[-]"
    line = f"{prefix} {marker} Administration rights {wording} {_ddl_target_context(result)}"
    reason = result.get("reason")
    if reason and status in {"failed", "unavailable"}:
        line += f" (reason:{reason})"
    return line


def _format_ddl_user_creation_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []
    result = record.get("ddl_user_creation")
    if not isinstance(result, dict):
        return []
    prefix = _nxc_prefix(record)
    username = str(result.get("username") or "-")
    cluster_results = result.get("clusters")
    if isinstance(cluster_results, list) and cluster_results:
        lines: list[str] = []
        for item in cluster_results:
            if not isinstance(item, dict):
                continue
            lines.append(_ddl_creation_line(prefix, username, item))
            grant_line = _ddl_grant_line(prefix, item)
            if grant_line is not None:
                lines.append(grant_line)
        return lines
    lines = [_ddl_creation_line(prefix, username, result)]
    grant_line = _ddl_grant_line(prefix, result)
    if grant_line is not None:
        lines.append(grant_line)
    return lines


def _format_ddl_topology_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if output_format == "json":
        return []
    requested = record.get("ddl_topology_requested")
    topology = record.get("ddl_topology")
    if not isinstance(requested, dict) or not isinstance(topology, dict):
        return []
    prefix = _nxc_prefix(record)
    clusters = topology.get("clusters")
    if topology.get("status") != "ok" or not isinstance(clusters, dict):
        reason = str(topology.get("reason") or "unavailable") if debug else "unavailable"
        return [f"{prefix} [-] DDL topology {reason}"]
    lines: list[str] = []
    if requested.get("clusters"):
        lines.append(f"{prefix} [*] DDL Clusters (clusters:{len(clusters)})")
        for cluster in sorted(clusters):
            lines.append(f'{prefix} [*] Cluster="{cluster}"')
    if requested.get("hosts"):
        count = sum(len(hosts) for hosts in clusters.values() if isinstance(hosts, list))
        lines.append(f"{prefix} [*] DDL Worker Hosts (hosts:{count})")
        for cluster, hosts in sorted(clusters.items()):
            if not isinstance(hosts, list):
                continue
            for host in hosts:
                lines.append(f'{prefix} [*] Cluster="{cluster}" Host="{host}"')
    return lines


__all__ = [
    "_nxc_prefix",
    "_emit_line",
    "_format_credential_attempts_records",
    "_format_credential_verification_records",
    "_format_ddl_topology_records",
    "_format_ddl_user_creation_records",
    "_format_detect_record",
    "_format_record",
    "_format_znode_capability_records",
    "_format_znodes_detail_records",
    "_render_colored_keeper_line",
]
