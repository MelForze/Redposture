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


def _format_ddl_user_creation_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []
    result = record.get("ddl_user_creation")
    if not isinstance(result, dict):
        return []
    prefix = _nxc_prefix(record)
    username = str(result.get("username") or "-")
    status = str(result.get("status") or "unavailable")
    lines = [f'{prefix} [!] ClickHouse user "{username}" creation:{status}']
    admin_status = str(result.get("admin_status") or "not_requested")
    if admin_status != "not_requested":
        lines.append(f"{prefix} [!] admin grant:{admin_status}")
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
    "_format_ddl_user_creation_records",
    "_format_ddl_topology_records",
    "_format_detect_record",
    "_format_record",
    "_format_znode_capability_records",
    "_format_znodes_detail_records",
    "_render_colored_keeper_line",
]
