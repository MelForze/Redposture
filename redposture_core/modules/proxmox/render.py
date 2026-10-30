"""Render helpers for the proxmox audit module."""

from __future__ import annotations

from .actions import (
    _format_add_user_detail_records,
    _format_credential_attempts_records,
    _format_detect_record,
    _format_discovered_urls_detail_records,
    _format_findings_detail_records,
    _format_nodes_detail_records,
    _format_partial_detail_records,
    _format_record,
    _format_single_finding_detail_line,
    _format_users_detail_records,
    _nxc_prefix,
    _render_colored_proxmox_line,
)


def _stream_proxmox_status(
    *,
    out_fh,
    emit_line,
    lock,
    status_emitted: set[tuple[str, int]],
    record: dict,
    output_format: str,
    suppress_fail_status_lines: bool = False,
    emit_detect_line: bool = True,
) -> None:
    key = (str(record.get("host") or ""), int(record.get("port") or 0))
    with lock:
        lines: list[str] = []
        if emit_detect_line and key not in status_emitted:
            lines.append(_format_detect_record(record, output_format))
            status_emitted.add(key)
        if not (suppress_fail_status_lines and str(record.get("status") or "") == "fail"):
            lines.append(_format_record(record, output_format))
        for line in lines:
            if out_fh is not None:
                out_fh.write(line + "\n")
                out_fh.flush()
            else:
                emit_line(line)


__all__ = [
    "_nxc_prefix",
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_findings_detail_records",
    "_format_single_finding_detail_line",
    "_format_discovered_urls_detail_records",
    "_format_nodes_detail_records",
    "_format_partial_detail_records",
    "_format_users_detail_records",
    "_format_add_user_detail_records",
    "_render_colored_proxmox_line",
    "_stream_proxmox_status",
]


def _format_vms_detail_records(record: dict, output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("show_vms"):
        return []
    prefix = _nxc_prefix(record)
    guests = record.get("vms") or []
    count = len(guests) if "vms" in record else "unknown"
    rows = [f"{prefix} [*] VMs Enumeration (Count:{count})"]
    if "vms" not in record:
        rows.append(f"{prefix} [*] VMs unavailable (reason:authenticated inventory was not obtained)")
    if record.get("vms_error"):
        rows.append(f"{prefix} [*] VMs unavailable (reason:{record['vms_error']})")
    for guest in guests:
        rows.append(
            f"{prefix} [*] VM={guest.get('vmid')} Name={guest.get('name')} (execute:{guest.get('execute') is True}) (type:{guest.get('type')}) (node:{guest.get('node')}) (status:{guest.get('status')})"
            + (f" (reason:{guest['execute_reason']})" if guest.get("execute_reason") else "")
        )
    return rows


def _format_execution_detail_records(record: dict, output_format: str) -> list[str]:
    from ..execution_api import render

    if output_format != "txt":
        return []
    rows = render("proxmox", record)
    execution = record.get("execution") or {}
    if execution.get("signal"):
        rows.append(f"{_nxc_prefix(record)} <error:command terminated by signal {execution['signal']}>")
    return rows


__all__ += ["_format_vms_detail_records", "_format_execution_detail_records"]
