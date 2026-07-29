"""Render helpers for the proxmox audit module."""

from __future__ import annotations

from .actions import (
    _format_add_user_detail_records,
    _format_credential_attempts_records,
    _format_detect_record,
    _format_discovered_urls_detail_records,
    _format_findings_detail_records,
    _format_nodes_detail_records,
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
    "_format_users_detail_records",
    "_format_add_user_detail_records",
    "_render_colored_proxmox_line",
    "_stream_proxmox_status",
]
