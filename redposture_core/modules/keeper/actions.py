"""Keeper adapters over the shared ZooKeeper-protocol audit primitives."""

from __future__ import annotations

import re
import secrets
from typing import Any

from ...clients.zookeeper import (
    _ZK_CREATE_EPHEMERAL,
    _ZK_ERR_NOAUTH,
    _ZK_ERR_NODEEXISTS,
    _ZK_ERR_NONODE,
    _ZK_ERR_OK,
    _zk_error_name,
)
from ...rendering import CountColorRule, RegexColorRule, render_colored_marker_line
from ..zookeeper.actions import (
    _format_credential_attempts_records,
    _format_credential_verification_records,
    _format_detect_record,
    _format_record,
    _format_znode_capability_records,
    _format_znodes_detail_records,
    _nxc_prefix,
    _render_colored_zookeeper_line,
)
from ..zookeeper.actions import host_stage as _zookeeper_protocol_host_stage

_DDL_QUEUE = "/clickhouse/task_queue/ddl"


def _ddl_host_spans(_marker: str, text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\(hosts:(\d+):([^)]*)\)", text):
        count = int(match.group(1))
        spans.append((match.start(1), match.end(1), "true_red" if count else "bright_green"))
        if match.group(2) != "-":
            spans.append((match.start(2), match.end(2), "orange"))
    return spans


def _reset_probe_session(client: Any) -> str | None:
    """Expire any ambiguous ephemeral marker before later lifecycle stages."""

    try:
        client.close()
        client.connect()
    except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
        return f"session reset failed: {exc}"
    return None


def probe_ddl_access(client: Any) -> tuple[str, str | None]:
    """Classify anonymous DDL-queue access using an ephemeral non-task child."""

    try:
        _children, read_err, _stat = client.get_children2(_DDL_QUEUE)
        read_err = int(read_err)
    except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
        return "Unknown", str(exc)
    if read_err == _ZK_ERR_NONODE:
        return "Absent", None
    readable = read_err == _ZK_ERR_OK
    if not readable and read_err != _ZK_ERR_NOAUTH:
        return "Unknown", f"read: {_zk_error_name(read_err)}"

    for _attempt in range(3):
        marker = f"{_DDL_QUEUE}/redposture-probe-{secrets.token_hex(12)}"
        try:
            create_err = int(client.create(marker, b"", flags=_ZK_CREATE_EPHEMERAL))
        except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
            reset_error = _reset_probe_session(client)
            detail = str(exc)
            return ("Read" if readable else "Unknown"), (f"{detail}; {reset_error}" if reset_error else detail)
        if create_err == _ZK_ERR_NODEEXISTS:
            continue
        if create_err == _ZK_ERR_NOAUTH:
            return ("Read" if readable else "Denied"), None
        if create_err != _ZK_ERR_OK:
            return ("Read" if readable else "Unknown"), f"create: {_zk_error_name(create_err)}"

        try:
            delete_err = int(client.delete(marker, -1))
        except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
            reset_error = _reset_probe_session(client)
            detail = f"delete: {exc}"
            return "Write", f"{detail}; {reset_error}" if reset_error else detail
        if delete_err != _ZK_ERR_OK:
            reset_error = _reset_probe_session(client)
            detail = f"delete: {_zk_error_name(delete_err)}"
            return "Write", f"{detail}; {reset_error}" if reset_error else detail
        return "Write", None

    return ("Read" if readable else "Unknown"), "marker collision"


def _render_colored_keeper_line(console: Any, line: str) -> bool:
    if any(
        marker in line
        for marker in (
            " [*] DDL Clusters ",
            " [*] DDL Worker Hosts ",
            " [*] Cluster=",
            " [+] ClickHouse user ",
            " [-] ClickHouse user ",
            " [+] Administration rights ",
            " [-] Administration rights ",
            " [-] DDL topology ",
        )
    ):
        return render_colored_marker_line(
            console,
            line,
            tag="KEEPER",
            include_auth_required=False,
            counts=(
                CountColorRule("clusters", "true_red", zero_color="bright_green"),
                CountColorRule("hosts", "true_red", zero_color="bright_green"),
            ),
            regexes=(
                RegexColorRule(r'(?<=Cluster=)"[^"]*"', "orange"),
                RegexColorRule(r'(?<=Host=)"[^"]*"', "orange"),
                RegexColorRule(r'(?<=ClickHouse user )"[^"]*"', "orange"),
                RegexColorRule(r'(?<=" )created\b', "true_red"),
                RegexColorRule(r'(?<=" )partially created\b', "orange"),
                RegexColorRule(r'(?<=" )not created\b', "bright_green"),
                RegexColorRule(r'(?<=" )creation unverified\b', "orange"),
                RegexColorRule(r"(?<=Administration rights )granted\b", "true_red"),
                RegexColorRule(r"(?<=Administration rights )partially granted\b", "orange"),
                RegexColorRule(r"(?<=Administration rights )not granted\b", "bright_green"),
                RegexColorRule(r"(?<=Administration rights )grant unverified\b", "orange"),
                RegexColorRule(r"(?<=cluster:)[^)]+", "orange"),
                RegexColorRule(r"(?<=reason:)[^)]+", "orange"),
                RegexColorRule(r"(?<=DDL topology )unavailable\b", "orange"),
            ),
            extra_spans=_ddl_host_spans,
        )
    return _render_colored_zookeeper_line(console, line)


# Compatibility boundary for integrations that import a module host action.
# Production Keeper routing uses the strict lifecycle engine in ``stage.py``.
host_stage = _zookeeper_protocol_host_stage


__all__ = [
    "_format_credential_attempts_records",
    "_format_credential_verification_records",
    "_format_detect_record",
    "_format_record",
    "_format_znode_capability_records",
    "_format_znodes_detail_records",
    "_nxc_prefix",
    "_render_colored_keeper_line",
    "host_stage",
]
