"""Keeper adapters over the shared ZooKeeper-protocol audit primitives."""

from __future__ import annotations

from typing import Any

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
from ..zookeeper.actions import (
    host_stage as _zookeeper_protocol_host_stage,
)


def _render_colored_keeper_line(console: Any, line: str) -> bool:
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
