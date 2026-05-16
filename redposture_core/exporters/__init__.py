"""Exporter scan/collect/trigger subsystem facades."""

from __future__ import annotations

from typing import Any

__all__ = [
    "collect_exporter_debug_data",
    "scan_exporter_presence",
    "scan_exporters_and_trigger",
]


def __getattr__(name: str) -> Any:
    if name == "collect_exporter_debug_data":
        from .collect import collect_exporter_debug_data

        return collect_exporter_debug_data
    if name == "scan_exporter_presence":
        from .discover import scan_exporter_presence

        return scan_exporter_presence
    if name == "scan_exporters_and_trigger":
        from .trigger import scan_exporters_and_trigger

        return scan_exporters_and_trigger
    raise AttributeError(name)
