"""Exporter profile loading and validation."""

from __future__ import annotations

import json
from typing import Any

from .constants import COLLECT_DEBUG_ENDPOINTS, COLLECT_EXPORTERS, DISCOVERY_EXPORTERS, SCAN_EXPORTERS

_PROFILE_KEYS = {
    "trigger_exporters",
    "discovery_exporters",
    "collect_exporters",
    "collect_debug_endpoints",
}


def _as_port(value: Any, context: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context}: port must be an integer") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{context}: port must be in range 1..65535")
    return port


def _as_str_list(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"{context}: must be a non-empty list")
    result: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{context}[{idx}]: must be a non-empty string")
        result.append(item)
    return tuple(result)


def _validate_trigger_exporters(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("trigger_exporters: must be a list")
    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        context = f"trigger_exporters[{idx}]"
        if not isinstance(item, dict):
            raise ValueError(f"{context}: must be an object")
        validated.append(
            {
                "name": str(item.get("name") or ""),
                "port": _as_port(item.get("port"), context),
                "detect_path": str(item.get("detect_path") or ""),
                "markers": _as_str_list(item.get("markers"), f"{context}.markers"),
                "trigger_path": str(item.get("trigger_path") or ""),
                "target_fmt": str(item.get("target_fmt") or ""),
                "trigger_query": str(item.get("trigger_query") or ""),
            }
        )
        if not validated[-1]["name"]:
            raise ValueError(f"{context}: name is required")
        if not validated[-1]["detect_path"]:
            raise ValueError(f"{context}: detect_path is required")
        if not validated[-1]["trigger_path"]:
            raise ValueError(f"{context}: trigger_path is required")
        if not validated[-1]["target_fmt"]:
            raise ValueError(f"{context}: target_fmt is required")
    return validated


def _validate_discovery_exporters(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("discovery_exporters: must be a list")
    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        context = f"discovery_exporters[{idx}]"
        if not isinstance(item, dict):
            raise ValueError(f"{context}: must be an object")
        name = str(item.get("name") or "")
        if not name:
            raise ValueError(f"{context}: name is required")
        validated.append(
            {
                "name": name,
                "port": _as_port(item.get("port"), context),
                "markers": _as_str_list(item.get("markers"), f"{context}.markers"),
            }
        )
    return validated


def _validate_collect_exporters(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("collect_exporters: must be a list")
    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        context = f"collect_exporters[{idx}]"
        if not isinstance(item, dict):
            raise ValueError(f"{context}: must be an object")
        name = str(item.get("name") or "")
        if not name:
            raise ValueError(f"{context}: name is required")
        validated.append(
            {
                "name": name,
                "port": _as_port(item.get("port"), context),
            }
        )
    return validated


def _validate_collect_endpoints(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError("collect_debug_endpoints: must be a non-empty list")
    endpoints: list[str] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, str) or not item.startswith("/"):
            raise ValueError(f"collect_debug_endpoints[{idx}]: must be a string starting with '/'")
        endpoints.append(item)
    return tuple(endpoints)


def _default_profiles() -> dict[str, Any]:
    return {
        "trigger_exporters": [dict(item) for item in SCAN_EXPORTERS],
        "discovery_exporters": [dict(item) for item in DISCOVERY_EXPORTERS],
        "collect_exporters": [dict(item) for item in COLLECT_EXPORTERS],
        "collect_debug_endpoints": tuple(COLLECT_DEBUG_ENDPOINTS),
    }


def load_profiles(path: str | None) -> dict[str, Any]:
    profiles = _default_profiles()
    if not path:
        return profiles

    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    if not isinstance(raw, dict):
        raise ValueError("profiles file must be a JSON object")

    unknown = set(raw.keys()) - _PROFILE_KEYS
    if unknown:
        raise ValueError(f"unknown profile keys: {', '.join(sorted(unknown))}")

    if "trigger_exporters" in raw:
        profiles["trigger_exporters"] = _validate_trigger_exporters(raw["trigger_exporters"])
    if "discovery_exporters" in raw:
        profiles["discovery_exporters"] = _validate_discovery_exporters(raw["discovery_exporters"])
    if "collect_exporters" in raw:
        profiles["collect_exporters"] = _validate_collect_exporters(raw["collect_exporters"])
    if "collect_debug_endpoints" in raw:
        profiles["collect_debug_endpoints"] = _validate_collect_endpoints(raw["collect_debug_endpoints"])

    return profiles
