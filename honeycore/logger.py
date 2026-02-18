"""Human-readable logger used by server and scanner flows."""

from __future__ import annotations

import threading
from typing import Any

from .utils import utc_now_iso

_COLORS = {
    "red": "31",
    "yellow": "33",
    "cyan": "36",
}

_SERVICE_TAGS = {
    "postgres": "PG",
    "redis": "REDIS",
    "proxmox": "PVE",
    "blackbox": "BLACKBOX",
    "scanner": "TRIGGER",
    "scan": "SCAN",
    "collect": "COLLECT",
}

_KEY_ALIASES = {
    "username": "user",
    "password": "pass",
    "callback_target": "callback",
    "user_agent": "ua",
    "content_length": "len",
    "requestline": "request",
    "error_message": "error",
}

_PRIORITY_KEYS = (
    "phase",
    "method",
    "protocol",
    "path",
    "query",
    "target",
    "callback_target",
    "module",
    "endpoint_type",
    "endpoint",
    "exporter",
    "job",
    "instance",
    "command",
    "status",
    "user",
    "username",
    "pass",
    "password",
    "error",
    "error_message",
)


def _paint(text: str, color: str) -> str:
    code = _COLORS.get(color)
    if not code:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _clip(text: str, width: int = 92) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _value_text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value)
    return _clip(text.replace("\n", "\\n"))


class AttemptLogger:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def close(self) -> None:
        return

    def log(self, service: str, remote: tuple[str, int], **fields: Any) -> None:
        event = {
            "timestamp": utc_now_iso(),
            "service": service,
            "remote_addr": f"{remote[0]}:{remote[1]}",
        }
        for key, value in fields.items():
            if value is not None:
                event[key] = value

        line = self._format_event(event)
        color = self._event_color(event)
        with self._lock:
            print(_paint(line, color), flush=True)

    def _event_color(self, event: dict[str, Any]) -> str:
        if "password" in event:
            return "red"
        if event.get("error") or event.get("error_message"):
            return "yellow"
        phase = str(event.get("phase") or "")
        if phase.endswith("_error"):
            return "yellow"
        return "cyan"

    def _field_parts(self, event: dict[str, Any]) -> list[str]:
        parts: list[str] = []
        used: set[str] = set()
        base_keys = {"timestamp", "service", "remote_addr"}

        for key in _PRIORITY_KEYS:
            if key not in event or key in base_keys:
                continue
            alias = _KEY_ALIASES.get(key, key)
            value = event[key]
            if key == "password":
                value = "<empty>" if value == "" else value
            parts.append(f"{alias}={_value_text(value)}")
            used.add(key)

        for key in sorted(event.keys()):
            if key in base_keys or key in used:
                continue
            alias = _KEY_ALIASES.get(key, key)
            parts.append(f"{alias}={_value_text(event[key])}")

        return parts

    def _format_event(self, event: dict[str, Any]) -> str:
        service = str(event.get("service") or "event")
        remote = str(event.get("remote_addr") or "-")
        timestamp = str(event.get("timestamp") or "")
        short_time = timestamp[11:19] if len(timestamp) >= 19 else timestamp
        tag = _SERVICE_TAGS.get(service, service.upper())
        if "password" in event:
            level = "CRED"
        elif event.get("error") or event.get("error_message"):
            level = "WARN"
        else:
            level = "INFO"
        parts = self._field_parts(event)
        body = " ".join(parts)
        if body:
            return f"[{short_time}] [{level}] [{tag}] {remote} {body}"
        return f"[{short_time}] [{level}] [{tag}] {remote}"
