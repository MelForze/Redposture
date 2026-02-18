"""Human-readable logger used by server and scanner flows."""

from __future__ import annotations

import os
import threading
from typing import Any

from .utils import utc_now_iso

_COLORS = {
    "red": "31",
    "yellow": "33",
    "cyan": "36",
}

_SERVICE_TAGS = {
    "postgres": "Postgres",
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


def _value_text(value: Any, clip_width: int | None = 92) -> str:
    if value is None:
        return "-"
    text = str(value)
    normalized = text.replace("\n", "\\n")
    if clip_width is None:
        return normalized
    return _clip(normalized, clip_width)


class AttemptLogger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._text_fh: Any | None = None
        self._text_path: str | None = None

    def close(self) -> None:
        with self._lock:
            if self._text_fh is not None:
                self._text_fh.close()
                self._text_fh = None
                self._text_path = None

    def set_text_output(self, path: str) -> None:
        with self._lock:
            if self._text_fh is not None:
                self._text_fh.close()
                self._text_fh = None
                self._text_path = None
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            self._text_fh = open(path, "w", encoding="utf-8")
            self._text_path = path

    def log(self, service: str, remote: tuple[str, int], **fields: Any) -> None:
        event = {
            "timestamp": utc_now_iso(),
            "service": service,
            "remote_addr": f"{remote[0]}:{remote[1]}",
        }
        for key, value in fields.items():
            if value is not None:
                event[key] = value

        line = self._format_event(event, clip_width=92)
        line_full = self._format_event(event, clip_width=None)
        color = self._event_color(event)
        with self._lock:
            print(_paint(line, color), flush=True)
            if self._text_fh is not None:
                self._text_fh.write(line_full + "\n")
                self._text_fh.flush()

    def _event_color(self, event: dict[str, Any]) -> str:
        password = event.get("password")
        if password not in (None, ""):
            return "red"
        if "password" in event:
            return "yellow"
        if event.get("error") or event.get("error_message"):
            return "yellow"
        phase = str(event.get("phase") or "")
        if phase.endswith("_error"):
            return "yellow"
        return "cyan"

    def _field_parts(self, event: dict[str, Any], clip_width: int | None = 92) -> list[str]:
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
            parts.append(f"{alias}={_value_text(value, clip_width=clip_width)}")
            used.add(key)

        for key in sorted(event.keys()):
            if key in base_keys or key in used:
                continue
            alias = _KEY_ALIASES.get(key, key)
            parts.append(f"{alias}={_value_text(event[key], clip_width=clip_width)}")

        return parts

    def _format_event(self, event: dict[str, Any], clip_width: int | None = 92) -> str:
        service = str(event.get("service") or "event")
        remote = str(event.get("remote_addr") or "-")
        timestamp = str(event.get("timestamp") or "")
        short_time = timestamp[11:19] if len(timestamp) >= 19 else timestamp
        tag = _SERVICE_TAGS.get(service, service.upper())
        password = event.get("password")
        if password not in (None, ""):
            level = "CRED"
        elif "password" in event:
            level = "WARN"
        elif event.get("error") or event.get("error_message"):
            level = "WARN"
        else:
            level = "INFO"
        parts = self._field_parts(event, clip_width=clip_width)
        body = " ".join(parts)
        if body:
            return f"[{short_time}] [{level}] [{tag}] {remote} {body}"
        return f"[{short_time}] [{level}] [{tag}] {remote}"
