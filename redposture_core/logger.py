"""Human-readable logger used by server and scanner flows."""

from __future__ import annotations

import os
import threading
from typing import Any

from .utils import utc_now_iso

_COLORS = {
    "blue": "1;94",
    "green": "1;92",
    "orange": "1;38;5;208",
    "red": "1;91",
    "white": "1;97",
    "yellow": "1;93",
    "cyan": "1;96",
}

_SERVICE_TAGS = {
    "postgres": "Postgres",
    "redis": "REDIS",
    "etcd": "ETCD",
    "registry": "REGISTRY",
    "proxmox": "PVE",
    "blackbox": "BLACKBOX",
    "scanner": "TRIGGER",
    "scan": "SCAN",
    "collect": "COLLECT",
}

_CALLBACK_EXPORTER_NAMES = {
    "postgres": "Postgres Exporter",
    "redis": "Redis Exporter",
    "proxmox": "Proxmox Exporter",
    "blackbox": "Blackbox Exporter",
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
        self._trigger_callback_mode = False
        self._trigger_callback_targets: tuple[str, ...] = ()
        self._trigger_seen_signatures: set[tuple[str, ...]] = set()
        self._trigger_deduplicate = True
        self._trigger_callback_stats_total = 0
        self._trigger_callback_stats_by_service: dict[str, int] = {}
        self._trigger_callback_stats_signatures: set[tuple[str, ...]] = set()

    def set_trigger_callback_mode(
        self,
        enabled: bool,
        callback_targets: list[str] | tuple[str, ...] | None = None,
        *,
        deduplicate: bool = True,
    ) -> None:
        with self._lock:
            self._trigger_callback_mode = bool(enabled)
            self._trigger_deduplicate = bool(deduplicate)
            self._trigger_seen_signatures.clear()
            self._trigger_callback_stats_total = 0
            self._trigger_callback_stats_by_service = {}
            self._trigger_callback_stats_signatures.clear()
            if callback_targets is None:
                self._trigger_callback_targets = ()
                return
            normalized = tuple(str(item) for item in callback_targets if str(item).strip())
            self._trigger_callback_targets = tuple(dict.fromkeys(normalized))

    def get_trigger_callback_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total": int(self._trigger_callback_stats_total),
                "by_service": dict(self._trigger_callback_stats_by_service),
            }

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
            self._record_trigger_callback_event(event)
            if self._trigger_callback_mode and self._trigger_deduplicate and self._is_duplicate_trigger_callback_event(event):
                return
            if self._trigger_callback_mode:
                self._emit_trigger_callback_line(event)
            print(_paint(line, color), flush=True)
            if self._text_fh is not None:
                self._text_fh.write(line_full + "\n")
                self._text_fh.flush()

    def _trigger_callback_signature(self, event: dict[str, Any]) -> tuple[str, ...] | None:
        service = str(event.get("service") or "").strip().lower()
        if service not in _CALLBACK_EXPORTER_NAMES:
            return None

        remote = str(event.get("remote_addr") or "-")
        remote_host = remote.rsplit(":", 1)[0] if ":" in remote else remote
        listen_port = str(event.get("listen_port") or "-")

        password = event.get("password")
        if password is None:
            password_token = "<none>"
        elif password == "":
            password_token = "<empty>"
        else:
            password_token = str(password)

        return (
            service,
            remote_host,
            listen_port,
            str(event.get("username") or ""),
            password_token,
            str(event.get("method") or ""),
            str(event.get("path") or ""),
            str(event.get("command") or ""),
            str(event.get("protocol") or ""),
            str(event.get("module") or ""),
        )

    def _record_trigger_callback_event(self, event: dict[str, Any]) -> None:
        if not self._trigger_callback_mode:
            return
        signature = self._trigger_callback_signature(event)
        if signature is None:
            return
        if event.get("error") or event.get("error_message"):
            return
        if str(event.get("method") or "").strip().upper() == "PARSE_ERROR":
            return

        if signature in self._trigger_callback_stats_signatures:
            return
        self._trigger_callback_stats_signatures.add(signature)

        service = signature[0]
        self._trigger_callback_stats_total += 1
        self._trigger_callback_stats_by_service[service] = self._trigger_callback_stats_by_service.get(service, 0) + 1

    def _is_duplicate_trigger_callback_event(self, event: dict[str, Any]) -> bool:
        signature = self._trigger_callback_signature(event)
        if signature is None:
            return False
        if signature in self._trigger_seen_signatures:
            return True
        self._trigger_seen_signatures.add(signature)
        return False

    def _emit_trigger_callback_line(self, event: dict[str, Any]) -> None:
        service = str(event.get("service") or "").strip().lower()
        exporter_name = _CALLBACK_EXPORTER_NAMES.get(service)
        if not exporter_name:
            return

        remote = str(event.get("remote_addr") or "-")
        remote_host = remote.rsplit(":", 1)[0] if ":" in remote else remote
        display_target = remote_host
        listen_port = str(event.get("listen_port") or "-")

        password = event.get("password")
        has_creds = password not in (None, "")
        marker_color = "green"
        suffix = ""
        if has_creds:
            suffix = " " + _paint("(CRED!)", "orange")
        else:
            marker_color = "green"
            suffix = " " + _paint("(SSRF!)", "orange")

        target_segment = "\t" + _clip(display_target, 64) + "\t" + _clip(listen_port, 16) + "\t"
        line = (
            f"{_paint('TRIGGER ', 'blue')}"
            f"{_paint(target_segment, 'white')}"
            f" {_paint('[+]', marker_color)} "
            f"{_paint(exporter_name, 'white')}{suffix}"
        )
        print(line, flush=True)

    def _is_trigger_ssrf_event(self, event: dict[str, Any]) -> bool:
        if not self._trigger_callback_mode:
            return False
        service = str(event.get("service") or "").strip().lower()
        if service not in _CALLBACK_EXPORTER_NAMES:
            return False
        if event.get("error") or event.get("error_message"):
            return False
        return event.get("password") in (None, "")

    def _event_color(self, event: dict[str, Any]) -> str:
        password = event.get("password")
        if password not in (None, ""):
            return "orange"
        if self._is_trigger_ssrf_event(event):
            return "orange"
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
        tag = self._event_tag(event)
        password = event.get("password")
        if password not in (None, ""):
            level = "CRED"
        elif self._is_trigger_ssrf_event(event):
            level = "SSRF"
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

    def _event_tag(self, event: dict[str, Any]) -> str:
        service = str(event.get("service") or "event")
        if service != "scanner":
            return _SERVICE_TAGS.get(service, service.upper())

        phase = str(event.get("phase") or "").strip().lower()
        if phase == "detected" or phase == "not_found" or phase.startswith("detect"):
            return "SCAN"
        return "TRIGGER"
