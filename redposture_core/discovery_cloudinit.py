"""Bounded reader for the legacy cloud-init chpasswd/list literal format.

This is not a YAML loader. Only an explicit #cloud-config document and a
chpasswd: / list: | block bind user:password lines to secret values. Public
authorized keys and unrelated mappings do not become credentials.
"""

from __future__ import annotations

import re
from typing import Any

_USER = re.compile(r"^[ \t]*[A-Za-z_][A-Za-z0-9_.@-]{0,255}:")


class CloudInitPasswords:
    def __init__(self, emit, partial) -> None:
        self.emit, self.partial = emit, partial
        self.active: bool | None = None
        self.head = ""
        self.chpasswd_indent: int | None = None
        self.list_indent: int | None = None
        self.value: Any = None
        self.line_size = 0
        self.trailing_cr = False

    def _part(self, text: str) -> None:
        if self.value is not None:
            self.value.append(text)
            return
        self.line_size += len(text)
        kept = self.head + text[: max(0, 512 - len(self.head))]
        self.head = kept
        if self.list_indent is not None:
            match = _USER.match(kept)
            indent = len(kept) - len(kept.lstrip(" \t"))
            if match is not None and indent > self.list_indent:
                from .discovery_text import _Value

                self.value = _Value(65536)
                # Only the prefix was buffered. The remaining current portion
                # still belongs to the password and must not be truncated.
                previous = self.line_size - len(text)
                start = max(0, match.end() - previous)
                if match.end() <= previous:
                    self.value.append(kept[match.end() : previous])
                self.value.append(text[start:])

    def _end(self) -> None:
        if self.active is None:
            self.active = self.head.strip() == "#cloud-config" if self.head.strip() else None
        elif self.value is not None:
            length = self.value.length
            value = self.value.finish()
            self.value = None
            from .discovery_values import DiskBackedText
            from .secret_detection import _is_secret_sentinel

            placeholder = value.obvious_placeholder if isinstance(value, DiskBackedText) else _is_secret_sentinel(value)
            if length >= 4 and not placeholder:
                self.emit(value)
            elif isinstance(value, DiskBackedText):
                value.close()
        elif self.active:
            stripped = self.head.strip()
            indent = len(self.head) - len(self.head.lstrip(" \t"))
            if stripped and self.list_indent is not None and indent <= self.list_indent:
                self.list_indent = None
            if stripped == "chpasswd:":
                self.chpasswd_indent = indent
            elif self.chpasswd_indent is not None:
                if stripped == "list: |" and indent > self.chpasswd_indent:
                    self.list_indent = indent
                elif stripped and indent <= self.chpasswd_indent:
                    self.chpasswd_indent = None
            if self.list_indent is not None and self.line_size > 512:
                self.partial("unsupported_cloud_init_entry")
        self.head, self.line_size = "", 0

    def feed(self, text: str) -> None:
        if self.active is False:
            return
        if self.trailing_cr:
            text = "\r" + text
            self.trailing_cr = False
        if text.endswith("\r"):
            text = text[:-1]
            self.trailing_cr = True
        parts = text.split("\n")
        for index, part in enumerate(parts):
            final_line = index == len(parts) - 1
            if not final_line and part.endswith("\r"):
                part = part[:-1]
            self._part(part)
            if not final_line:
                self._end()
                if self.active is False:
                    return

    def finish(self) -> None:
        if self.trailing_cr:
            self._part("\r")
            self.trailing_cr = False
        self._end()

    def close(self) -> None:
        if self.value is not None:
            self.value.close()
            self.value = None
