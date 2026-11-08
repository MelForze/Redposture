"""Bounded CSV cells with an explicitly sensitive header, without row truncation.

Auto-detection accepts identifier-like headers and at least one sensitive
column. Other text stays on the ordinary text reader. Quoting follows RFC4180:
double quotes escape themselves; backslashes are ordinary characters.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .discovery_values import DiskBackedText
from .secret_fields import is_secret_field_name

_BOUNDARY = re.compile('[,"\r\n]')
_HEADER = re.compile(r"[A-Za-z0-9_. -]*\Z")


@dataclass(frozen=True)
class CSVCell:
    row: int
    column: int
    name: str | DiskBackedText
    value: str | DiskBackedText


class CSVSecretStream:
    def __init__(self, emit: Callable[[CSVCell], Any], partial: Callable[[str], Any], *, portion: int) -> None:
        from .discovery_text import _Value

        self.emit, self.partial, self.portion = emit, partial, portion
        self.cell = _Value(portion)
        self.headers: Any = []
        self.header_bytes = 0
        self.sensitive = False
        self.row = self.column = 0
        self.mode = "start"
        self.active = self.disabled = self.failed = self.skip_lf = False
        self.dirty = False

    def _append(self, part: str) -> None:
        if self.row == 0 and _HEADER.fullmatch(part) is None:
            self.disabled = True
            self.close()
            return
        self.cell.append(part)

    def _field(self) -> None:
        from .discovery_keys import disk_key_hint
        from .discovery_spool import SpoolingValues
        from .discovery_text import _Value

        value = self.cell.finish()
        self.cell = _Value(self.portion)
        if self.row == 0:
            hint = disk_key_hint(value) if isinstance(value, DiskBackedText) else value
            self.sensitive |= is_secret_field_name(hint)
            self.header_bytes += value.byte_length if isinstance(value, DiskBackedText) else len(value.encode("utf-8"))
            if type(self.headers) is list and (self.header_bytes > 65_536 or len(self.headers) >= 1024):
                headers = SpoolingValues()
                headers.extend(self.headers)
                self.headers = headers
            self.headers.append(value)
        else:
            name = self.headers[self.column] if self.column < len(self.headers) else f"column_{self.column}"
            self.emit(CSVCell(self.row, self.column, name, value))
        self.column += 1
        self.mode = "start"

    def _record(self) -> None:
        self._field()
        if self.row == 0:
            if not self.sensitive or self.column < 2:
                self.disabled = True
                self.close()
                return
            finish = getattr(self.headers, "finish", None)
            if finish is not None:
                finish()
            self.active = True
        elif self.column != len(self.headers):
            self.partial("csv_column_count")
        self.row += 1
        self.column = 0
        self.dirty = False

    def _invalid(self) -> None:
        if self.active:
            self.partial("invalid_csv_quote")
            self.failed = True
        else:
            self.disabled = True
        self.close()

    def feed(self, text: str) -> None:
        if self.disabled or self.failed:
            return
        position = 0
        while position < len(text):
            if self.skip_lf:
                self.skip_lf = False
                if text[position] == "\n":
                    position += 1
                    continue
            match = _BOUNDARY.search(text, position)
            end = match.start() if match is not None else len(text)
            if end > position:
                if self.mode == "after_quote":
                    self._invalid()
                    return
                self._append(text[position:end])
                if self.disabled:
                    return
                self.dirty = True
                if self.mode == "start":
                    self.mode = "unquoted"
            if match is None:
                return
            char = match.group()
            position = match.end()
            self.dirty = True
            if self.mode == "quoted":
                if char == '"':
                    self.mode = "after_quote"
                else:
                    self._append(char)
            elif char == '"':
                if self.mode == "after_quote":
                    self._append('"')
                    self.mode = "quoted"
                elif self.mode == "start":
                    self.mode = "quoted"
                else:
                    self._invalid()
                    return
            elif char == ",":
                self._field()
            else:
                self._record()
                self.skip_lf = char == "\r"
            if self.disabled or self.failed:
                return

    def finish(self) -> None:
        if self.disabled or self.failed:
            return
        if self.mode == "quoted":
            if self.active:
                self.partial("unterminated_csv_value")
            self.close()
        elif self.dirty:
            self._record()

    def close(self) -> None:
        self.cell.close()
        self.headers = []
