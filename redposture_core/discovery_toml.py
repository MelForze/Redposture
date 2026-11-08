"""Incremental TOML 1.0 multiline string literals, with bounded capture.

Only triple-quoted assignments select this grammar. Ordinary quoted values
retain the existing unknown-dialect policy; this reader does not reinterpret
backslashes in SQL, shell or other single-quoted assignment languages.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

_BASIC_RUN = re.compile(r'[^"\\\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+')
_LITERAL_RUN = re.compile(r"[^'\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")
_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


class TOMLMultiline:
    def __init__(self, quote: str, partial: Callable[[str], Any], *, portion: int = 65_536) -> None:
        from .discovery_text import _Value

        self.quote, self.partial = quote, partial
        self.value = _Value(portion)
        self.initial = True
        self.cr = False
        self.run = 0
        self.escape = ""
        self.unicode_digits = ""
        self.continuation = False
        self.continuation_newline = False
        self.done = self.failed = False

    def _invalid(self, reason: str) -> None:
        if not self.failed:
            self.partial(reason)
        self.failed = True
        self.value.close()

    def feed(self, text: str, *, final: bool = False) -> int:
        """Consume through the closing quote run; leave following syntax unread."""
        position = 0
        pattern = _BASIC_RUN if self.quote == '"' else _LITERAL_RUN
        while position < len(text) and not self.done:
            char = text[position]
            if self.run:
                if char == self.quote:
                    self.run += 1
                    position += 1
                    if self.run > 5:
                        self._invalid("invalid_toml_quote_run")
                    continue
                if self.run >= 3:
                    if not self.failed:
                        self.value.append(self.quote * (self.run - 3))
                    self.done = True
                    break
                if not self.failed:
                    self.value.append(self.quote * self.run)
                self.run = 0
            if self.cr:
                self.cr = False
                if char != "\n":
                    self._invalid("invalid_toml_newline")
                else:
                    position += 1
                    if self.continuation:
                        self.continuation_newline = True
                    elif self.initial:
                        self.initial = False
                    elif not self.failed:
                        self.value.append("\n")
                    continue
            if self.escape in {"u", "U"}:
                needed = 4 if self.escape == "u" else 8
                if char not in "0123456789abcdefABCDEF":
                    self._invalid("invalid_toml_unicode_escape")
                    self.escape = ""
                    continue
                self.unicode_digits += char
                position += 1
                if len(self.unicode_digits) == needed:
                    number = int(self.unicode_digits, 16)
                    if number > 0x10FFFF or 0xD800 <= number <= 0xDFFF:
                        self._invalid("invalid_toml_unicode_escape")
                    elif not self.failed:
                        self.value.append(chr(number))
                    self.escape = self.unicode_digits = ""
                continue
            if self.escape == "start":
                self.escape = ""
                if char in _ESCAPES:
                    if not self.failed:
                        self.value.append(_ESCAPES[char])
                    position += 1
                    continue
                if char in "uU":
                    self.escape = char
                    self.unicode_digits = ""
                    position += 1
                    continue
                if char in " \t\r\n":
                    self.continuation = True
                    self.continuation_newline = False
                else:
                    self._invalid("invalid_toml_escape")
            if self.continuation:
                if char in " \t\n":
                    self.continuation_newline |= char == "\n"
                    position += 1
                    continue
                if char == "\r":
                    self.cr = True
                    position += 1
                    continue
                if not self.continuation_newline:
                    self._invalid("invalid_toml_continuation")
                self.continuation = False
            if char == self.quote:
                self.initial = False
                self.run = 1
                position += 1
                continue
            if char == "\r":
                self.cr = True
                position += 1
                continue
            if char == "\n":
                position += 1
                if self.initial:
                    self.initial = False
                elif not self.failed:
                    self.value.append("\n")
                continue
            self.initial = False
            if self.quote == '"' and char == "\\":
                self.escape = "start"
                position += 1
                continue
            run = pattern.match(text, position)
            if run is None:
                self._invalid("invalid_toml_control_character")
                position += 1
            else:
                if not self.failed:
                    self.value.append(run.group())
                position = run.end()
        if final and not self.done:
            if 3 <= self.run <= 5 and not self.cr and not self.escape and not self.continuation:
                if not self.failed:
                    self.value.append(self.quote * (self.run - 3))
                self.done = True
            else:
                self._invalid("unterminated_toml_value")
        return position

    def take(self) -> Any:
        return self.value.finish() if self.done and not self.failed else None

    def close(self) -> None:
        self.value.close()
