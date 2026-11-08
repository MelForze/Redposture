"""Bounded SQL credential literals; unknown dialect never guesses escapes."""

from __future__ import annotations

import re
from typing import Literal

from .discovery_values import DiskBackedText

SQLDialect = Literal["unknown", "standard", "mysql"]
_ACCOUNT = r"(?:'(?:''|\\.|[^'\\])*'|\"(?:\"\"|\\.|[^\"\\])*\"|`(?:``|[^`])*`|[A-Za-z0-9_.$%+-]+)"
SQL_IDENTIFIED_PREFIX = (
    r"(?i)(?<![\w.])(?:CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?|ALTER\s+USER\s+(?:IF\s+EXISTS\s+)?)"
    + _ACCOUNT
    + r"(?:\s*@\s*"
    + _ACCOUNT
    + r")?\s+IDENTIFIED\s+BY\s+"
)
SQL_IDENTIFIED_HEAD = re.compile(SQL_IDENTIFIED_PREFIX + r"([\"'])")
SQL_PASSWORD_HEAD = re.compile(r"(?i)\b(?:WITH\s+)?PASSWORD\s+([\"'])")
SQL_START = re.compile(r"(?i)\b(?:CREATE|ALTER)\s+USER\b")
_EVENT = re.compile(r"[\\\"']")
_MYSQL_ESCAPES = {"0": "\0", "b": "\b", "n": "\n", "r": "\r", "t": "\t", "Z": "\x1a", "%": r"\%", "_": r"\_"}


class SQLLiteral:
    """Consume text after the opening quote, publishing only a confirmed end.

    Standard SQL collapses doubled delimiters. Unknown mode also preserves
    backslash sequences byte for byte, using them only for quote termination.
    MySQL unescaping is available only when the caller explicitly knows it.
    """

    def __init__(self, quote: str, *, portion: int = 65536, dialect: SQLDialect = "unknown") -> None:
        if dialect not in {"unknown", "standard", "mysql"} or quote not in {"'", '"'}:
            raise ValueError("unsupported SQL literal dialect or delimiter")
        from .discovery_text import _Value

        self.value = _Value(portion)
        self.quote = quote
        self.dialect = dialect
        self.escaped = self.closing = self.complete = False
        self.valid = True

    def feed(self, text: str, *, final: bool = False) -> int:
        position = 0
        while position < len(text):
            if self.closing:
                self.closing = False
                if text[position] != self.quote:
                    self.complete = True
                    # A bare identifier glued to the closing delimiter is not
                    # a complete SQL literal (and must not confirm a prefix).
                    self.valid = not (text[position].isalnum() or text[position] in "_$")
                    return position
                self.value.append(self.quote)
                position += 1
                continue
            if self.escaped:
                self.escaped = False
                char = text[position]
                self.value.append(_MYSQL_ESCAPES.get(char, char) if self.dialect == "mysql" else char)
                position += 1
                continue
            event = _EVENT.search(text, position)
            if event is None:
                self.value.append(text[position:])
                position = len(text)
                break
            self.value.append(text[position : event.start()])
            char = event.group()
            position = event.end()
            if char == self.quote:
                self.closing = True
            elif char == "\\" and self.dialect != "standard":
                if self.dialect == "unknown":
                    self.value.append(char)
                self.escaped = True
            else:
                self.value.append(char)
        if final and self.closing:
            self.closing = False
            self.complete = True
        return position

    def take(self) -> str | DiskBackedText | None:
        return self.value.finish() if self.complete and self.valid else None

    def close(self) -> None:
        self.value.close()
