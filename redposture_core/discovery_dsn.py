"""Streaming validation of complete database/storage property carriers."""

from __future__ import annotations

import base64
import binascii
import re
import time
from typing import NamedTuple

from .discovery_values import DiskBackedText

DSN_HEAD = re.compile(
    r"(?i)(?<![\w.])(?:jdbc:sqlserver://|(?:driver|server|host|hostaddr|data source|dsn|"
    r"defaultendpointsprotocol|accountname)\s*=)"
)
_KEYS = frozenset(
    {
        "driver",
        "server",
        "host",
        "hostaddr",
        "datasource",
        "dsn",
        "database",
        "databasename",
        "dbname",
        "uid",
        "user",
        "userid",
        "username",
        "pwd",
        "password",
        "accountname",
        "accountkey",
        "defaultendpointsprotocol",
        "endpointsuffix",
        "blobendpoint",
        "queueendpoint",
        "fileendpoint",
    }
)


class DSNGrammar:
    """Retain only small proof fields; long property values remain in the caller's spool."""

    def __init__(self, *, space: bool = False) -> None:
        self.space = space
        self.state = "key"
        self.key = ""
        self.value = ""
        self.value_length = 0
        self.fields: dict[str, str] = {}
        self.present: set[str] = set()
        self.invalid = False
        self.escaped = False
        self.quote = ""
        self.line_boundary = False

    def _append(self, text: str) -> None:
        self.value_length += len(text)
        if self.key in _KEYS:
            self.value = (self.value + text)[:4096]

    def _finish(self) -> None:
        if self.key in _KEYS:
            self.present.add(self.key)
            # Large passwords are proved nonempty but never copied. Fields
            # needing exact bounded format checks must not accept a prefix.
            self.fields[self.key] = self.value.strip() if self.value_length <= 4096 else "\x00large"
        self.state, self.key, self.value, self.value_length = "key", "", "", 0

    def feed(self, text: str) -> None:
        position = 0
        while position < len(text):
            char = text[position]
            if char in "\r\n" and self.state not in {"brace", "quoted"}:
                self.line_boundary = True
            if self.state == "key":
                if char == "=":
                    self.key = re.sub(r"[\s_-]+", "", self.key).lower()
                    self.state = "start"
                elif char == ";" or (self.space and char.isspace() and not self.key):
                    if self.key.strip():
                        self.invalid = True
                    self.key = ""
                elif len(self.key) < 128:
                    self.key += char
                else:
                    self.invalid = True
            elif self.state == "start":
                if char.isspace():
                    position += 1
                    continue
                if char == "{":
                    self.state = "brace"
                elif char in "\"'":
                    self.quote, self.state = char, "quoted"
                else:
                    self.state = "plain"
                    continue
            elif self.state == "brace":
                if char == "}":
                    self.state = "brace_end"
                else:
                    end = text.find("}", position)
                    end = len(text) if end < 0 else end
                    self._append(text[position:end])
                    position = end
                    continue
            elif self.state == "brace_end":
                if char == "}":
                    self._append("}")
                    self.state = "brace"
                else:
                    self.state = "after"
                    continue
            elif self.state == "quoted":
                if self.escaped:
                    self._append(char)
                    self.escaped = False
                elif char == "\\":
                    self.escaped = True
                elif char == self.quote:
                    self.state = "quote_end"
                else:
                    end = position
                    while end < len(text) and text[end] not in {"\\", self.quote}:
                        end += 1
                    self._append(text[position:end])
                    position = end
                    continue
            elif self.state == "quote_end":
                if char == self.quote and not self.space:
                    self._append(char)
                    self.state = "quoted"
                else:
                    self.state = "after"
                    continue
            elif self.state == "after":
                if char == ";" or (self.space and char.isspace()):
                    self._finish()
                elif not char.isspace():
                    self.invalid = True
            elif self.state == "plain":
                separator = re.search(r"\s" if self.space else ";", text[position:])
                end = position + separator.start() if separator else len(text)
                self._append(text[position:end])
                position = end
                if end < len(text):
                    self._finish()
                    position += 1
                continue
            position += 1

    def finish(self) -> bool:
        if self.state in {"plain", "after", "brace_end", "quote_end", "start"}:
            self._finish()
        elif self.state in {"brace", "quoted"}:
            self.invalid = True
        elif self.key.strip():
            self.invalid = True
        return not self.invalid


class DSNResult(NamedTuple):
    detected: bool
    complete: bool
    placeholder: bool = False


def dsn_carrier(value: str | DiskBackedText, *, deadline: float | None = None) -> DSNResult:
    """Validate one whole property value and distinguish a redacted carrier."""
    prefix = next(value.iter_text_chunks(max_chars=512), "") if isinstance(value, DiskBackedText) else value[:512]
    head = DSN_HEAD.match(prefix.lstrip())
    if head is None:
        return DSNResult(False, True)
    jdbc = prefix.lstrip().lower().startswith("jdbc:sqlserver://")
    libpq = re.match(r"(?i)\s*(?:host|hostaddr)\s*=\s*", prefix)
    delimiter = re.search(r"[\s;]", prefix[libpq.end() :]) if libpq is not None else None
    space = libpq is not None and (delimiter is None or delimiter.group() != ";")
    parser = DSNGrammar(space=space)
    chunks = (
        value.iter_text_chunks()
        if isinstance(value, DiskBackedText)
        else (value[n : n + 65536] for n in range(0, len(value), 65536))
    )
    authority = ""
    prefix_pending = jdbc
    for chunk in chunks:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        if prefix_pending:
            authority += chunk
            if ";" not in authority:
                if len(authority) > 4096:
                    return DSNResult(False, False)
                continue
            server, chunk = authority.split(";", 1)
            if len(server) > 4096:
                return DSNResult(False, False)
            parser.fields["server"] = server.removeprefix("jdbc:sqlserver://")
            authority = ""
            prefix_pending = False
        parser.feed(chunk)
    complete = parser.finish() and not prefix_pending
    if parser.line_boundary:
        # A log with several complete lines is scanned line by line. Errors
        # in a later line must not reinterpret it as one broken DSN.
        return DSNResult(False, True)
    fields = parser.fields
    from .discovery_rules import _looks_placeholder

    password = fields.get("password", fields.get("pwd", ""))
    user = next((fields[key] for key in ("uid", "user", "userid", "username") if fields.get(key)), "")
    endpoint = any(fields.get(key) for key in ("server", "host", "hostaddr", "datasource", "dsn"))
    valid = bool(endpoint and user and password and not _looks_placeholder(password))
    if (
        fields.get("accountname")
        and fields.get("accountkey")
        and any(
            fields.get(key)
            for key in ("defaultendpointsprotocol", "endpointsuffix", "blobendpoint", "queueendpoint", "fileendpoint")
        )
    ):
        try:
            valid = len(base64.b64decode(fields["accountkey"], validate=True)) == 64
        except (ValueError, binascii.Error):
            pass
    placeholder = (
        complete
        and endpoint
        and bool(user)
        and ("password" in fields or "pwd" in fields)
        and _looks_placeholder(password)
    )
    return DSNResult(valid and complete, complete, bool(placeholder))


def dsn_carriers(text: str):
    """Yield complete line carriers; quoted/braced newlines remain inside them."""
    consumed = 0
    for head in DSN_HEAD.finditer(text):
        if head.start() < consumed or text[text.rfind("\n", 0, head.start()) + 1 : head.start()].strip():
            continue
        parser = DSNGrammar()
        position = head.start()
        while True:
            end = text.find("\n", position)
            if end < 0:
                end = len(text)
            parser.feed(text[position:end])
            if end == len(text) or parser.state not in {"brace", "quoted"}:
                break
            parser.feed("\n")
            position = end + 1
        consumed = end
        raw = text[head.start() : end].rstrip("\r")
        result = dsn_carrier(raw)
        if result.detected or result.placeholder:
            yield raw, (head.start(), head.start() + len(raw)), result.detected
