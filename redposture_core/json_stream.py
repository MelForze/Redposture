"""Bounded incremental decoding of a single JSON string field."""

from __future__ import annotations

import codecs
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .discovery_values import DiskBackedText


class DiskJSONKey(DiskBackedText):
    """A completed JSON key with stable identity across parser passes."""

    def __hash__(self) -> int:
        return hash((self.byte_length, self.digest))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DiskJSONKey):
            return NotImplemented
        return self.byte_length == other.byte_length and self.digest == other.digest


JSONPath = tuple[str | DiskBackedText | int, ...]


@dataclass
class _Frame:
    kind: str
    path: JSONPath
    state: str
    key: str | DiskBackedText | None = None
    index: int = 0


class JSONScalarStream:
    """Decode arbitrary nested JSON and emit scalar string fragments."""

    _ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
    _STRING_STOP = re.compile(r'["\\\x00-\x1f]')

    def __init__(
        self,
        on_string: Callable[[JSONPath, str, bool], None],
        *,
        on_primitive: Callable[[tuple[JSONPath, Any]], None] | None = None,
        on_container: Callable[[JSONPath, str], None] | None = None,
        on_container_end: Callable[[JSONPath, str], None] | None = None,
        deadline: float | None = None,
    ) -> None:
        self.on_string = on_string
        self.on_primitive = on_primitive
        self.on_container = on_container
        self.on_container_end = on_container_end
        self.deadline = deadline
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.stack: list[_Frame] = []
        self.root_state = "value"
        self.root_kind: str | None = None
        self.string_mode: str | None = None
        self.string_state = "value"
        self.string_parts: list[str] = []
        self._string_chars = 0
        self._key: DiskJSONKey | None = None
        self.string_path: JSONPath = ()
        self.hex_digits = ""
        self.high_surrogate: int | None = None
        self.literal: str | None = None
        self.literal_index = 0
        self.literal_path: JSONPath = ()
        self.number_state: str | None = None
        self.number_path: JSONPath = ()
        self.number_chars: list[str] = []

    def _path(self) -> JSONPath:
        if not self.stack:
            return ()
        frame = self.stack[-1]
        if frame.kind == "object":
            if frame.key is None:
                raise ValueError("object value has no key")
            return (*frame.path, frame.key)
        return (*frame.path, frame.index)

    def _complete_value(self) -> None:
        if not self.stack:
            self.root_state = "done"
            return
        frame = self.stack[-1]
        if frame.kind == "object":
            if frame.state != "value":
                raise ValueError("unexpected object value")
            frame.state = "comma_or_end"
            frame.key = None
        else:
            if frame.state not in {"value_or_end", "value_required"}:
                raise ValueError("unexpected array value")
            frame.state = "comma_or_end"
            frame.index += 1

    def _start_value(self, char: str) -> None:
        if not self.stack and self.root_kind is None:
            self.root_kind = "object" if char == "{" else "array" if char == "[" else "scalar"
        if char in "{[":
            if len(self.stack) >= 128:
                raise ValueError("JSON nesting limit")
            path = self._path()
            if self.on_container is not None:
                self.on_container(path, "object" if char == "{" else "array")
            self.stack.append(
                _Frame("object" if char == "{" else "array", path, "key_or_end" if char == "{" else "value_or_end")
            )
        elif char == '"':
            self.string_mode = "value"
            self.string_state = "value"
            self.string_path = self._path()
            self.string_parts = []
            self._string_chars = 0
        elif char in "tfn":
            self.literal = {"t": "true", "f": "false", "n": "null"}[char]
            self.literal_index = 1
            self.literal_path = self._path()
        elif char == "-":
            self.number_state = "sign"
            self.number_path = self._path()
            self.number_chars = [char]
        elif char == "0":
            self.number_state = "zero"
            self.number_path = self._path()
            self.number_chars = [char]
        elif char in "123456789":
            self.number_state = "int"
            self.number_path = self._path()
            self.number_chars = [char]
        else:
            raise ValueError("invalid JSON value")

    def _append_string(self, text: str) -> None:
        offset = 0
        while offset < len(text):
            # Exactly 4096-character keys stay inline. Their next character
            # starts the disk key, matching the character-stepped decoder.
            limit = 4097 if self.string_mode == "key" and self._key is None else 4096
            end = min(len(text), offset + limit - self._string_chars)
            part = text[offset:end]
            self.string_parts.append(part)
            self._string_chars += len(part)
            offset = end
            if self._string_chars == limit:
                value = "".join(self.string_parts)
                if self.string_mode == "key":
                    if self._key is None:
                        self._key = DiskJSONKey()
                    self._key.append_text(value)
                else:
                    self.on_string(self.string_path, value, False)
                self.string_parts.clear()
                self._string_chars = 0

    def _finish_string(self) -> None:
        if self.string_mode == "key":
            frame = self.stack[-1]
            if self._key is not None:
                self._key.append_text("".join(self.string_parts))
                self._key.finish()
                frame.key = self._key
                self._key = None
            else:
                frame.key = "".join(self.string_parts)
            frame.state = "colon"
        else:
            self.on_string(self.string_path, "".join(self.string_parts), True)
            self._complete_value()
        self.string_mode = None
        self.string_parts.clear()
        self._string_chars = 0
        self.string_path = ()

    def _string_character(self, char: str) -> None:
        if self.string_state == "value":
            if char == '"':
                self._finish_string()
            elif char == "\\":
                self.string_state = "escape"
            elif ord(char) < 32:
                raise ValueError("unescaped JSON control character")
            else:
                self._append_string(char)
        elif self.string_state == "escape":
            if char == "u":
                self.hex_digits = ""
                self.string_state = "unicode"
            elif char in self._ESCAPES:
                self._append_string(self._ESCAPES[char])
                self.string_state = "value"
            else:
                raise ValueError("invalid JSON escape")
        elif self.string_state in {"unicode", "low_hex"}:
            if char not in "0123456789abcdefABCDEF":
                raise ValueError("invalid JSON unicode escape")
            self.hex_digits += char
            if len(self.hex_digits) == 4:
                codepoint = int(self.hex_digits, 16)
                if self.string_state == "unicode" and 0xD800 <= codepoint <= 0xDBFF:
                    self.high_surrogate = codepoint
                    self.string_state = "low_slash"
                elif (
                    self.string_state == "low_hex" and self.high_surrogate is not None and 0xDC00 <= codepoint <= 0xDFFF
                ):
                    self._append_string(chr(0x10000 + (self.high_surrogate - 0xD800) * 0x400 + codepoint - 0xDC00))
                    self.high_surrogate = None
                    self.string_state = "value"
                elif self.string_state == "unicode" and not 0xDC00 <= codepoint <= 0xDFFF:
                    self._append_string(chr(codepoint))
                    self.string_state = "value"
                else:
                    raise ValueError("invalid JSON surrogate pair")
        elif self.string_state == "low_slash":
            if char != "\\":
                raise ValueError("invalid JSON surrogate pair")
            self.string_state = "low_u"
        elif self.string_state == "low_u":
            if char != "u":
                raise ValueError("invalid JSON surrogate pair")
            self.hex_digits = ""
            self.string_state = "low_hex"

    def _number_character(self, char: str) -> bool:
        state = self.number_state
        if state == "sign" and char in "0123456789":
            self.number_state = "zero" if char == "0" else "int"
        elif state == "int" and char in "0123456789":
            pass
        elif state in {"zero", "int"} and char == ".":
            self.number_state = "dot"
        elif state == "dot" and char in "0123456789":
            self.number_state = "frac"
        elif state == "frac" and char in "0123456789":
            pass
        elif state in {"zero", "int", "frac"} and char in "eE":
            self.number_state = "exp"
        elif state == "exp" and char in "+-":
            self.number_state = "exp_sign"
        elif state in {"exp", "exp_sign"} and char in "0123456789":
            self.number_state = "exp_int"
        elif state == "exp_int" and char in "0123456789":
            pass
        elif state in {"zero", "int", "frac", "exp_int"} and char in " \t\r\n,]}":
            self._finish_number()
            return False
        else:
            raise ValueError("invalid JSON number")
        self.number_chars.append(char)
        if len(self.number_chars) > 4096:
            raise ValueError("JSON number length limit")
        return True

    def _finish_number(self) -> None:
        if self.on_primitive is not None:
            self.on_primitive((self.number_path, json.loads("".join(self.number_chars))))
        self.number_state = None
        self.number_chars.clear()
        self._complete_value()

    def _close_container(self) -> None:
        frame = self.stack.pop()
        if self.on_container_end is not None:
            self.on_container_end(frame.path, frame.kind)
        self._complete_value()

    def _character(self, char: str) -> None:
        if self.string_mode is not None:
            self._string_character(char)
            return
        if self.literal is not None:
            if char != self.literal[self.literal_index]:
                raise ValueError("invalid JSON literal")
            self.literal_index += 1
            if self.literal_index == len(self.literal):
                if self.on_primitive is not None:
                    self.on_primitive((self.literal_path, {"true": True, "false": False, "null": None}[self.literal]))
                self.literal = None
                self._complete_value()
            return
        if self.number_state is not None and self._number_character(char):
            return
        if not self.stack:
            if self.root_state == "done":
                if char not in " \t\r\n":
                    raise ValueError("trailing JSON data")
            elif char not in " \t\r\n":
                self._start_value(char)
            return
        frame = self.stack[-1]
        if char in " \t\r\n":
            return
        if frame.kind == "object":
            if frame.state in {"key_or_end", "key_required"}:
                if char == '"':
                    self.string_mode = "key"
                    self.string_state = "value"
                    self.string_parts = []
                    self._string_chars = 0
                elif char == "}" and frame.state == "key_or_end":
                    self._close_container()
                else:
                    raise ValueError("invalid JSON object key")
            elif frame.state == "colon":
                if char != ":":
                    raise ValueError("invalid JSON object separator")
                frame.state = "value"
            elif frame.state == "value":
                self._start_value(char)
            elif frame.state == "comma_or_end":
                if char == ",":
                    frame.state = "key_required"
                elif char == "}":
                    self._close_container()
                else:
                    raise ValueError("invalid JSON object delimiter")
        elif frame.state in {"value_or_end", "value_required"}:
            if char == "]" and frame.state == "value_or_end":
                self._close_container()
            else:
                self._start_value(char)
        elif frame.state == "comma_or_end":
            if char == ",":
                frame.state = "value_required"
            elif char == "]":
                self._close_container()
            else:
                raise ValueError("invalid JSON array delimiter")

    def feed(self, chunk: bytes) -> None:
        try:
            text = self.decoder.decode(chunk)
            index, next_check = 0, 0
            while index < len(text):
                if index == next_check:
                    if self.deadline is not None and time.monotonic() >= self.deadline:
                        raise TimeoutError("discover_time")
                    next_check += 4096
                if self.string_mode is not None and self.string_state == "value":
                    # Searching and slicing stop at the next deadline check.
                    # No complete long run or decoded key is copied into RAM.
                    end = min(len(text), next_check)
                    stop = self._STRING_STOP.search(text, index, end)
                    run_end = stop.start() if stop is not None else end
                    if run_end > index:
                        self._append_string(text[index:run_end])
                        index = run_end
                        continue
                self._character(text[index])
                index += 1
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """Release an unfinished key; completed keys belong to their consumers."""
        if self._key is not None:
            self._key.close()
            self._key = None
        self.string_parts.clear()
        self._string_chars = 0

    def finish(self) -> None:
        for char in self.decoder.decode(b"", final=True):
            self._character(char)
        if self.number_state in {"zero", "int", "frac", "exp_int"} and not self.stack:
            self._finish_number()
        if self.root_state != "done" or self.stack or self.string_mode is not None or self.literal is not None:
            raise ValueError("incomplete JSON response")


class SingleStringFieldStream:
    """Decode a one-field JSON object without materializing its string value."""

    def __init__(
        self, field: str, on_text: Callable[[str], None], *, on_complete: Callable[[], None] | None = None
    ) -> None:
        self.on_text = on_text
        self.on_complete = on_complete
        self.expected_key = json.dumps(field, ensure_ascii=True)
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.state = "start"
        self.key_position = 0
        self.hex_digits = ""
        self.high_surrogate: int | None = None
        self.text: list[str] = []

    def _flush(self) -> None:
        if self.text:
            self.on_text("".join(self.text))
            self.text.clear()

    def _emit(self, char: str) -> None:
        self.text.append(char)
        if char == "\n" or len(self.text) >= 4096:
            self._flush()

    def _character(self, char: str) -> None:
        if self.state == "start":
            if char.isspace():
                return
            if char != "{":
                raise ValueError("response is not a JSON object")
            self.state = "key"
        elif self.state == "key":
            if self.key_position == 0 and char.isspace():
                return
            if char != self.expected_key[self.key_position]:
                raise ValueError("unsupported JSON field")
            self.key_position += 1
            if self.key_position == len(self.expected_key):
                self.state = "colon"
        elif self.state == "colon":
            if char.isspace():
                return
            if char != ":":
                raise ValueError("invalid JSON separator")
            self.state = "value_start"
        elif self.state == "value_start":
            if char.isspace():
                return
            if char != '"':
                raise ValueError("JSON field is not a string")
            self.state = "value"
        elif self.state == "value":
            if char == '"':
                self._flush()
                self.state = "close"
                if self.on_complete is not None:
                    self.on_complete()
            elif char == "\\":
                self.state = "escape"
            elif ord(char) < 32:
                raise ValueError("unescaped control character in JSON string")
            else:
                self._emit(char)
        elif self.state == "escape":
            escaped = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
            if char == "u":
                self.hex_digits = ""
                self.state = "unicode"
            elif char in escaped:
                self._emit(escaped[char])
                self.state = "value"
            else:
                raise ValueError("invalid JSON escape")
        elif self.state in {"unicode", "low_hex"}:
            if char not in "0123456789abcdefABCDEF":
                raise ValueError("invalid JSON unicode escape")
            self.hex_digits += char
            if len(self.hex_digits) == 4:
                codepoint = int(self.hex_digits, 16)
                if self.state == "unicode" and 0xD800 <= codepoint <= 0xDBFF:
                    self.high_surrogate = codepoint
                    self.state = "low_slash"
                elif self.state == "low_hex" and self.high_surrogate is not None and 0xDC00 <= codepoint <= 0xDFFF:
                    combined = 0x10000 + (self.high_surrogate - 0xD800) * 0x400 + (codepoint - 0xDC00)
                    self._emit(chr(combined))
                    self.high_surrogate = None
                    self.state = "value"
                elif self.state == "unicode" and not 0xDC00 <= codepoint <= 0xDFFF:
                    self._emit(chr(codepoint))
                    self.state = "value"
                else:
                    raise ValueError("invalid JSON surrogate pair")
        elif self.state == "low_slash":
            if char != "\\":
                raise ValueError("invalid JSON surrogate pair")
            self.state = "low_u"
        elif self.state == "low_u":
            if char != "u":
                raise ValueError("invalid JSON surrogate pair")
            self.hex_digits = ""
            self.state = "low_hex"
        elif self.state == "close":
            if char.isspace():
                return
            if char != "}":
                raise ValueError("unsupported JSON shape")
            self.state = "done"
        elif self.state == "done" and not char.isspace():
            raise ValueError("trailing JSON data")

    def feed(self, chunk: bytes) -> None:
        for char in self.decoder.decode(chunk):
            self._character(char)
        # Downstream readers own lexical completion (a quote, PEM footer,
        # XML close tag). Do not strand a completed finding in this decoder's
        # small buffer until an unrelated next response chunk arrives.
        self._flush()

    def finish(self) -> None:
        for char in self.decoder.decode(b"", final=True):
            self._character(char)
        if self.state != "done":
            raise ValueError("incomplete JSON response")
        self._flush()
