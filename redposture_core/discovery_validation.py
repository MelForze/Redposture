"""Bounded product-neutral validation of complete discovery values."""

from __future__ import annotations

import base64
import math
import re
import time
from array import array
from collections import Counter
from typing import Any

from .discovery_encoded import decode_disk_base64_utf8
from .discovery_text import _Value
from .discovery_values import DiskBackedText
from .json_stream import JSONPath, JSONScalarStream

_URLSAFE = re.compile(r"[A-Za-z0-9_-]*")


def _check(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("max_seconds")


class _JSONPart:
    def __init__(self) -> None:
        self.length = 0
        self.pending = ""
        self.failed = False
        self.string_fields: set[str] = set()
        self.parser = JSONScalarStream(self._string, on_primitive=self._primitive, on_container=self._container)

    def _string(self, path: JSONPath, _text: str, final: bool) -> None:
        if final and path in {("alg",), ("enc",)}:
            self.string_fields.add(str(path[0]))

    def _primitive(self, item: tuple[JSONPath, Any]) -> None:
        path, _value = item
        if path in {("alg",), ("enc",)}:
            self.string_fields.discard(str(path[0]))

    def _container(self, path: JSONPath, _kind: str) -> None:
        if path in {("alg",), ("enc",)}:
            self.string_fields.discard(str(path[0]))

    def feed(self, part: str) -> None:
        self.length += len(part)
        if self.failed:
            return
        try:
            self.pending += part
            end = len(self.pending) // 4 * 4
            if end:
                self.parser.feed(base64.b64decode(self.pending[:end], altchars=b"-_", validate=True))
                self.pending = self.pending[end:]
        except (ValueError, UnicodeError):
            self.failed = True
            self.pending = ""

    def finish(self) -> bool:
        if self.failed:
            return False
        try:
            if self.pending:
                self.parser.feed(
                    base64.b64decode(self.pending + "=" * (-len(self.pending) % 4), altchars=b"-_", validate=True)
                )
            self.parser.finish()
            return self.parser.root_kind == "object"
        except (ValueError, UnicodeError):
            return False


def validated_disk_jose(value: DiskBackedText, *, deadline: float | None = None) -> str | None:
    """Apply Elastic's JWT/JWE structure checks without decoding a whole payload."""
    lengths = [0]
    header, payload = _JSONPart(), _JSONPart()
    for chunk in value.iter_text_chunks():
        _check(deadline)
        pieces = chunk.split(".")
        for offset, part in enumerate(pieces):
            if offset:
                lengths.append(0)
                if len(lengths) > 5:
                    return None
            if _URLSAFE.fullmatch(part) is None:
                return None
            index = len(lengths) - 1
            lengths[index] += len(part)
            if index == 0:
                header.feed(part)
            elif index == 1:
                payload.feed(part)
    if not header.finish() or "alg" not in header.string_fields:
        return None
    if len(lengths) == 3 and min(lengths) >= 8 and payload.finish():
        return "jwt"
    if len(lengths) == 5 and "enc" in header.string_fields and min(lengths[i] for i in (0, 2, 3, 4)) >= 8:
        return "jwe"
    return None


def disk_entropy(value: DiskBackedText, *, deadline: float | None = None) -> tuple[float, int]:
    """Exact stripped Unicode evidence with fixed <9 MB histogram storage."""
    counts = array("Q", [0]) * 0x110000
    length = 0
    classes = [False] * 4
    started = False
    pending: Counter[str] = Counter()
    for chunk in value.iter_text_chunks():
        _check(deadline)
        if not started:
            chunk = chunk.lstrip()
            started = bool(chunk)
        body = chunk.rstrip()
        if body:
            for character, count in pending.items():
                counts[ord(character)] += count
                length += count
            if pending:
                classes[3] = True
                pending.clear()
        length += len(body)
        for character, count in Counter(body).items():
            counts[ord(character)] += count
        for index, pattern in enumerate((r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")):
            classes[index] |= re.search(pattern, body) is not None
        pending.update(chunk[len(body) :])
    entropy = -sum((count / length) * math.log2(count / length) for count in counts if count) if length else 0.0
    return entropy, sum(classes)


def disk_basic_password(value: DiskBackedText, *, deadline: float | None = None) -> str | DiskBackedText | None:
    decoded = decode_disk_base64_utf8(value, deadline=deadline)
    if decoded is None:
        return None
    username = ""
    seen_colon = False
    password = _Value(65_536)
    try:
        for part in decoded.iter_text_chunks():
            _check(deadline)
            if "\r" in part or "\n" in part:
                return None
            if not seen_colon:
                before, separator, after = part.partition(":")
                username += before
                if len(username) > 256:
                    return None
                if not separator:
                    continue
                if re.fullmatch(r"[A-Za-z0-9_.@\\/+-]{1,256}", username) is None:
                    return None
                seen_colon = True
                part = after
            password.append(part)
        return password.finish() if seen_colon and password.length else None
    finally:
        decoded.close()
        password.close()
