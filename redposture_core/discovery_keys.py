"""Bounded equivalent field hints for an arbitrarily long mapping key."""

from __future__ import annotations

import time
from collections.abc import Iterator

from .discovery_values import DiskBackedText
from .secret_detection import _NON_SECRET_FIELD_RE, _SECRET_KEY_RE, _SECRET_METADATA_SUFFIXES


class _Normalizer:
    def __init__(self) -> None:
        self.pending = self.previous = ""
        self.separator = False

    def feed(self, text: str, *, final: bool = False) -> Iterator[str]:
        text = self.pending + text
        stop = len(text) if final else max(0, len(text) - 1)
        self.pending = text[stop:]
        output: list[str] = []
        for index in range(stop):
            char = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            if "A" <= char <= "Z" and (
                "a" <= self.previous <= "z"
                or "0" <= self.previous <= "9"
                or ("A" <= self.previous <= "Z" and "a" <= following <= "z")
            ):
                output.append("_")
            if char.isspace() or char in ".-":
                if not self.separator:
                    output.append("_")
                self.separator = True
            else:
                self.separator = False
                output.append(char.lower())
            self.previous = char
            if len(output) >= 8192:
                yield "".join(output)
                output.clear()
        if output:
            yield "".join(output)


class _Profile:
    def __init__(self) -> None:
        self.normalizer = _Normalizer()
        self.tail = ""
        self.length = 0
        self.secret = self.excluded = False
        self.tokens: set[str] = set()

    def _accept(self, part: str, final: bool) -> None:
        text = self.tail + part
        at_start = self.length <= len(self.tail)
        for pattern, flag in ((_SECRET_KEY_RE, "secret"), (_NON_SECRET_FIELD_RE, "excluded")):
            for match in pattern.finditer(text):
                if (match.start() or at_start) and (match.end() < len(text) or final):
                    setattr(self, flag, True)
        for token in (
            "client_secret",
            "password",
            "passwd",
            "passphrase",
            "session",
            "cookie",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
        ):
            if token in text:
                self.tokens.add(token)
        self.length += len(part)
        self.tail = text[-128:]

    def feed(self, text: str, *, final: bool = False) -> None:
        for part in self.normalizer.feed(text, final=final):
            self._accept(part, False)
        if final:
            self._accept("", True)

    @property
    def metadata(self) -> bool:
        # Metadata suffixes are bounded and contain no sensitive field token.
        # The prefix may be arbitrarily long; its sensitivity was streamed.
        return self.secret and self.tail.rsplit("_", 1)[-1] in _SECRET_METADATA_SUFFIXES


def disk_key_hint(key: DiskBackedText, deadline: float | None = None) -> str:
    full, tail = _Profile(), _Profile()
    for part in key.iter_text_chunks():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        full.feed(part)
        if "." in part:
            tail = _Profile()
            part = part.rsplit(".", 1)[-1]
        tail.feed(part)
    full.feed("", final=True)
    tail.feed("", final=True)
    if full.excluded or full.metadata:
        # Field suppression examines the entire key; the entropy rule examines
        # only its final dot component. Preserve both decisions separately.
        return "hash" if tail.excluded or tail.metadata else "hash.data"
    if not full.secret:
        return "data"
    if "client_secret" in full.tokens:
        return "client_secret"
    if (
        full.tokens & {"password", "passwd", "passphrase"}
        or full.tail.endswith(("pwd", "_pass"))
        or full.tail == "pass"
    ):
        return "password"
    if full.tokens & {"session", "cookie"} or full.tail == "sid":
        return "session"
    if full.tokens & {"api_key", "apikey"}:
        return "api_key"
    if full.tokens & {"access_token", "refresh_token"}:
        return "access_token"
    return "secret"
