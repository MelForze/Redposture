"""Validate full credential-bearing URIs with bounded parsing state."""

from __future__ import annotations

import re
import time
import urllib.parse

from .discovery_values import DiskBackedText

_AUTHORITY_END = re.compile(r"[/#?]")
_FORBIDDEN = re.compile(r"[\s\"']")


# Recognition reads the whole carrier in bounded pieces. Values themselves keep
# their original spelling; decoding components must never replace the carrier.
_CARRIER_HEAD = re.compile(r"^(?:jdbc:)?([A-Za-z][A-Za-z0-9+.-]*)://", re.I)
_URI_QUERY_KEYS = frozenset(
    {
        "sig",
        "sv",
        "sp",
        "se",
        "si",
        "sr",
        "ss",
        "srt",
        "user",
        "username",
        "password",
        "pwd",
        "x-amz-algorithm",
        "x-amz-credential",
        "x-amz-date",
        "x-amz-expires",
        "x-amz-signedheaders",
        "x-amz-signature",
        "x-amz-security-token",
    }
)


class _QueryFields:
    def __init__(self) -> None:
        self.fields: dict[str, str] = {}
        self.key = ""
        self.value = ""
        self.in_value = False
        self.known = True

    def feed(self, text: str, *, final: bool = False) -> None:
        for piece in re.split("([&])", text):
            if piece == "&":
                self._finish()
                continue
            if not self.in_value:
                key, sep, rest = piece.partition("=")
                self.key = (self.key + key)[:128]
                if sep:
                    self.in_value = True
                    self.key = urllib.parse.unquote(self.key).lower()
                    self.known = self.key in _URI_QUERY_KEYS
                    piece = rest
                else:
                    continue
            if self.known:
                self.value = (self.value + piece)[:4096]
        if final:
            self._finish()

    def _finish(self) -> None:
        if self.known and self.in_value:
            self.fields[self.key] = urllib.parse.unquote(self.value)
        self.key = self.value = ""
        self.in_value = False
        self.known = True


def uri_carrier_kind(value: str | DiskBackedText, *, deadline: float | None = None) -> str | None:
    """Validate credential-bearing authority/query without retaining big fields."""
    import base64
    import binascii

    chunks = (
        value.iter_text_chunks()
        if isinstance(value, DiskBackedText)
        else (value[n : n + 65536] for n in range(0, len(value), 65536))
    )
    first = next(iter(value.iter_text_chunks(max_chars=512)), "") if isinstance(value, DiskBackedText) else value[:512]
    head = _CARRIER_HEAD.match(first)
    if head is None:
        return None
    scheme = head.group(1).lower()
    jdbc = first.lower().startswith("jdbc:")
    position = 0
    colon = at = -1
    host = ""
    host_length = 0
    host_brackets = False
    authority = True
    query = False
    fragment = False
    fields = _QueryFields()
    for chunk in chunks:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        if _FORBIDDEN.search(chunk):
            return None
        part = chunk[max(0, head.end() - position) :] if position < head.end() else chunk
        start = max(position, head.end())
        if authority:
            boundary = _AUTHORITY_END.search(part)
            auth = part if boundary is None else part[: boundary.start()]
            if colon < 0 and ":" in auth:
                colon = start + auth.index(":")
            if "@" in auth:
                index = auth.rindex("@")
                at = start + index
                host = auth[index + 1 :]
                host_length = len(host)
                host_brackets = "[" in host or "]" in host
            else:
                host_length += len(auth)
                host_brackets |= "[" in auth or "]" in auth
                host = (host + auth)[-4097:]
            if boundary is not None:
                authority = False
                part = part[boundary.start() :]
            else:
                part = ""
        if not authority and not fragment:
            if not query:
                marker = re.search("[?#]", part)
                if marker is not None:
                    fragment = marker.group() == "#"
                    query = marker.group() == "?"
                    part = part[marker.end() :]
                else:
                    part = ""
            if query:
                part, mark, _tail = part.partition("#")
                fields.feed(part)
                fragment = bool(mark)
                if fragment:
                    fields.feed("", final=True)
                    query = False
        position += len(chunk)
    fields.feed("", final=True)
    if not host_length:
        return None
    try:
        if host_length <= 4096:
            if not urllib.parse.urlsplit("//" + host).hostname:
                return None
        elif host_brackets:
            return None
    except ValueError:
        return None
    if at >= head.end() and head.end() <= colon < at - 1:
        return "connection_string"
    params = fields.fields
    if (
        "sv" in params
        and "sig" in params
        and ("si" in params or {"sp", "se"} <= params.keys())
        and ("sr" in params or {"ss", "srt"} <= params.keys())
    ):
        try:
            if len(base64.b64decode(params["sig"], validate=True)) == 32:
                return "signed_url"
        except (ValueError, binascii.Error):
            pass
    if (
        params.get("x-amz-algorithm") == "AWS4-HMAC-SHA256"
        and re.fullmatch(
            r"(?:AKIA|ASIA)[A-Z0-9]{16}/\d{8}/[^/]+/[^/]+/aws4_request", params.get("x-amz-credential", "")
        )
        and re.fullmatch(r"\d{8}T\d{6}Z", params.get("x-amz-date", ""))
        and re.fullmatch(r"[0-9a-fA-F]{64}", params.get("x-amz-signature", ""))
        and params.get("x-amz-expires", "").isdigit()
        and 0 < int(params["x-amz-expires"]) <= 604800
        and params.get("x-amz-signedheaders")
    ):
        return "signed_url"
    if (
        jdbc or scheme in {"postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "clickhouse"}
    ) and (params.get("password") or params.get("pwd")):
        return "connection_string"
    return None
