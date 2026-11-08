"""Validation of complete credential carriers without materializing big bodies."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import time

from .discovery_values import DiskBackedText

_BASIC_HEAD = re.compile(r"^Basic[ \t]+", re.I)
_USER = re.compile(r"[A-Za-z0-9_.@\\/+-]{1,256}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def valid_basic_carrier(value: str | DiskBackedText, *, deadline: float | None = None, encoded: bool = False) -> bool:
    first = next(value.iter_text_chunks(max_chars=512), "") if isinstance(value, DiskBackedText) else value[:512]
    head = _BASIC_HEAD.match(first)
    if head is None and not encoded:
        return False
    head_end = head.end() if head is not None and not encoded else 0
    chunks = (
        value.iter_text_chunks()
        if isinstance(value, DiskBackedText)
        else (value[n : n + 65536] for n in range(0, len(value), 65536))
    )
    offset = 0
    carry = ""
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    username = ""
    split = False
    password = False
    started = False
    padded = False
    try:
        for chunk in chunks:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("discover_time")
            part = chunk[max(0, head_end - offset) :] if offset < head_end else chunk
            offset += len(chunk)
            if not started:
                part = part.lstrip(" \t")
                started = bool(part)
            if not part:
                continue
            if padded or re.search(r"[^A-Za-z0-9+/=]", part):
                return False
            carry += part
            size = len(carry) // 4 * 4
            if not size:
                continue
            block, carry = carry[:size], carry[size:]
            raw = base64.b64decode(block, validate=True)
            padded = "=" in block
            text = decoder.decode(raw)
            if _CONTROL.search(text):
                return False
            if not split:
                user, sep, rest = text.partition(":")
                username += user
                if len(username) > 256:
                    return False
                if sep:
                    if _USER.fullmatch(username) is None:
                        return False
                    split = True
                    password = bool(rest)
            else:
                password |= bool(text)
        tail = decoder.decode(b"", final=True)
        return not carry and split and (password or bool(tail)) and not _CONTROL.search(tail)
    except (ValueError, UnicodeError, binascii.Error):
        return False


COOKIE_HEAD = re.compile(r"(?im)(?<![\w-])(?:Set-Cookie|Cookie):[ \t]*")
_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SESSION_NAME = re.compile(
    r"(?i)(?:session(?:id)?|sid|auth_token|access_token|refresh_token|jsessionid|"
    r"connect\.sid|__Host-session|__Secure-session)"
)


def valid_cookie_carrier(value: str | DiskBackedText, *, deadline: float | None = None, body: bool = False) -> bool:
    first = next(value.iter_text_chunks(max_chars=512), "") if isinstance(value, DiskBackedText) else value[:512]
    head = COOKIE_HEAD.match(first)
    if head is None and not body:
        return False
    skip = head.end() if head is not None else 0
    chunks = (
        value.iter_text_chunks()
        if isinstance(value, DiskBackedText)
        else (value[n : n + 65536] for n in range(0, len(value), 65536))
    )
    offset = 0
    pending = ""
    long = False
    proved = False

    def field() -> bool:
        nonlocal proved
        from .discovery_rules import _looks_placeholder

        name, sep, content = pending.strip().partition("=")
        if not name or _COOKIE_NAME.fullmatch(name) is None:
            return False
        if sep and _SESSION_NAME.fullmatch(name) and len(content) >= 8 and not _looks_placeholder(content):
            proved = True
        # Set-Cookie attributes may be flags; Cookie request members need '='.
        return bool(sep) or (head is not None and head.group().lower().startswith("set-cookie:") and not long)

    for chunk in chunks:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        part = chunk[max(0, skip - offset) :] if offset < skip else chunk
        offset += len(chunk)
        if _CONTROL.search(part):
            return False
        for segment in re.split("(;)", part):
            if segment == ";":
                if not field():
                    return False
                pending, long = "", False
            else:
                long |= len(pending) + len(segment) > 4096
                pending = (pending + segment)[:4096]
    return field() and proved
