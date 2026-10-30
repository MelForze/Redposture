"""Validation and request-scoped overrides for operator supplied HTTP headers."""

from __future__ import annotations

import argparse
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_LOCK = threading.RLock()
_ACTIVE_HEADERS: tuple[tuple[str, str], ...] = ()


def parse_http_header(value: str) -> tuple[str, str]:
    """Parse one ``Name: value`` CLI option without accepting header injection."""

    name, separator, raw_value = value.partition(":")
    if not separator or not _HEADER_NAME.fullmatch(name):
        raise argparse.ArgumentTypeError("header must be in 'Name: value' form with a valid HTTP name")
    field_value = raw_value.strip(" \t")
    if any(ord(char) < 32 or ord(char) == 127 for char in field_value):
        raise argparse.ArgumentTypeError("header value contains a control character")
    try:
        field_value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("header value must be Latin-1 encodable") from exc
    return name, field_value


@contextmanager
def custom_http_headers(values: Sequence[tuple[str, str]] | None) -> Iterator[None]:
    """Install CLI headers for the lifetime of one audit command, including workers."""

    global _ACTIVE_HEADERS
    with _LOCK:
        previous = _ACTIVE_HEADERS
        _ACTIVE_HEADERS = tuple(values or ())
    try:
        yield
    finally:
        with _LOCK:
            _ACTIVE_HEADERS = previous


def merge_custom_http_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Apply operator headers last, with case-insensitive name replacement."""

    result = {str(name): str(value) for name, value in (headers or {}).items()}
    for name, value in _ACTIVE_HEADERS:
        for existing in tuple(result):
            if existing.lower() == name.lower():
                del result[existing]
        result[name] = value
    return result


__all__ = ["custom_http_headers", "merge_custom_http_headers", "parse_http_header"]
