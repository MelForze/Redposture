"""Bounded base64 decoding for explicit API/BSON binary schemas."""

from __future__ import annotations

import base64
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from .discovery_values import DiskBackedText


@contextmanager
def decoded_base64_file(
    value: str | DiskBackedText, check: Callable[[], None]
) -> Iterator[tuple[tempfile.SpooledTemporaryFile[bytes], int]]:
    """Validate a whole encoded value before treating its bytes as a source.

    Callers supply an explicit wire schema. A textual 'base64:' prefix in an
    ordinary user string is not sufficient evidence to invoke this decoder.
    """
    chunks = (
        value.iter_text_chunks()
        if isinstance(value, DiskBackedText)
        else (value[offset : offset + 65536] for offset in range(0, len(value), 65536))
    )
    carry = ""
    padded = False
    size = 0
    with tempfile.SpooledTemporaryFile(max_size=65536) as output:
        for chunk in chunks:
            check()
            if padded and chunk:
                raise ValueError("data after base64 padding")
            carry += chunk
            whole = len(carry) // 4 * 4
            if whole:
                block, carry = carry[:whole], carry[whole:]
                decoded = base64.b64decode(block, validate=True)
                padded = "=" in block
                if padded and carry:
                    raise ValueError("data after base64 padding")
                output.write(decoded)
                size += len(decoded)
        check()
        if carry:
            raise ValueError("incomplete base64 value")
        output.seek(0)
        yield output, size
