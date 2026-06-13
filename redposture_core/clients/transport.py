"""Shared TCP transport helpers used by audit clients and modules.

These consolidate the framed-read primitive and connection-error classification
that were previously copy-pasted across many modules. The classifiers use a
**superset** match (substring + common errno spellings) so they work both on
raw OS error text (`[Errno 61] Connection refused`) and on the already-normalized
text some modules produce (`connection refused (...)`).
"""

from __future__ import annotations

import socket
from typing import Any


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes, raising on premature EOF."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def is_connection_refused(value: Any) -> bool:
    """True when ``value`` looks like a TCP connection-refused error."""
    text = str(value or "").strip().lower()
    return bool(text) and (
        "connection refused" in text or "[errno 111]" in text or "[errno 61]" in text or "10061" in text
    )


def is_connection_timeout(value: Any) -> bool:
    """True when ``value`` looks like a connection/read timeout error."""
    text = str(value or "").strip().lower()
    return bool(text) and ("connection timeout" in text or "timed out" in text or "timeout" in text)


def is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and is_connection_refused(record.get("error"))


def is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and is_connection_timeout(record.get("error"))
