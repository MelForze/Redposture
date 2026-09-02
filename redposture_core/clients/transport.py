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


_RESET_MARKERS = (
    "connection reset",
    "reset by peer",
    "broken pipe",
    "unexpected eof",
    "connection closed",
    "remote end closed",
    "server closed",
    "protocol closed before",
    "closed before",
)


def escalating_timeout(base: float, attempt_index: int) -> float:
    """Таймаут ступени `attempt_index` (0-based) по лесенке base → max(5,base) → max(7,base)."""
    base_value = max(0.1, float(base))
    floors = (base_value, max(5.0, base_value), max(7.0, base_value))
    idx = min(max(0, int(attempt_index)), len(floors) - 1)
    return floors[idx]


def classify_failure_reason(value: Any) -> str:
    """Классифицировать причину сетевого падения по нормализованному/сырому тексту.

    Приоритет refused → tls → timeout → dns → network → reset → other.
    Ветка timeout НЕ матчит голое слово ``timeout`` (только ``connection timeout`` /
    ``timed out`` / errno 60,110), иначе прикладные ``INVALID_SESSION_TIMEOUT`` и
    ``Timeout exceeded: ... max_execution_time`` ложно считались бы сетевыми.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "other"
    if "connection refused" in text or "[errno 111]" in text or "[errno 61]" in text or "10061" in text:
        return "refused"
    if (
        "certificate verify failed" in text
        or "self signed certificate" in text
        or "tls verification failed" in text
        or "wrong version number" in text
    ):
        return "tls"
    if "connection timeout" in text or "timed out" in text or "[errno 60]" in text or "[errno 110]" in text:
        return "timeout"
    if (
        "name or service not known" in text
        or "nodename nor servname" in text
        or "getaddrinfo" in text
        or "dns lookup failed" in text
        or "temporary failure in name resolution" in text
    ):
        return "dns"
    if "no route to host" in text or "network is unreachable" in text or "network unreachable" in text:
        return "network"
    if any(marker in text for marker in _RESET_MARKERS):
        return "reset"
    return "other"


def is_terminal_reason(reason: str) -> bool:
    """True, если ретрай бесполезен: refused/dns/network/tls."""
    return reason in {"refused", "dns", "network", "tls"}


def is_escalating_reason(reason: str) -> bool:
    """True, если стоит ретраить с ростом таймаута: timeout/reset."""
    return reason in {"timeout", "reset"}
