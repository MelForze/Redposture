from __future__ import annotations

import pytest

from redposture_core.clients import transport


class _FakeSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk


def test_recv_exact_reads_multiple_chunks_and_raises_on_eof() -> None:
    assert transport.recv_exact(_FakeSocket([b"ab", b"cd", b"ef"]), 6) == b"abcdef"

    with pytest.raises(ConnectionError, match="unexpected EOF"):
        transport.recv_exact(_FakeSocket([b"ab", b""]), 3)


def test_transport_error_classifiers_and_fail_record_helpers() -> None:
    assert transport.is_connection_refused("[Errno 61] Connection refused") is True
    assert transport.is_connection_refused("10061 connect failed") is True
    assert transport.is_connection_refused(None) is False
    assert transport.is_connection_timeout("socket timed out") is True
    assert transport.is_connection_timeout("") is False
    assert transport.is_connection_refused_fail_record({"status": "fail", "error": "[Errno 111]"}) is True
    assert transport.is_connection_timeout_fail_record({"status": "fail", "error": "timeout"}) is True
    assert transport.is_connection_timeout_fail_record({"status": "ok", "error": "timeout"}) is False


def test_escalating_timeout_ladder_default_base():
    assert [transport.escalating_timeout(3.0, i) for i in range(4)] == [3.0, 5.0, 7.0, 7.0]


def test_escalating_timeout_ladder_high_base_clamps_up():
    assert [transport.escalating_timeout(8.0, i) for i in range(3)] == [8.0, 8.0, 8.0]


def test_escalating_timeout_ladder_low_explicit_base():
    assert [transport.escalating_timeout(1.0, i) for i in range(3)] == [1.0, 5.0, 7.0]


def test_classify_failure_reason_buckets():
    assert transport.classify_failure_reason("[Errno 61] Connection refused") == "refused"
    assert transport.classify_failure_reason("connection timeout") == "timeout"
    assert transport.classify_failure_reason("Read timed out") == "timeout"
    assert transport.classify_failure_reason("Name or service not known") == "dns"
    assert transport.classify_failure_reason("No route to host") == "network"
    assert transport.classify_failure_reason("certificate verify failed") == "tls"
    assert transport.classify_failure_reason("Connection reset by peer") == "reset"


def test_classify_failure_reason_ignores_application_timeout_words():
    # Прикладные «timeout», не сетевые — не должны считаться timeout.
    assert transport.classify_failure_reason("INVALID_SESSION_TIMEOUT") == "other"
    assert transport.classify_failure_reason("Timeout exceeded: elapsed 10s, maximum: max_execution_time") == "other"


def test_reason_predicates():
    assert transport.is_terminal_reason("refused") is True
    assert transport.is_terminal_reason("dns") is True
    assert transport.is_terminal_reason("tls") is True
    assert transport.is_escalating_reason("timeout") is True
    assert transport.is_escalating_reason("reset") is True
    assert transport.is_escalating_reason("refused") is False
