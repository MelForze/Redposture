"""NEXT_QA #6 — Kafka broker: SASL handshake/authenticate — негативные ветви (auth).

Докрывает в clients/kafka.py негативы, не покрытые штатными тестами:
  _sasl_handshake_plain: unsupported-mechanism (!=0,!=35), success (==0), битый ответ;
  _sasl_authenticate_plain (modern flow): unexpected-corr, success (==0),
  ошибка !=35 и !=58 → None с деталью из error_message.
Штатный test_clients_kafka уже покрывает: 35/35→UNSUPPORTED_VERSION, unexpected-corr
у handshake, 58→False у authenticate — здесь их не дублируем.

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import struct

from redposture_core.clients import kafka


class _FrameSocket:
    """Фейк-сокет: отдаёт каждый кадр с префиксом длины (как настоящий брокер)."""

    def __init__(self, frames: bytes | list[bytes] = b"") -> None:
        self.sent: list[bytes] = []
        items = frames if isinstance(frames, list) else [frames]
        self._payload = b"".join(struct.pack(">i", len(f)) + f for f in items)
        self._timeout = 1.0

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        chunk = self._payload[:size]
        self._payload = self._payload[size:]
        return chunk

    def gettimeout(self) -> float:
        return self._timeout

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout


def _nstr(value: str | None) -> bytes:
    """Nullable Kafka string: i16 длина (-1 = null) + байты."""
    if value is None:
        return struct.pack(">h", -1)
    data = value.encode("utf-8")
    return struct.pack(">h", len(data)) + data


# --- _sasl_handshake_plain ---------------------------------------------------


def test_handshake_unsupported_mechanism_is_handshake_failure() -> None:
    """error_code != 0 и != 35 (33=UNSUPPORTED_SASL_MECHANISM) → handshake failed."""
    ok, next_corr, error = kafka._sasl_handshake_plain(_FrameSocket(struct.pack(">ih", 1, 33)), 1)
    assert ok is False
    assert next_corr == 2
    assert error == "SASL handshake failed: UNSUPPORTED_SASL_MECHANISM"


def test_handshake_success_returns_true() -> None:
    """error_code == 0 + корректный string-array механизмов → успех."""
    frame = struct.pack(">ih", 1, 0) + struct.pack(">i", 0)  # пустой массив механизмов
    ok, next_corr, error = kafka._sasl_handshake_plain(_FrameSocket(frame), 1)
    assert ok is True
    assert next_corr == 2
    assert error is None


def test_handshake_truncated_response_is_invalid() -> None:
    """Обрезанный ответ (нет error_code i16) → struct.error → 'invalid SASL handshake response'."""
    ok, next_corr, error = kafka._sasl_handshake_plain(
        _FrameSocket(struct.pack(">i", 1)),
        1,  # только correlation id, дальше нечего читать
    )
    assert ok is False
    assert next_corr == 2
    assert error is not None and "invalid SASL handshake response" in error


# --- _sasl_authenticate_plain (modern SASL_AUTHENTICATE flow) ----------------


def test_authenticate_unexpected_correlation() -> None:
    ok, next_corr, error = kafka._sasl_authenticate_plain(_FrameSocket(struct.pack(">i", 999)), 3, "user", "pw")
    assert ok is None
    assert error is not None and "unexpected correlation id" in error


def test_authenticate_success_returns_true() -> None:
    frame = struct.pack(">ih", 3, 0) + _nstr(None) + struct.pack(">i", -1)  # ok, null msg, null bytes
    ok, next_corr, error = kafka._sasl_authenticate_plain(_FrameSocket(frame), 3, "user", "pw")
    assert ok is True
    assert next_corr == 4
    assert error is None


def test_authenticate_other_error_is_inconclusive_none_with_detail() -> None:
    """error_code != 0, != 35, != 58 → None (неопределённо), деталь берётся из error_message."""
    frame = struct.pack(">ih", 3, 1) + _nstr("broker said no") + struct.pack(">i", -1)
    ok, next_corr, error = kafka._sasl_authenticate_plain(_FrameSocket(frame), 3, "user", "pw")
    assert ok is None  # не False — ошибка не из «явно отклонён» класса (58)
    assert error is not None and "broker said no" in error


# --- legacy fallback (raw size-prefixed SASL bytes) --------------------------
# Вход в fallback: modern SASL_AUTHENTICATE вернул error_code==35 (нет return в
# modern-блоке) → управление доходит до legacy-ветви 2637-2672.


def _modern_err35_frame() -> bytes:
    return struct.pack(">ih", 3, 35) + _nstr(None) + struct.pack(">i", -1)


def test_authenticate_legacy_fallback_detects_auth_error_frame() -> None:
    """fallback: сырой size-prefixed кадр с текстом auth-ошибки → (False, детали)."""
    legacy_body = b"SASL authentication failed: invalid credentials"
    sock = _FrameSocket([_modern_err35_frame(), legacy_body])
    ok, next_corr, error = kafka._sasl_authenticate_plain(sock, 3, "user", "pw")
    assert ok is False
    assert error is not None and "authentication failed" in error.lower()
    # fallback реально отправил сырые SASL-байты (после modern-запроса)
    assert len(sock.sent) >= 2


def test_authenticate_legacy_fallback_no_response_is_unavailable() -> None:
    """fallback: ответа нет (кадр пуст) → None, 'SASL authentication response unavailable'."""
    sock = _FrameSocket([_modern_err35_frame()])  # второго кадра нет
    ok, next_corr, error = kafka._sasl_authenticate_plain(sock, 3, "user", "pw")
    assert ok is None
    assert error == "SASL authentication response unavailable"
