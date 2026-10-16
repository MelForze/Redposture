"""NEXT_QA #6 — Kafka broker: TLS-ошибки → понятная классификация (auth/render-ветвь).

`clients/kafka.py::_classify_ssl_error` превращает сырой текст SSL-ошибки в
человекочитаемую причину для аудит-строки (hostname mismatch, не-TLS листенер,
mTLS, cipher mismatch и т.п.). Это render/auth-ветвь: от неё зависит, что увидит
оператор при TLS-проблеме. Каждый класс = отдельная ветвь; покрываем положительный
(распознанный класс) и отрицательный (fallback с чисткой _ssl.c-хвоста) исходы.

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import ssl

import pytest

from redposture_core.clients import kafka as kafka_client


@pytest.mark.parametrize(
    ("message", "expected_substr"),
    [
        # cert verify failed + mismatch-маркер → hostname mismatch
        ("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: IP address mismatch", "hostname mismatch"),
        ("certificate verify failed: hostname 'x' not valid for 'y'", "hostname mismatch"),
        # cert verify failed без mismatch → недоверенный CA
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate",
            "not trusted by the configured CA",
        ),
        # TLS ClientHello против plaintext-пира
        ("[SSL: WRONG_VERSION_NUMBER] wrong version number", "not a TLS listener"),
        # EOF без alert
        ("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred", "without alert"),
        ("TLS/SSL connection has been closed (EOF)", "without alert"),
        # требуется клиентский сертификат (mTLS)
        ("[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] certificate required", "mTLS"),
        ("[SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3_alert_bad_certificate (_ssl.c:1000)", "mTLS"),
        # handshake failure
        ("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure", "rejected TLS handshake"),
        # certificate unknown
        ("[SSL: TLSV1_ALERT_CERTIFICATE_UNKNOWN] certificate_unknown", "certificate unknown"),
        # нет общего шифра
        ("[SSL: NO_SHARED_CIPHER] no shared cipher", "no shared TLS cipher"),
    ],
)
def test_classify_ssl_error_recognized_classes(message: str, expected_substr: str) -> None:
    reason = kafka_client._classify_ssl_error(ssl.SSLError(message))
    assert expected_substr in reason


def test_classify_ssl_error_cert_verification_error_type() -> None:
    """Положительный: тип SSLCertVerificationError распознаётся даже без ключевого текста."""
    exc = ssl.SSLCertVerificationError("boom")
    reason = kafka_client._classify_ssl_error(exc)
    assert "certificate" in reason.lower()


def test_classify_ssl_error_fallback_strips_ssl_c_trailer() -> None:
    """Отрицательный: нераспознанный класс → исходный текст, но без шумного _ssl.c:LINE хвоста."""
    reason = kafka_client._classify_ssl_error(ssl.SSLError("some novel tls failure (_ssl.c:992)"))
    assert "some novel tls failure" in reason
    assert "_ssl.c:" not in reason


def test_classify_ssl_error_uses_verify_message_attr() -> None:
    """verify_message-атрибут участвует в распознавании hostname mismatch."""
    exc = ssl.SSLError("certificate verify failed")
    exc.verify_message = "hostname mismatch"
    reason = kafka_client._classify_ssl_error(exc)
    assert "hostname mismatch" in reason
