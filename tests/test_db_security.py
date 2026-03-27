from __future__ import annotations

import gzip
import json

from redposture_core.db.security import NoOpArtifactCipher, SecretCandidate, build_secret_ref, sanitize_payload
from redposture_core.db.util import compress_json_payload, parse_datetime, stable_hash


def test_sanitize_payload_redacts_nested_secrets_and_collects_candidates() -> None:
    payload = {
        "password": "Sup3rSecret!",
        "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
        "dsn": "postgresql://postgres:postgres@db.internal/app?sslmode=require&password=hidden",
        "plain": "token=abcdef password=ghijk",
    }

    sanitized = sanitize_payload(payload)
    dumped = json.dumps(sanitized.data, ensure_ascii=False)

    assert "Sup3rSecret!" not in dumped
    assert "postgres:postgres" not in dumped
    assert "<redacted:password>" in dumped
    assert "<redacted:basic_auth>" in dumped
    assert any(marker in dumped for marker in ("<redacted:url_basic_auth>", "<redacted:dsn_auth>"))
    assert len(sanitized.secret_candidates) >= 4
    assert len(sanitized.preview_text) <= 512


def test_build_secret_ref_and_noop_cipher_roundtrip() -> None:
    ref = build_secret_ref(
        SecretCandidate(
            secret_kind="password",
            raw_value="secret",
            redacted_value="<redacted:password>",
            source_hint="payload.password",
        )
    )
    cipher = NoOpArtifactCipher()
    encrypted = cipher.encrypt(b"payload")

    assert ref.secret_kind == "password"
    assert ref.redacted_value == "<redacted:password>"
    assert len(ref.fingerprint) == 64
    assert cipher.decrypt(encrypted.payload) == b"payload"
    assert encrypted.content_encoding is None


def test_sanitize_payload_does_not_redact_non_secret_key_substrings() -> None:
    payload = {"monkey": "banana", "donkey": "cart", "keynote": "public talk"}

    sanitized = sanitize_payload(payload)

    assert sanitized.data == payload
    assert sanitized.secret_candidates == ()


def test_sanitize_payload_redacts_embedded_json_strings() -> None:
    payload = {"body": '{"username":"metrics","password":"secret","dsn":"postgresql://metrics:secret@db.internal/app"}'}

    sanitized = sanitize_payload(payload)
    dumped = json.dumps(sanitized.data, ensure_ascii=False)

    assert "secret" not in dumped
    assert "metrics:secret@" not in dumped
    assert "<redacted:password>" in dumped
    assert any(marker in dumped for marker in ("<redacted:url_basic_auth>", "<redacted:dsn_auth>"))


def test_sanitize_payload_redacts_json_like_string_fragments() -> None:
    payload = {"sample": '"sasl_password": "Kfka-M0nitor-2026", "sasl_username": "metrics_collector"'}

    sanitized = sanitize_payload(payload)
    dumped = json.dumps(sanitized.data, ensure_ascii=False)

    assert "Kfka-M0nitor-2026" not in dumped
    assert "<redacted:sasl_password>" in dumped


def test_sanitize_payload_redacts_non_url_dsn_auth_patterns() -> None:
    payload = {"sample": 'data_source_name":"metrics:MySQL-Metrics!2026@(mysql.internal:3306)/"'}

    sanitized = sanitize_payload(payload)
    dumped = json.dumps(sanitized.data, ensure_ascii=False)

    assert "MySQL-Metrics!2026" not in dumped
    assert "<redacted:dsn_auth>" in dumped


def test_db_util_helpers_roundtrip_json_payload_and_parse_datetime() -> None:
    compressed, content_encoding, size_bytes, sha256_value = compress_json_payload({"a": 1})
    restored = json.loads(gzip.decompress(compressed).decode("utf-8"))

    assert restored == {"a": 1}
    assert content_encoding == "gzip"
    assert size_bytes == len(compressed)
    assert len(sha256_value) == 64
    assert parse_datetime("2026-03-23T12:00:00Z") is not None
    assert parse_datetime("") is None
    assert stable_hash("a", "b") == stable_hash("a", "b")
