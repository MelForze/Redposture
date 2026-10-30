"""Elastic streamed values keep its detector policy and complete secret values."""

from __future__ import annotations

import base64
import hashlib
import io
import json

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverResponse
from redposture_core.modules.elastic.search_stream import StreamedSearchPage


def consume(source):
    payload = {
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_index": "logs", "_id": "one", "_source": source}]}
    }
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload, ensure_ascii=False).encode()), inline_limit=1024)
    engine = DiscoverEngine(lambda _request: pytest.fail("no network request is needed for a supplied page"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        stream.summary(),
        candidate=True,
        payload_complete=True,
    )
    return engine


@pytest.mark.parametrize("shape", ["assignment", "xml", "encoded_json", "encoded_gzip"])
def test_streamed_elastic_text_keeps_whole_contextual_secret(shape) -> None:
    secret = "Ab0λ" * 20000 + "-tail"
    if shape == "xml":
        text = "<config><password>" + secret + "</password></config>"
    elif shape in {"encoded_json", "encoded_gzip"}:
        import gzip

        raw = json.dumps({"database": {"password": secret}}, ensure_ascii=False).encode()
        if shape == "encoded_gzip":
            raw = gzip.compress(raw, mtime=0)
        text = base64.b64encode(raw).decode()
    else:
        text = 'ordinary status\npassword="' + secret + '"\nlater status'
    engine = consume({"message": text})
    findings = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons, engine.coverage.truncated_reasons
    assert len(findings) == 1
    assert findings[0].secret_type == "password"
    assert isinstance(findings[0].value, DiskBackedText)
    assert findings[0].value.digest == hashlib.sha256(secret.encode()).hexdigest()
    assert findings[0].locations[0].path.startswith("/message")


def test_streamed_elastic_valid_jwt_is_fully_validated_without_materializing_payload() -> None:
    def encoded(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    token = encoded({"alg": "HS256"}) + "." + encoded({"query": "ordinary " * 20000}) + "." + "s" * 43
    engine = consume({"message": token})
    findings = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons
    assert len(findings) == 1 and findings[0].secret_type == "jwt"
    assert isinstance(findings[0].value, DiskBackedText)
    assert findings[0].value.digest == hashlib.sha256(token.encode()).hexdigest()


def test_streamed_elastic_does_not_accept_a_structurally_invalid_jwt() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9." + "YWJj" * 20000 + "." + "s" * 43
    engine = consume({"message": token})
    assert not engine.accumulator.findings()


def test_streamed_elastic_medium_key_and_semantic_pair_keep_full_values() -> None:
    secret = "Ab0Z1_2T3q4V5u6" * 10000
    for source, pointer in [({"api_key": secret}, "/api_key"), ({"name": "db_password", "value": secret}, "/value")]:
        engine = consume(source)
        findings = list(engine.accumulator.findings())
        assert not engine.coverage.truncated_reasons, engine.coverage.truncated_reasons
        assert len(findings) == 1
        assert isinstance(findings[0].value, DiskBackedText)
        assert findings[0].value.digest == hashlib.sha256(secret.encode()).hexdigest()
        assert findings[0].locations[0].path == pointer


@pytest.mark.parametrize("kind,size", [("bearer", 2000), ("basic", 20000)])
def test_streamed_elastic_mixed_auth_log_keeps_completed_secret(kind, size) -> None:
    secret = "Ab0Z1_2T3q4V5u6" * size
    if kind == "basic":
        token = base64.b64encode(("qa:" + secret).encode()).decode()
        text = "Authorization: Basic " + token + "\nlater ordinary text"
    else:
        text = "Authorization: Bearer " + secret + "\nlater ordinary text"
    engine = consume({"message": text})
    findings = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons
    assert len(findings) == 1
    assert findings[0].secret_type == ("password" if kind == "basic" else "bearer_token")
    actual = findings[0].value
    digest = actual.digest if isinstance(actual, DiskBackedText) else hashlib.sha256(actual.encode()).hexdigest()
    assert digest == hashlib.sha256(secret.encode()).hexdigest()


@pytest.mark.parametrize("shape", ["assignment", "xml", "encoded_json"])
def test_materialized_elastic_large_text_uses_the_same_complete_reader(shape) -> None:
    secret = "Ab0λ" * 20000 + "-tail"
    if shape == "xml":
        text = "<config><password>" + secret + "</password></config>"
    elif shape == "encoded_json":
        text = base64.b64encode(json.dumps({"database": {"password": secret}}, ensure_ascii=False).encode()).decode()
    else:
        text = 'password="' + secret + '"'
    engine = DiscoverEngine(lambda _request: pytest.fail("no network request is needed for a supplied hit"))
    engine._process_hit(
        "logs", {"_index": "logs", "_id": "one", "_source": {"message": text}}, candidate=True, payload_complete=True
    )
    findings = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons
    assert len(findings) == 1 and findings[0].secret_type == "password"
    assert isinstance(findings[0].value, DiskBackedText)
    assert findings[0].value.digest == hashlib.sha256(secret.encode()).hexdigest()


def test_materialized_elastic_large_scalar_adds_only_bounded_working_memory() -> None:
    import tracemalloc

    secret = "Ab0λ" * 5000000
    engine = DiscoverEngine(lambda _request: pytest.fail("no network request is needed for a supplied hit"))
    hit = {"_index": "logs", "_id": "one", "_source": {"password": secret}}
    tracemalloc.start()
    try:
        engine._process_hit("logs", hit, candidate=True, payload_complete=True)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8_000_000, peak
    findings = list(engine.accumulator.findings())
    assert len(findings) == 1
    assert isinstance(findings[0].value, DiskBackedText)
    assert findings[0].value.digest == hashlib.sha256(secret.encode()).hexdigest()


@pytest.mark.parametrize("header", [b'{"alg":false}', b'{"alg":{}}', b'{"alg":"HS256","alg":false}'])
def test_streamed_elastic_jwt_requires_the_final_alg_field_to_be_a_string(header) -> None:
    def encoded(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    token = encoded(header) + "." + encoded(json.dumps({"query": "ordinary " * 2000}).encode()) + "." + "s" * 43
    engine = consume({"message": token})
    assert not engine.accumulator.findings()


@pytest.mark.parametrize("empty_key", [False, True])
def test_streamed_elastic_jwe_keeps_the_complete_ciphertext_token(empty_key) -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"RSA-OAEP-256","enc":"A256GCM"}').decode().rstrip("=")
    token = ".".join([header, "" if empty_key else "Abcdefgh12345", "iv1234567890", "Ab0_" * 4000, "AuthTag12345"])
    engine = consume({"message": token})
    findings = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons
    assert len(findings) == 1 and findings[0].secret_type == "jwe"
    assert isinstance(findings[0].value, DiskBackedText)
    assert findings[0].value.digest == hashlib.sha256(token.encode()).hexdigest()


def test_streamed_elastic_basic_does_not_interpret_gzip_as_protocol_credentials() -> None:
    import gzip

    password = "".join(hashlib.sha256(str(index).encode()).hexdigest() for index in range(2000))
    token = base64.b64encode(gzip.compress(("qa:" + password).encode(), mtime=0)).decode()
    assert len(token) > 65536
    engine = consume({"message": "Basic " + token})
    assert not engine.accumulator.findings()


def test_streamed_elastic_low_entropy_medium_field_is_not_a_secret() -> None:
    engine = consume({"api_key": "A" * 100000})
    assert not engine.accumulator.findings()
    assert not engine.coverage.truncated_reasons
