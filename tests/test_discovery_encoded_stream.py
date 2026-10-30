"""Encoded large text preserves decoded field context and complete values."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from io import BytesIO
from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("encoding", ["base64", "urlsafe", "hex", "gzip", "double"])
@pytest.mark.parametrize("shape", ["assignment", "json", "xml"])
def test_large_encoded_secret_keeps_full_decoded_value_and_field_context(encoding, shape) -> None:
    expected = "Ab0λ" * 20000 + "-tail"
    if shape == "assignment":
        raw = ('password="' + expected + '"\n').encode()
    elif shape == "xml":
        raw = ("<config><password>" + expected + "</password></config>").encode()
    else:
        raw = json.dumps({"config": {"password": expected}}, ensure_ascii=False).encode()
    if encoding == "hex":
        encoded = raw.hex()
    elif encoding == "gzip":
        encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    elif encoding == "double":
        encoded = base64.b64encode(base64.b64encode(raw)).decode()
    elif encoding == "urlsafe":
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    else:
        encoded = base64.b64encode(raw).decode()
    matches, _size, covered = _scan_portioned_value({"message": encoded}, "$.source", 512)
    assert covered
    passwords = [match for match in matches if match.detector == "password"]
    assert len(passwords) == 1
    value = passwords[0].value
    assert isinstance(value, DiskBackedText)
    assert value.digest == hashlib.sha256(expected.encode()).hexdigest()
    assert passwords[0].object_path.endswith(".password")


def test_archive_member_with_large_encoded_json_retains_nested_place() -> None:
    password = "Ab0λ" * 20000 + "-tail"
    body = base64.b64encode(json.dumps({"database": {"password": password}}, ensure_ascii=False).encode())
    result_collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    result_collector._scan_member_stream("source", "config.b64", BytesIO(body), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "password"
    assert finding["value"].digest == hashlib.sha256(password.encode()).hexdigest()
    assert finding["object_path"] == "$.source/file/config.b64.database.password"


@pytest.mark.parametrize("shape", ["assignment", "xml"])
def test_encoded_structured_secret_under_sensitive_field_reports_leaf_value(shape) -> None:
    password = "Ab0λ" * 20000 + "-tail"
    raw = ('password="' + password + '"') if shape == "assignment" else ("<password>" + password + "</password>")
    encoded = base64.b64encode(raw.encode()).decode()
    matches, _size, covered = _scan_portioned_value({"password": encoded}, "$.source", 512)
    assert covered and len(matches) == 1
    assert matches[0].detector == "password"
    assert matches[0].value.digest == hashlib.sha256(password.encode()).hexdigest()


@pytest.mark.parametrize("encoding", ["wrapped", "small_gzip"])
def test_encoded_file_reader_handles_mime_lines_and_small_compressed_source(encoding) -> None:
    password = "Ab0λ" * 20000 + "-tail"
    raw = json.dumps({"database": {"password": password}}, ensure_ascii=False).encode()
    body = base64.encodebytes(raw) if encoding == "wrapped" else base64.b64encode(gzip.compress(raw, mtime=0))
    result_collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    result_collector._scan_member_stream("source", "config.b64", BytesIO(body), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "password"
    assert finding["value"].digest == hashlib.sha256(password.encode()).hexdigest()
    assert finding["object_path"] == "$.source/file/config.b64.database.password"


@pytest.mark.parametrize("damage", ["crc", "truncated", "trailing"])
def test_corrupted_encoded_gzip_never_becomes_a_complete_source(damage) -> None:
    raw = b'password="' + b"Ab0" * 20000 + b'"\n'
    compressed = gzip.compress(raw, mtime=0)
    if damage == "crc":
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    elif damage == "trailing":
        compressed += b"trailing-invalid-gzip-data"
    else:
        compressed = compressed[:-5]
    encoded = base64.b64encode(compressed).decode()
    matches, _size, covered = _scan_portioned_value({"message": encoded}, "$.source", 512)
    assert not covered
    assert not matches


def test_http_mime_blob_does_not_publish_encoded_fragments_as_entropy_findings() -> None:
    from redposture_core.clients.http_api import HttpResponse

    password = "Ab0λ" * 20000 + "-tail"
    body = base64.encodebytes(json.dumps({"database": {"password": password}}, ensure_ascii=False).encode())
    observed = []
    result_collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(
            args=SimpleNamespace(discover_time=30), host="qa", port=80, live_emit=lambda lines: observed.extend(lines)
        ),
        {"status": "open_no_auth"},
    )

    class Pool:
        def request_stream(self, method, url, *, on_chunk, **kwargs):
            for offset in range(0, len(body), 509):
                on_chunk(body[offset : offset + 509])
            return HttpResponse(200, b"", {})

    assert result_collector.stream_http_content(Pool(), "http://qa", "source", headers={}, timeout=1)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "password"
    assert finding["value"].digest == hashlib.sha256(password.encode()).hexdigest()
    assert not observed, "only a verified disk-backed password is expected, no small encoded fragments"


def test_concatenated_gzip_members_form_one_complete_encoded_text() -> None:
    expected = "Ab0λ" * 20000 + "-tail"
    prefix = ('password="' + expected[:10000]).encode()
    tail = (expected[10000:] + '"\n').encode()
    encoded = base64.b64encode(gzip.compress(prefix, mtime=0) + gzip.compress(tail, mtime=0)).decode()
    matches, _size, covered = _scan_portioned_value({"message": encoded}, "$.source", 512)
    assert covered and len(matches) == 1
    assert matches[0].detector == "password"
    assert matches[0].value.digest == hashlib.sha256(expected.encode()).hexdigest()


def test_encoded_expansion_obeys_target_deadline_without_emitting_partial_candidate(monkeypatch) -> None:
    import time

    now = [0.0]
    encoded = base64.b64encode(gzip.compress(b'password="' + b"Ab0" * 100000 + b'"\n', mtime=0)).decode()
    original = DiskBackedText.append_text
    writes = []

    def append(self, text):
        original(self, text)
        if text.startswith('password="'):
            now[0] = 2.0
        writes.append(len(text))

    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    monkeypatch.setattr(DiskBackedText, "append_text", append)
    result_collector = DiscoveryCollector(
        "portainer",
        SimpleNamespace(args=SimpleNamespace(discover_time=1), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    assert not result_collector.add("source", {"message": encoded}, charge=False, prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "partial"
    assert "discover_time" in result["partial_reasons"]
    assert not result["findings"]
    assert sum(writes) < 200000, "decoding must stop before expanding the entire candidate"


def test_small_json_string_still_expands_a_large_compressed_child() -> None:
    password = "Ab0λ" * 20000
    inner = base64.b64encode(gzip.compress(('password="' + password + '"').encode(), mtime=0)).decode()
    value = json.dumps({"config": {"payload": inner}})
    matches, _size, covered = _scan_portioned_value({"message": value}, "$.source", 65536)
    assert covered and len(matches) == 1
    assert matches[0].detector == "password"
    assert matches[0].value.digest == hashlib.sha256(password.encode()).hexdigest()
    assert matches[0].object_path == "$.source.message.config.payload.password"


def test_timeout_during_encoded_sibling_keeps_previously_completed_finding(monkeypatch) -> None:
    import time

    now = [0.0]
    encoded = base64.b64encode(gzip.compress(b'password="' + b"Ab0" * 100000 + b'"\n', mtime=0)).decode()
    original = DiskBackedText.append_text

    def append(self, text):
        original(self, text)
        if text.startswith('password="'):
            now[0] = 2.0

    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    monkeypatch.setattr(DiskBackedText, "append_text", append)
    result_collector = DiscoveryCollector(
        "portainer",
        SimpleNamespace(args=SimpleNamespace(discover_time=1), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    assert not result_collector.add("source", {"password": "BeforeTimeoutSecret", "payload": encoded})
    result = result_collector.result()
    assert result["status"] == "partial"
    assert "discover_time" in result["partial_reasons"]
    assert [(item["type"], item["value"]) for item in result["findings"]] == [("password", "BeforeTimeoutSecret")]


def test_encoded_neutral_utf8_text_does_not_create_entropy_findings_from_mime_fragments() -> None:
    raw = ("ordinary status λ: successful operation\n" * 1000).encode()
    body = base64.encodebytes(raw)
    result_collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    result_collector._scan_member_stream("source", "status.b64", BytesIO(body), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert not result["findings"]


def test_compressed_hex_with_leading_whitespace_and_mixed_case_still_expands() -> None:
    password = "Ab0λ" * 20000
    hex_text = gzip.compress(('password="' + password + '"').encode(), mtime=0).hex()
    encoded = " " * 1000 + "".join(char.upper() if offset % 3 == 1 else char for offset, char in enumerate(hex_text))
    matches, _size, covered = _scan_portioned_value({"message": encoded}, "$.source", 65536)
    assert covered and len(matches) == 1
    assert matches[0].detector == "password"
    assert matches[0].value.digest == hashlib.sha256(password.encode()).hexdigest()


def test_long_opaque_secret_field_keeps_its_stored_base64_value() -> None:
    encoded = base64.b64encode(b"ordinary printable value " * 5000).decode()
    matches, _size, covered = _scan_portioned_value({"password": encoded}, "$.source", 65536)
    assert covered and len(matches) == 1
    assert matches[0].detector == "password"
    assert matches[0].value.digest == hashlib.sha256(encoded.encode()).hexdigest()
