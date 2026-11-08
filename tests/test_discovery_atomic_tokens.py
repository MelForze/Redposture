"""Large atomic tokens in neutral fields retain their complete value."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize(
    ("prefix", "middle", "suffix", "detector"),
    [
        ("eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoi", "YWJj", "In0.c2lnbmF0dXJl", "jwt"),
        ("glsa_", "Ab0_", "tail", "grafana_token"),
        ("sk-proj-", "Ab0_", "tail", "api_token"),
        ("dckr_pat_", "Ab0_", "tail", "docker_token"),
        ("dop_v1_", "Ab0", "tail", "digitalocean_token"),
        ("shpat_", "Ab0", "tail", "shopify_token"),
        ("pypi-AgEI", "Ab0_", "tail", "pypi_token"),
    ],
)
def test_neutral_disk_token_keeps_full_value_without_materializing(prefix, middle, suffix, detector) -> None:
    expected = prefix + middle * 80_000 + suffix
    with DiskBackedText() as disk:
        for pos in range(0, len(expected), 8191):
            disk.append_text(expected[pos : pos + 8191])
        disk.finish()
        matches, size, covered = _scan_portioned_value(disk, "$.message", 512)
        assert covered
        assert size == len(expected.encode())
        assert [(match.detector, match.object_path) for match in matches] == [(detector, "$.message")]
        assert matches[0].value is disk
        assert disk.digest == hashlib.sha256(expected.encode()).hexdigest()


@pytest.mark.parametrize("reader", ["scalars", "text_field"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_streamed_neutral_jwt_waits_for_end_and_keeps_exact_value(reader, interrupted) -> None:
    from redposture_core.clients.http_api import HttpResponse

    token = "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoi" + "YWJj" * 80_000 + "In0.c2lnbmF0dXJl"
    body = json.dumps({"message": token}).encode()
    if interrupted:
        body = body[:-2]

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for pos in range(0, len(body), 257):
                on_chunk(body[pos : pos + 257])
                if pos + 257 < len(body):
                    assert not collector.findings, "an unfinished token must not be emitted"
            return HttpResponse(200, b"", {}, error="EOF" if interrupted else None, truncated=interrupted)

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1024, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    if reader == "scalars":
        ok = collector.stream_json_scalars(
            Pool(), "http://qa/value", "source", headers={}, timeout=1, root_kind="object"
        )
    else:
        ok = collector.stream_json_text_field(Pool(), "http://qa/value", "source", "message", headers={}, timeout=1)
    result = collector.result()
    assert ok is not interrupted
    assert result["status"] == ("partial" if interrupted else "complete"), result["partial_reasons"]
    if interrupted:
        assert not result["findings"]
    else:
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["type"] == "jwt"
        assert isinstance(finding["value"], DiskBackedText)
        assert finding["value"].digest == hashlib.sha256(token.encode()).hexdigest()


@pytest.mark.parametrize("reader", ["scalars", "text_field", "archive"])
def test_large_neutral_token_keeps_later_completed_finding(reader) -> None:
    from io import BytesIO

    from redposture_core.clients.http_api import HttpResponse

    token = "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoi" + "YWJj" * 400 + "In0.c2lnbmF0dXJl"
    text = token + "\npassword=qa-late-password\n"
    payload = json.dumps({"message": text}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for pos in range(0, len(payload), 256):
                on_chunk(payload[pos : pos + 256])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    if reader == "scalars":
        collector.stream_json_scalars(Pool(), "http://qa", "source", headers={}, timeout=1, root_kind="object")
    elif reader == "text_field":
        collector.stream_json_text_field(Pool(), "http://qa", "source", "message", headers={}, timeout=1)
    else:
        collector._scan_member_stream("source", "test.log", BytesIO(text.encode()))
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    observed = {
        (
            item["type"],
            "".join(item["value"].iter_text_chunks()) if isinstance(item["value"], DiskBackedText) else item["value"],
        )
        for item in result["findings"]
    }
    assert ("jwt", token) in observed
    assert ("password", "qa-late-password") in observed


@pytest.mark.parametrize(
    "bad", ["not-a-token-" + "a" * 200_000, "glsa_" + "a" * 200_000 + "☃", "eyJabcdefgh." + "a" * 200_000]
)
def test_neutral_size_and_partial_prefix_are_not_secret_evidence(bad) -> None:
    with DiskBackedText() as disk:
        disk.append_text(bad)
        disk.finish()
        matches, _, _ = _scan_portioned_value(disk, "$.message", 512)
        assert not matches


def test_materialized_neutral_token_uses_same_complete_disk_path() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoi" + "YWJj" * 1000 + "In0.c2lnbmF0dXJl"
    matches, size, covered = _scan_portioned_value({"message": token}, "$", 512)
    assert covered
    assert size >= len(token)
    assert len(matches) == 1 and matches[0].detector == "jwt"
    value = matches[0].value
    assert isinstance(value, DiskBackedText)
    assert "".join(value.iter_text_chunks()) == token


@pytest.mark.parametrize("reader", ["scalars", "text_field"])
def test_completed_large_token_is_emitted_before_later_source_failure(reader) -> None:
    from redposture_core.clients.http_api import HttpResponse

    token = "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoi" + "YWJj" * 1000 + "In0.c2lnbmF0dXJl"
    head = json.dumps({"message": token}).encode()[:-1] + (b',"later":' if reader == "scalars" else b"")
    emitted: list[str] = []

    def emit(_module, _host, _port, *, value, **_kwargs):
        emitted.append(value.digest)

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for pos in range(0, len(head), 256):
                on_chunk(head[pos : pos + 256])
            assert emitted == [hashlib.sha256(token.encode()).hexdigest()]
            return HttpResponse(200, b"", {}, error="connection reset", truncated=True)

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80, live_discovery_value=emit
    )
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    if reader == "scalars":
        ok = collector.stream_json_scalars(Pool(), "http://qa", "source", headers={}, timeout=1, root_kind="object")
    else:
        ok = collector.stream_json_text_field(Pool(), "http://qa", "source", "message", headers={}, timeout=1)
    result = collector.result()
    assert not ok and result["status"] == "partial"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["value"].digest == hashlib.sha256(token.encode()).hexdigest()
