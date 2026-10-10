"""Bounded gzip decoding in both shared HTTP transports."""

from __future__ import annotations

import gzip

import pytest

from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, HttpResponse, decode_http_content
from redposture_core.clients.http_session import HttpSessionPool


def test_decode_http_content_handles_proxy_gzip_without_double_decoding() -> None:
    raw = b'{"version":"2.11.2"}'
    response = HttpResponse(200, gzip.compress(raw), {"Content-Encoding": "GZip", "Content-Length": "99"})
    decoded = decode_http_content(response, max_bytes=1024)
    assert decoded.body == raw
    assert decoded.json() == {"version": "2.11.2"}
    assert decoded.headers == {}
    assert decode_http_content(decoded, max_bytes=1024) == decoded


@pytest.mark.parametrize("payload", [b"not-gzip", gzip.compress(b"{}")[:-3], gzip.compress(b"{}") + b"junk"])
def test_decode_http_content_rejects_malformed_payload(payload: bytes) -> None:
    decoded = decode_http_content(HttpResponse(200, payload, {"content-encoding": "gzip"}), max_bytes=1024)
    assert decoded.error == "invalid gzip HTTP response"
    assert decoded.body == b""


def test_decode_http_content_limits_inflated_body() -> None:
    decoded = decode_http_content(
        HttpResponse(200, gzip.compress(b"x" * 100_000), {"Content-Encoding": "gzip"}), max_bytes=1024
    )
    assert decoded.truncated is True
    assert decoded.body == b""
    assert decoded.error == "decompressed HTTP response exceeds limit"


def test_http_api_client_decodes_gzip_before_detector_receives_body(monkeypatch: pytest.MonkeyPatch) -> None:
    client = HttpApiClient(HttpClientConfig(response_size_cap=1024))
    monkeypatch.setattr(
        client,
        "_send_with_retries",
        lambda *_args, **_kwargs: HttpResponse(200, gzip.compress(b'{"name":"Grafana"}'), {"Content-Encoding": "gzip"}),
    )
    assert client.get("http://grafana.test/api/health").json() == {"name": "Grafana"}


def test_http_session_pool_decodes_gzip_before_detector_receives_body(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = b'{"version":"3.0.2"}'

    class Response:
        status = 200
        length = 0
        will_close = True

        def read(self, _size: int) -> bytes:
            return gzip.compress(raw)

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Content-Encoding", "gzip")]

        def close(self) -> None:
            pass

    class Connection:
        def request(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getresponse(self) -> Response:
            return Response()

    pool = HttpSessionPool(timeout=1)
    monkeypatch.setattr(pool, "_acquire", lambda *_args: (Connection(), False))
    monkeypatch.setattr(pool, "_release", lambda *_args: None)
    assert pool.request("GET", "http://airflow.test/api/v2/version", response_size_cap=1024).json() == {
        "version": "3.0.2"
    }
