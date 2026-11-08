"""A normalized transport failure must not repeat the whole Docker detector."""

from __future__ import annotations

import asyncio
import http.client
import ssl
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback
from redposture_core.clients.docker_engine import (
    DockerEngineClient,
    DockerEngineConnectionError,
    normalize_docker_error,
)
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.docker import actions, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext, _invoke_host_stage
from scripts.performance_http_fixtures import response
from scripts.performance_http_server import AsyncHttpFixture
from tests.test_http_detect_handoff import peer
from tests.test_stage_docker import _args


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionRefusedError(111, "Connection refused"),
        ssl.SSLError("WRONG_VERSION_NUMBER"),
        ssl.SSLCertVerificationError("certificate verify failed"),
    ],
)
@pytest.mark.parametrize("port", [2375, 2376])
def test_native_transport_error_keeps_sync_record_and_both_transport_attempts(monkeypatch, failure, port):
    sync_calls = []
    native_calls = []

    def sync(self, method, path, **kwargs):
        scheme = "https" if self.transport == "tls" else "http"
        sync_calls.append((method, f"{scheme}://{self.host}:{self.port}{path}"))
        raise DockerEngineConnectionError(normalize_docker_error(failure)) from failure

    monkeypatch.setattr(DockerEngineClient, "request", sync)
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    args = _args()
    spec = stage.build_docker_spec(args)
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=port,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )
    expected = _invoke_host_stage(spec.host_stage, module="docker", ctx=ctx, run_deep_checks=False).to_dict()

    class Native(AsyncDetectionHttp):
        async def get(self, url, **kwargs):
            native_calls.append(("GET", url))
            self.last_exception = failure
            return HttpResponse(0, b"", {}, error=str(failure), request_url=url, final_url=url)

    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native(timeout=1, retries=0, max_bytes=262144))).to_dict()
    for record in (expected, got):
        for name in ("elapsed_ms", "stages", "stage_durations_ms", "stage_timing_total_ms"):
            record.pop(name, None)
    assert got == expected
    assert native_calls == sync_calls
    assert len(native_calls) == 2
    assert got["is_docker"] is False


@pytest.mark.parametrize(
    "failure",
    [
        None,
        ValueError("unknown native error"),
        http.client.RemoteDisconnected("peer closed without response"),
        http.client.IncompleteRead(b"part", 20),
    ],
)
def test_unknown_transport_error_still_requires_original_client(failure):
    args = _args()
    spec = stage.build_docker_spec(args)
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=2375,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )

    class Native(AsyncDetectionHttp):
        async def get(self, url, **kwargs):
            self.last_exception = failure
            return HttpResponse(0, b"", {}, error="unknown native error", request_url=url, final_url=url)

    assert spec.detect_async is not None
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(spec.detect_async(ctx, Native(timeout=1, retries=0, max_bytes=262144)))


@pytest.mark.parametrize("message", ["", "timed out"])
def test_timeout_keeps_the_existing_sync_recovery_boundary(message):
    args = _args()
    spec = stage.build_docker_spec(args)
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=2375,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )
    calls = []

    class Native(AsyncDetectionHttp):
        async def get(self, url, **kwargs):
            calls.append(url)
            self.last_exception = TimeoutError(message)
            return HttpResponse(0, b"", {}, error="timed out", request_url=url, final_url=url)

    assert spec.detect_async is not None
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(spec.detect_async(ctx, Native(timeout=1, retries=0, max_bytes=262144)))
    # The original timeout policy hands over after the first native read.
    # A second native transport would add an attempt before sync escalation.
    assert calls == ["http://127.0.0.1:2375/_ping"]


@pytest.mark.parametrize("truncated", [False, True])
def test_damaged_positive_response_does_not_become_a_final_transport_denial(truncated):
    args = _args()
    spec = stage.build_docker_spec(args)
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=2375,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )

    class Native(AsyncDetectionHttp):
        async def get(self, url, **kwargs):
            self.last_exception = ConnectionResetError("stale error must not decide this response")
            return HttpResponse(
                200, b"part", {}, error="damaged body", truncated=truncated, request_url=url, final_url=url
            )

    assert spec.detect_async is not None
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(spec.detect_async(ctx, Native(timeout=1, retries=0, max_bytes=262144)))


def test_cancelled_native_read_is_not_a_completed_negative_detection():
    args = _args()
    spec = stage.build_docker_spec(args)
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=2375,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )

    class Native(AsyncDetectionHttp):
        async def get(self, url, **kwargs):
            raise asyncio.CancelledError

    assert spec.detect_async is not None
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(spec.detect_async(ctx, Native(timeout=1, retries=0, max_bytes=262144)))


def test_real_foreign_http_and_tls_mismatch_finish_without_a_sync_replay():
    with peer(responses={"/_ping": (404, b"foreign service")}) as (url, connections, requests):
        args = _args()
        spec = stage.build_docker_spec(args)
        ctx = AuditHookContext(
            host="127.0.0.1",
            port=urlsplit(url).port,
            args=args,
            logger=None,
            credential=AuditCredentialRun(source="anonymous"),
            phase="detect",
        )
        assert spec.detect_async is not None
        got = asyncio.run(spec.detect_async(ctx, AsyncDetectionHttp(timeout=1, retries=0, max_bytes=262144)))
        assert got.extra["is_docker"] is False
        assert len(connections) == 2
        assert requests == [("/_ping", None, None)]


def test_real_timeout_keeps_first_read_as_the_fallback_boundary():
    fixture = AsyncHttpFixture(lambda *args: response(200, "OK"), delay=lambda *args: 0.3)
    fixture.start()
    try:
        args = _args(timeout=0.1)
        spec = stage.build_docker_spec(args)
        ctx = AuditHookContext(
            host="127.0.0.1",
            port=fixture.port,
            args=args,
            logger=None,
            credential=AuditCredentialRun(source="anonymous"),
            phase="detect",
        )
        assert spec.detect_async is not None
        with pytest.raises(AsyncHttpFallback):
            asyncio.run(spec.detect_async(ctx, AsyncDetectionHttp(timeout=0.1, retries=0, max_bytes=262144)))
        assert fixture.stats["connections"] == 1
    finally:
        fixture.close()
    assert not fixture.errors
