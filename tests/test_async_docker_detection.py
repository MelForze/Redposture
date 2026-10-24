"""Docker detector parity includes useful anonymous access and protected /info."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.docker_engine import DockerEngineClient, DockerEngineHTTPError, DockerHTTPResponse
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.modules.docker import actions, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext, _invoke_host_stage
from tests.test_stage_docker import _args


@pytest.mark.parametrize("case", ["open", "denied", "info-fallback", "negative"])
def test_docker_full_record_and_order(monkeypatch, case):
    calls = []

    def response(method, url):
        calls.append((method, url))
        path = urlsplit(url).path
        code, reason, data = 200, "Lab OK", "OK"
        if path == "/version":
            data = json.dumps({"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"})
            if case == "info-fallback":
                code, reason, data = 404, "Not Here", "{}"
        elif path == "/info":
            data = json.dumps(
                {
                    "ServerVersion": "25.0.5",
                    "ApiVersion": "1.45",
                    "Containers": 4,
                    "Images": 7,
                    "OSType": "linux",
                    "OperatingSystem": "Linux",
                }
            )
            if case == "denied":
                code, reason, data = 403, "Lab Denied", '{"message":"authorization denied"}'
        if case == "negative":
            code, reason, data = 404, "Not Here", "{}"
        return code, reason, data.encode()

    def sync(self, method, path, **kw):
        scheme = "https" if self.transport == "tls" else "http"
        url = f"{scheme}://{self.host}:{self.port}{self.base_path}{path}"
        code, reason, body = response(method, url)
        if code not in kw.get("allow_statuses", set(range(200, 300))):
            raise DockerEngineHTTPError(code, reason, body, {})
        return DockerHTTPResponse(code, reason, {}, body)

    monkeypatch.setattr(DockerEngineClient, "request", sync)
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
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
    expected = _invoke_host_stage(spec.host_stage, module="docker", ctx=ctx, run_deep_checks=False).to_dict()
    expected_calls = calls[:]
    calls.clear()

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)
        last_reason = ""

        async def close(self):
            pass

        async def get(self, url, **kw):
            code, self.last_reason, body = response("GET", url)
            return HttpResponse(code, body, {}, request_url=url, final_url=url)

    assert spec.detect is None
    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native())).to_dict()
    for rec in (expected, got):
        for key in ("elapsed_ms", "stages", "stage_durations_ms", "stage_timing_total_ms"):
            rec.pop(key, None)
    assert got == expected
    assert calls == expected_calls
