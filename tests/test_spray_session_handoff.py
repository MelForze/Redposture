"""The whole spray producer shares one FD handoff budget, including queued jobs."""

from __future__ import annotations

import queue
import threading
import time
from types import SimpleNamespace

from redposture_core.spray_async_detect import PreparedSource
from redposture_core.targeting import ScanTargetSpec
from tests.test_http_detect_handoff import peer


def test_prepared_targets_share_budget_and_auth_context_keeps_the_owner():
    responses = {
        "/api/health": (200, b'{"database":"ok","version":"11.2.0","commit":"qa"}'),
        "/api/datasources": (401, b"{}"),
        "/api/user": (401, b"{}"),
    }
    with peer(responses=responses) as (url, _, _):
        port = int(url.rsplit(":", 1)[1])
        ns = SimpleNamespace(timeout=1, retries=0, debug=False)
        target = ScanTargetSpec("127.0.0.1", scheme="http", explicit_port=port)
        jobs = [("grafana", ns, target.host, port, target) for _ in range(24)]
        source = PreparedSource(
            jobs,
            None,
            SimpleNamespace(cancelled=threading.Event()),
            SimpleNamespace(job_finished=lambda key: False),
            limit=4,
            workers=2,
        )
        values = []
        try:
            deadline = time.monotonic() + 5
            while True:
                assert time.monotonic() < deadline
                try:
                    job, value = next(source)
                except queue.Empty:
                    time.sleep(0.005)
                    continue
                except StopIteration:
                    break
                assert value is not None
                values.append(value)
            assert len(values) == 24
            assert source._handoff_budget.active == 2
            assert all(value[2]._http_handoff_budget is source._handoff_budget for value in values)
            assert all(value[3].reuse_http and value[3].session_budget is source._handoff_budget for value in values)
            for value in values:
                source.release(value)
            assert source._handoff_budget.active == 0
        finally:
            source.close()


def test_spray_ui_detect_and_auth_share_socket_without_changing_verdict():
    import asyncio
    from dataclasses import replace
    from urllib.parse import urlsplit

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.spray_async_detect import prepare_target
    from redposture_core.stage_runtime import AuditCredentialRun
    from tests.test_async_retained_parity import normalize

    def response(url):
        path = urlsplit(url).path
        if path == "/":
            return HttpResponse(
                200,
                b'<title>Home - Mongo Express</title><img src="/public/img/mongo-express-logo.png"><a href="/db/qa/">qa</a>',
                {},
            )
        if path.endswith(".png"):
            return HttpResponse(200, b"PNG", {"Content-Type": "image/png"})
        return HttpResponse(401, b"Unauthorized", {"WWW-Authenticate": 'Basic realm="qa"'})

    with peer(responder=response) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        target = ScanTargetSpec("127.0.0.1", scheme="http", explicit_port=port, surface_hint="ui")
        results, calls, counts = [], [], []
        for optimized in (False, True):
            before, start = len(connections), len(requests)
            prepared = asyncio.run(
                prepare_target(("mongodb", SimpleNamespace(timeout=1, retries=0), target.host, port, target), None)
            )
            assert prepared is not None
            _, _, runner, ctx, detected = prepared
            try:
                auth_ctx = replace(
                    ctx,
                    reuse_http=optimized,
                    phase="auth",
                    credential=AuditCredentialRun("reader", "wrong", source="provided"),
                )
                result = runner._auth(auth_ctx, detected.record)
                assert result.extra["provided_credentials_ok"] is False
                results.append(normalize(result.to_dict()))
                calls.append(requests[start:])
                counts.append(len(connections) - before)
            finally:
                runner._close_all_lifecycle_states()
        assert results[0] == results[1]
        assert calls[0] == calls[1]
        assert counts == [2, 1]
