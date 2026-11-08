"""Known-answer product corpora must survive fixed concurrency changes."""

import asyncio
import contextvars
import hashlib
import ipaddress
import time
from collections import Counter
from urllib.parse import urlsplit

import pytest

from redposture_core.async_detection import AsyncDetectScheduler
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec
from tests.http_detect_fixtures import detection_response
from tests.test_async_http_timeout_retries import MODULES, make_runner


def run_corpus(module, scheduler_class=AsyncDetectScheduler, *, concurrency=4):
    """Virtualize backoff time, not product decisions or attempt budgets."""
    with pytest.MonkeyPatch.context() as patch:
        real_sleep = asyncio.sleep

        async def sleep(delay, *args, **kw):
            return await real_sleep(delay / 100 if delay >= 0.2 else delay, *args, **kw)

        patch.setattr(asyncio, "sleep", sleep)
        attempts, calls = Counter(), Counter()
        attempt = contextvars.ContextVar("accuracy_attempt", default=0)
        request_deadline = contextvars.ContextVar("accuracy_request_deadline", default=None)
        original_send = AsyncDetectionHttp._send_with_retries

        async def checked_send(self, *args, **kwargs):
            token = request_deadline.set(kwargs.get("deadline"))
            try:
                return await original_send(self, *args, **kwargs)
            finally:
                request_deadline.reset(token)

        patch.setattr(AsyncDetectionHttp, "_send_with_retries", checked_send)
        first_ip = int(ipaddress.IPv4Address("198.18.0.0"))
        public = {
            "/",
            "/api/health",
            "/version",
            "/health",
            "/api/overview",
            "/v1/agent/self",
            "/api2/json",
            "/api2/json/version",
            "/minio/health/live",
            "/api/v4/version",
        }

        async def wire(self, url, timeout, headers, **options):
            # The effective timeout is remaining deadline, so its microseconds
            # cannot match across schedules. Compare configured budgets, while
            # independently rejecting any reduction beyond elapsed wall time.
            configured_timeout = self.timeout
            deadline = request_deadline.get()
            minimum = configured_timeout if deadline is None else min(configured_timeout, deadline - time.monotonic())
            assert 0 < timeout <= configured_timeout
            assert minimum <= timeout
            parsed = urlsplit(url)
            index = int(ipaddress.IPv4Address(parsed.hostname)) - first_ip
            kind = index % 6
            calls[
                (
                    index,
                    parsed.port,
                    options.get("method", "GET"),
                    parsed.path,
                    parsed.query,
                    configured_timeout,
                    attempt.get(),
                )
            ] += 1
            await real_sleep(0.002 if index % 10 else 0.006)
            if kind == 5 or (kind == 4 and attempt.get() == 1):
                raise TimeoutError("timed out")
            if kind == 2:
                return HttpResponse(404, b"{}", {})
            if kind == 3:
                return HttpResponse(
                    200, b"<html><title>Unrelated service</title>version 1.2.3</html>", {"Content-Type": "text/html"}
                )
            answer = detection_response(module, url)
            if kind == 1 and module == "docker-registry" and parsed.path == "/v2/":
                return HttpResponse(
                    401,
                    b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                    {**answer.headers, "WWW-Authenticate": 'Basic realm="registry"'},
                )
            if kind == 1 and parsed.path not in public and answer.status != 404:
                return HttpResponse(403, b'{"error":"access denied"}', answer.headers)
            return answer

        patch.setattr(AsyncDetectionHttp, "_once", wire)

        class Runner(AuditCommandRunner):
            async def _run_async_detect_attempt(self, *args, **kw):
                # Context-local attempt identity keeps concurrent origins apart.
                identity = (args[0], args[1])
                attempts[identity] += 1
                token = attempt.set(attempts[identity])
                try:
                    return await super()._run_async_detect_attempt(*args, **kw)
                finally:
                    attempt.reset(token)

        args, spec = make_runner(module)
        runner = Runner(args=args, spec=spec, emit_line=lambda _: None)
        jobs = [(str(ipaddress.IPv4Address(first_ip + i)), spec.default_port + i % 2) for i in range(120)]
        seen = {}

        async def prepare(job):
            target = ScanTargetSpec(host=job[0], explicit_port=job[1], scheme="http")
            outcome = await runner._run_async_detect_with_state(job[0], job[1], target, None)
            assert outcome is not None, "supported response unexpectedly delegated to sync fallback"
            return outcome

        def finish(job, outcome):
            try:
                record = outcome.record
                return (
                    runner._is_detected(record),
                    record.status,
                    record.auth_required,
                    record.extra.get("version"),
                    record.extra.get("server_version"),
                    record.extra.get("error"),
                )
            finally:
                runner._close_lifecycle_state(outcome.lifecycle_state)

        options = dict(detect_workers=concurrency, deep_workers=2)
        try:
            for job, result in scheduler_class(**options).iter_completed(jobs, prepare, finish):
                assert job not in seen
                seen[job] = result
        finally:
            runner._close_all_lifecycle_states()
        expected = {job for i, job in enumerate(jobs) if i % 6 in {0, 1, 4}}
        actual = {job for job, row in seen.items() if row[0]}
        assert set(seen) == set(jobs)
        assert actual == expected, (module, expected - actual, actual - expected)
        assert {port for _, port in seen} == {spec.default_port, spec.default_port + 1}
        for i, job in enumerate(jobs):
            assert attempts[job] == (2 if i % 6 == 4 else 3 if i % 6 == 5 else 1)
            if i % 6 in {0, 1, 4} and module in {"qdrant", "kubeapi", "docker-registry"}:
                assert seen[job][2] is (i % 6 == 1)
            if i % 6 in {0, 1, 4} and module == "minio":
                assert seen[job][2] is True
        return {
            "module": module,
            "targets": len(seen),
            "found": len(actual),
            "missing": 0,
            "extra": 0,
            "duplicates": 0,
            "requests": sum(calls.values()),
            "attempts": sum(attempts.values()),
            "results_sha256": hashlib.sha256(repr(sorted(seen.items())).encode()).hexdigest(),
            "requests_sha256": hashlib.sha256(repr(sorted(calls.items())).encode()).hexdigest(),
        }


@pytest.mark.parametrize("module", MODULES)
def test_fixed_detection_preserves_product_auth_ports_and_recovery(module):
    serial = run_corpus(module, concurrency=1)
    concurrent = run_corpus(module, concurrency=8)
    assert concurrent["results_sha256"] == serial["results_sha256"]
    assert concurrent["requests_sha256"] == serial["requests_sha256"]
    assert concurrent["attempts"] == serial["attempts"]
