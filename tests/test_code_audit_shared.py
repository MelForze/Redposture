"""Regressions for shared code-audit findings, with bounded local doubles."""

from __future__ import annotations

import http.client
import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core import secret_detection, stage_spray
from redposture_core.clients import http_api
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.transport import recv_exact
from redposture_core.exporters.http_pool import HTTPConnectionPool
from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec


def _partial_response() -> http.client.HTTPResponse:
    sock = SimpleNamespace(
        makefile=lambda *a, **k: io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: close\r\n\r\npartial"
        )
    )
    response = http.client.HTTPResponse(sock)
    response.begin()
    return response


@pytest.mark.parametrize("exporter", [False, True])
def test_r1_reused_socket_receives_new_timeout(exporter: bool) -> None:
    connection = Mock()
    key = ("http", "fixture", 80)
    if exporter:
        pool: Any = HTTPConnectionPool()
        pool._idle[key] = [connection]
        pool._idle_total = 1
        acquired = pool._acquire("http", "fixture", 80, 2.5)
    else:
        pool = HttpSessionPool(timeout=1)
        pool._idle[key].append(connection)
        acquired, reused = pool._acquire(key, 2.5)
        assert reused
    assert acquired is connection
    connection.sock.settimeout.assert_called_once_with(2.5)
    pool.close()


def test_r2_exporter_rejects_short_content_length(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = HTTPConnectionPool()
    connection = Mock()
    connection.getresponse.return_value = _partial_response()
    monkeypatch.setattr(pool, "_acquire", lambda *a: connection)
    status, _body, _kind, error, truncated = pool.get("http://fixture/", 1, max_bytes=100)
    assert error is not None and "incomplete" in str(error).lower()
    assert status is None and not truncated
    pool.close()


def test_r2_direct_client_rejects_short_body_and_download(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(http_api, "_open_http_request", lambda *a, **k: _partial_response())
    client = http_api.HttpApiClient(http_api.HttpClientConfig(timeout=1, retries=0))
    response = client.get("http://fixture/")
    assert response.error and "incomplete" in response.error.lower()
    status, size, error = client.download_to_file("http://fixture/", str(tmp_path / "blob"), chunk_size=3)
    assert error and "incomplete" in error.lower()
    assert size == 7
    assert status == 0


@pytest.mark.parametrize("source", ["token_file", "_jupyter_token", "_vault_token", "_nomad_token"])
def test_r3_verified_token_file_is_explicit_for_cve(source: str) -> None:
    runner = AuditCommandRunner(
        args=SimpleNamespace(**{source: "fixture-token"}),
        spec=ModuleAuditSpec(module="jupyter", label="JUPYTER", default_port=8888),
        emit_line=lambda _: None,
    )
    assert runner._record_reports_verified_credentials({"token_valid": True})
    assert not runner._record_reports_verified_credentials({"token_valid": False})


def test_r6_fragmented_frame_avoids_immutable_prefix_copy() -> None:
    class Fragment(bytes):
        def __radd__(self, other: Any) -> bytes:
            pytest.fail("immutable prefix concatenation copies each fragmented frame")

    class Reader:
        def recv(self, size: int) -> bytes:
            return Fragment(b"x" * min(16, size))

    assert recv_exact(Reader(), 4096) == b"x" * 4096


def test_r9_candidate_inputs_are_deduplicated_before_product(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    users, passwords = tmp_path / "users", tmp_path / "passwords"
    users.write_text("one\none\ntwo\ntwo\n")
    passwords.write_text("first\nfirst\nsecond\nsecond\n")
    original = stage_spray.Candidate
    calls: list[tuple[Any, ...]] = []

    def make(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(stage_spray, "Candidate", make)
    values = stage_spray.load_candidates(
        SimpleNamespace(users=str(users), passwords=str(passwords), pairs=None, tokens=None)
    )
    assert [v.display for v in values] == ["one:first", "two:first", "one:second", "two:second"]
    assert len(calls) == 4


def test_r10_entropy_does_not_rescan_all_explicit_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    accesses = 0
    original = secret_detection.SecretMatch

    class CountedMatch:
        def __init__(self, detector: str, confidence: str, object_path: str, value: str) -> None:
            self.detector, self.confidence, self.object_path, self._value = detector, confidence, object_path, value

        @property
        def value(self) -> str:
            nonlocal accesses
            accesses += 1
            return self._value

    monkeypatch.setattr(secret_detection, "SecretMatch", CountedMatch)
    text = "\n".join(f"password=AbCd{i:010d}EfGhIjKlMnOp" for i in range(200))
    found = secret_detection._scan_text(text, "$", {"password", "high_entropy"})
    assert len(found) >= 200
    assert accesses < 4000
    monkeypatch.setattr(secret_detection, "SecretMatch", original)


def test_r5_port_expansion_does_not_rescan_every_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.stage_runtime import AuditCommandPlan
    from redposture_core.targeting import StreamingTargetPlan, stream_scan_target_specs

    plan = stream_scan_target_specs(",".join(f"host-{i}: {10000 + i % 20}".replace(" ", "") for i in range(200)))
    original = StreamingTargetPlan._spec_matches_port
    calls = 0

    def counted(self: Any, *args: Any) -> bool:
        nonlocal calls
        calls += 1
        return original(self, *args)

    monkeypatch.setattr(StreamingTargetPlan, "_spec_matches_port", counted)
    items = list(AuditCommandPlan(target_plan=plan, ports=(9999,)).iter_target_specs())
    assert len(items) == 200
    assert len({(x[1], x[2]) for x in items}) == 200
    assert calls < 1000


def test_r4_paused_jobs_release_workers_and_keep_context() -> None:
    import time
    from contextvars import ContextVar

    from redposture_core.scheduler import BoundedScheduler

    local: ContextVar[int] = ContextVar("audit-job", default=-1)
    starts: list[int] = []
    finishes: list[int] = []

    def work(item: int) -> Any:
        local.set(item)
        starts.append(item)
        yield 0.03
        assert len(starts) == 4
        assert local.get() == item
        finishes.append(item)
        return item

    scheduler: Any = BoundedScheduler(max_workers=2, max_inflight=4)
    now = time.monotonic()
    values = list(scheduler.iter_paused(range(4), work))
    assert sorted(value for _, value in values) == [0, 1, 2, 3]
    assert len(finishes) == 4 and time.monotonic() - now < 1


def test_r7_exporter_first_output_precedes_unrelated_slow_preflight() -> None:
    import threading
    from contextlib import nullcontext

    from redposture_core.exporters.collect import collect_exporter_debug_data

    first = threading.Event()
    was_live: list[bool] = []

    def plan(host: str, _exporter: str, port: int, endpoints: tuple[str, ...], *args: Any) -> Any:
        if host == "slow":
            was_live.append(first.wait(0.2))
        record = dict(
            timestamp="fixture",
            host=host,
            exporter="fixture",
            port=port,
            endpoint="/metrics",
            url="http://" + host,
            ok=True,
            status=200,
            elapsed_ms=0,
            content_type="text/plain",
            error=None,
            truncated=False,
            body="fixture",
        )
        return endpoints, {"/metrics": (record, True)}

    class Pool:
        def __init__(self, **kwargs: Any) -> None:
            pass

    count, success = collect_exporter_debug_data(
        None,
        ["fast", "slow"],
        1,
        None,
        emit_line=lambda _: first.set(),
        workers=2,
        collect_exporters=[dict(name="fixture", port=9000)],
        collect_debug_endpoints=["/metrics"],
        plan_collect_fn=plan,
        pool_cls=Pool,
        activate_pool_fn=lambda _: nullcontext(),
        emit_summary=False,
    )
    assert count == success == 2
    assert was_live == [True]


def test_r9_large_product_is_lazy_and_preserves_pair_token_indices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users, passwords, pairs, tokens = (tmp_path / name for name in ("users", "passwords", "pairs", "tokens"))
    users.write_text("\n".join(f"u{i}" for i in range(100)))
    passwords.write_text("\n".join(f"p{i}" for i in range(100)))
    pairs.write_text("u0:p0\nu99:p99\nu0:p0\ncustom:pair\n")
    tokens.write_text("tok\ntok\n")
    original = stage_spray.Candidate
    calls = 0

    def make(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(stage_spray, "Candidate", make)
    candidates = stage_spray.load_candidates(
        SimpleNamespace(users=str(users), passwords=str(passwords), pairs=str(pairs), tokens=str(tokens))
    )
    assert len(candidates) == 10002
    assert calls < 10
    assert [candidates[i].display for i in (0, 1, 2, 3, -2, -1)] == [
        "u0:p0",
        "u99:p99",
        "custom:pair",
        "u1:p0",
        "u98:p99",
        "tok",
    ]
    assert len({x.display for x in candidates}) == len(candidates)


def test_r4_spray_stage_detects_other_origins_while_accounts_wait(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.cli_args import parse_args

    starts: set[str] = set()
    verified: list[tuple[str, str]] = []

    def detect(ctx: Any) -> AuditRecord:
        starts.add(ctx.host)
        return AuditRecord.from_mapping(
            dict(host=ctx.host, port=3000, is_grafana=True, status="auth_required", auth_required=True)
        )

    def auth(ctx: Any, prior: AuditRecord) -> AuditRecord:
        if ctx.credential.password == "second":
            assert len(starts) == 4
        verified.append((ctx.host, ctx.credential.password))
        return AuditRecord.from_mapping(
            {**prior.to_dict(), "status": "invalid_credentials", "provided_credentials_ok": False}
        )

    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=3000,
        detect=detect,
        auth=auth,
        is_detected=lambda r: r.extra.get("is_grafana") is True,
    )
    from redposture_core.modules.grafana.stage import build_grafana_plan

    monkeypatch.setattr(
        stage_spray,
        "importlib",
        SimpleNamespace(
            import_module=lambda _: SimpleNamespace(
                build_grafana_spec=lambda ns: spec, build_grafana_plan=build_grafana_plan
            )
        ),
    )
    passwords = tmp_path / "passwords"
    passwords.write_text("first\nsecond\n")
    output = tmp_path / "spray.txt"
    args = parse_args(
        [
            "spray",
            "-t",
            ",".join(f"host-{i}:3000" for i in range(4)),
            "--modules",
            "grafana",
            "-u",
            "qa",
            "-p",
            str(passwords),
            "-w",
            "2",
            "--origin-rate",
            "10000",
            "--account-interval",
            "0.03",
            "--no-color",
            "-o",
            str(output),
        ]
    )
    assert stage_spray.run_spray_stage(args, None) == 0
    assert len(starts) == 4 and len(verified) == 8
    assert "\x1b" not in output.read_text()


def test_cooperative_rate_checks_actual_dispatch_after_delayed_wakeup(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1.0]
    monkeypatch.setattr(stage_spray.time, "monotonic", lambda: clock[0])
    gate: Any = stage_spray.RateGate(10, 1)
    assert gate.reserve("origin", "account") == (True, 0)
    clock[0] = 5.0  # A congested worker started much later than the reservation.
    assert gate.claim("origin", "account") == 0
    assert gate.claim("origin", "account") == 1
    clock[0] = 6.0
    assert gate.claim("origin", "account") == 0


def test_paused_cancel_closes_idle_context_and_propagates_failure() -> None:
    import threading

    from redposture_core.scheduler import BoundedScheduler

    cancelled = threading.Event()
    closed: list[str] = []

    def waiting(item: int) -> Any:
        try:
            yield 10
        finally:
            closed.append("closed")

    scheduler: Any = BoundedScheduler(max_workers=1)
    assert list(scheduler.iter_paused([], waiting)) == []
    cancelled.set()
    assert list(scheduler.iter_paused([1], waiting, cancelled=cancelled)) == []

    def fail(item: int) -> Any:
        yield 0
        raise ValueError("fixture failure")

    with pytest.raises(ValueError, match="fixture failure"):
        list(scheduler.iter_paused([1], fail))

    def one_done(item: int) -> Any:
        try:
            if item == 1:
                yield 0.03
                return "first"
            yield 10
        finally:
            closed.append(str(item))

    results = scheduler.iter_paused([1, 2], one_done)
    assert next(results) == (1, "first")
    results.close()
    assert "2" in closed


def test_expanding_scheduler_propagates_worker_and_child_errors() -> None:
    from redposture_core.scheduler import BoundedScheduler

    scheduler: Any = BoundedScheduler(max_workers=1)
    assert list(scheduler.iter_expanding([], lambda x: x, lambda x, r: ())) == []

    def fail(_item: Any) -> Any:
        raise ValueError("worker failure")

    with pytest.raises(ValueError, match="worker failure"):
        list(scheduler.iter_expanding([1], fail, lambda x, r: ()))

    def bad_child(_item: Any, _result: Any) -> Any:
        raise ValueError("child failure")

    with pytest.raises(ValueError, match="child failure"):
        list(scheduler.iter_expanding([1], lambda x: x, bad_child))


def test_r2_http_error_framing_is_not_a_trustworthy_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    response = _partial_response()
    error = urllib.error.HTTPError("http://fixture/", 401, "Unauthorized", response.headers, response)

    def open_error(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(http_api, "_open_http_request", open_error)
    result = http_api.HttpApiClient(http_api.HttpClientConfig(retries=0)).get("http://fixture/")
    assert result.error and "incomplete" in result.error


def test_paused_cancel_closes_an_active_job_if_it_later_yields() -> None:
    import threading

    from redposture_core.scheduler import BoundedScheduler

    entered, release, cancelled, closed = (threading.Event() for _ in range(4))
    retained: list[Any] = []

    def generator() -> Any:
        try:
            entered.set()
            assert release.wait(1)
            yield 10
        finally:
            closed.set()

    def worker(item: Any) -> Any:
        job = generator()
        retained.append(job)
        return job

    scheduler: Any = BoundedScheduler(max_workers=1)
    runner = threading.Thread(target=lambda: list(scheduler.iter_paused([1], worker, cancelled=cancelled)))
    try:
        runner.start()
        assert entered.wait(1)
        cancelled.set()
        runner.join(1)
        assert not runner.is_alive()
        release.set()
        assert closed.wait(1)
    finally:
        release.set()
        runner.join(1)
        for job in retained:
            if job.gi_frame is not None and not job.gi_running:
                job.close()


def test_r2_manual_proxy_parser_enforces_framing_with_head_and_cap_controls() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\npartial"
    with pytest.raises(ConnectionError, match="incomplete"):
        http_api._parse_http_response_bytes_detailed(raw, response_cap=100)
    assert http_api._parse_http_response_bytes_detailed(raw, response_cap=3)[3] is True
    assert http_api._parse_http_response_bytes_detailed(raw, response_cap=100, method="HEAD")[0] == 200


def test_paused_cleanup_attempts_every_idle_generator_after_one_close_error() -> None:
    from redposture_core.scheduler import BoundedScheduler

    closed: list[int] = []
    held: list[Any] = []

    def job(item: int) -> Any:
        try:
            yield 0.05 if item == 0 else 10
            return item
        finally:
            closed.append(item)
            if item == 1:
                raise RuntimeError("fixture close failure")

    def worker(item: int) -> Any:
        generator = job(item)
        held.append(generator)
        return generator

    scheduler: Any = BoundedScheduler(max_workers=1, max_inflight=3)
    results = scheduler.iter_paused([0, 1, 2], worker)
    assert next(results) == (0, 0)
    try:
        with pytest.raises(RuntimeError, match="fixture close failure"):
            results.close()
        assert set(closed) == {0, 1, 2}
        assert all(g.gi_frame is None for g in held)
    finally:
        for g in held:
            if g.gi_frame is not None:
                g.close()
