from __future__ import annotations

import resource
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.elastic import stage as elastic_stage
from redposture_core.progress import ProgressBar
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandResult,
    AuditCommandRunner,
    ModuleAuditSpec,
)


def test_parse_args_tracks_explicit_network_option_provenance() -> None:
    defaults = parse_args(["elastic", "-t", "192.0.2.10"])
    assert defaults._workers_option_provided is False
    assert defaults._retries_option_provided is False
    assert defaults._timeout_option_provided is False

    explicit = parse_args(
        [
            "elastic",
            "-t",
            "192.0.2.10",
            "-w125",
            "--retries=2",
            "--timeout",
            "3",
        ]
    )
    assert explicit._workers_option_provided is True
    assert explicit._retries_option_provided is True
    assert explicit._timeout_option_provided is True


def test_elastic_bare_defaults_and_explicit_additive_ports_are_preserved() -> None:
    bare_plan = elastic_stage.build_elastic_plan(parse_args(["elastic", "-t", "192.0.2.10"]))
    assert bare_plan.ports == (9200, 19200, 29200)
    assert [(host, port) for _idx, host, port in bare_plan.iter_targets()] == [
        ("192.0.2.10", 9200),
        ("192.0.2.10", 19200),
        ("192.0.2.10", 29200),
    ]

    target_port_plan = elastic_stage.build_elastic_plan(parse_args(["elastic", "-t", "192.0.2.10:29200"]))
    assert [(host, port) for _idx, host, port in target_port_plan.iter_targets()] == [("192.0.2.10", 29200)]
    assert elastic_stage._effective_plan_ports(target_port_plan) == (29200,)

    additive_plan = elastic_stage.build_elastic_plan(
        parse_args(["elastic", "-t", "192.0.2.10:19200", "--port", "9300"])
    )
    assert {(host, port) for _idx, host, port in additive_plan.iter_targets()} == {
        ("192.0.2.10", 19200),
        ("192.0.2.10", 9300),
    }


def test_mass_profile_applies_only_to_implicit_cli_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(elastic_stage, "_safe_mass_worker_limit", lambda ceiling: min(123, ceiling))
    small_args = parse_args(["elastic", "-t", "192.0.2.10"])
    small_plan = elastic_stage.build_elastic_plan(small_args)
    assert small_plan.workers == 50
    assert small_args.retries == 0
    assert small_args._elastic_effective_profile["automatic_fields"] == ("retries",)

    args = parse_args(["elastic", "-t", "10.0.0.0/18"])

    plan = elastic_stage.build_elastic_plan(args)

    assert plan.target_count >= 10_000
    assert plan.workers == 123
    assert args.workers == 123
    assert args.retries == 0
    assert args.timeout == 1.0
    assert args._elastic_effective_profile["automatic_fields"] == ("workers", "retries", "timeout")

    explicit_args = parse_args(
        [
            "elastic",
            "-t",
            "10.0.0.0/18",
            "--workers",
            "17",
            "--retries",
            "2",
            "--timeout",
            "4",
        ]
    )
    explicit_plan = elastic_stage.build_elastic_plan(explicit_args)
    assert explicit_plan.workers == 17
    assert explicit_args.retries == 2
    assert explicit_args.timeout == 4.0
    assert explicit_args._elastic_effective_profile["automatic_fields"] == ()


def test_programmatic_args_without_provenance_do_not_enable_mass_profile() -> None:
    args = parse_args(["elastic", "-t", "10.0.0.0/18"])
    del args._workers_option_provided
    del args._retries_option_provided
    del args._timeout_option_provided
    args.workers = 19
    args.retries = 4
    args.timeout = 2.5

    plan = elastic_stage.build_elastic_plan(args)

    assert plan.workers == 19
    assert args.retries == 4
    assert args.timeout == 2.5
    assert args._elastic_effective_profile["automatic_fields"] == ()


def test_mass_profile_proxy_cap_and_safe_fd_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    ceilings: list[int] = []
    real_safe_limit = elastic_stage._safe_mass_worker_limit

    def fake_safe_limit(ceiling: int) -> int:
        ceilings.append(ceiling)
        return ceiling

    monkeypatch.setattr(elastic_stage, "_safe_mass_worker_limit", fake_safe_limit)
    args = parse_args(
        [
            "elastic",
            "-t",
            "10.0.0.0/18",
            "--proxy",
            "http://127.0.0.1:8080",
        ]
    )
    plan = elastic_stage.build_elastic_plan(args)
    assert ceilings == [64]
    assert plan.workers == 64

    monkeypatch.setattr(resource, "getrlimit", lambda _kind: (256, 256))
    assert real_safe_limit(200) == 96


def test_exact_90k_synthetic_plan_uses_bounded_mass_profile_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = parse_args(["elastic", "-t", "synthetic.invalid"])
    synthetic_plan = AuditCommandPlan(
        targets_by_port={9200: ("synthetic.invalid",) * 90_000},
        ports=(9200,),
        workers=args.workers,
    )
    monkeypatch.setattr(elastic_stage, "_safe_mass_worker_limit", lambda ceiling: ceiling)

    profiled_plan = elastic_stage._apply_elastic_mass_profile(args, synthetic_plan)

    assert profiled_plan.target_count == 90_000
    assert profiled_plan.workers == 200
    assert profiled_plan.workers <= elastic_stage._MASS_PROFILE_MAX_WORKERS
    assert args.retries == 0
    assert args.timeout == 1.0
    assert args._elastic_effective_profile["endpoint_count"] == 90_000

    # Exercise retention accounting without iterating the synthetic targets or
    # invoking a detect hook: an empty window stream represents a dry runtime.
    monkeypatch.setattr(AuditCommandPlan, "iter_target_windows", lambda _self, _window_size=None: iter(()))
    emitted: list[str] = []
    result = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=emitted.append,
    ).run_plan(profiled_plan)

    assert result.record_count == 0
    assert result.records == []
    assert result.typed_records == []
    assert result.record_retention_truncated is True
    assert len(emitted) == 1
    assert "90000 target(s)" in emitted[0]


def test_elastic_spec_opts_into_bounded_retention_and_throttled_progress() -> None:
    spec = elastic_stage.build_elastic_spec(SimpleNamespace())
    assert spec.record_retention_limit == 9_999
    assert spec.progress_refresh_interval_s == 0.1


def test_module_record_retention_limit_keeps_counts_and_streaming_output() -> None:
    emitted: list[str] = []
    callback_hosts: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_demo",
            extra={"is_demo": False},
        )

    runner = AuditCommandRunner(
        args=SimpleNamespace(
            debug=False,
            timeout=1.0,
            retries=0,
            workers=1,
            record_callback=lambda record: callback_hosts.append(str(record["host"])),
        ),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=9200,
            detect=detect,
            render=lambda record: (f"{record.host}:{record.port}",),
            record_retention_limit=1,
        ),
        emit_line=emitted.append,
    )
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("one.example", "two.example")},
            ports=(9200,),
            workers=1,
        )
    )

    assert result.record_count == 2
    assert result.records == []
    assert result.typed_records == []
    assert result.record_retention_truncated is True
    assert emitted == ["one.example:9200", "two.example:9200"]
    assert callback_hosts == ["one.example", "two.example"]


def test_progress_refresh_throttles_intermediate_renders_but_forces_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core import progress as progress_module

    class FakeStream:
        def __init__(self) -> None:
            self.buffer = ""

        def isatty(self) -> bool:
            return True

        def write(self, text: str) -> int:
            self.buffer += text
            return len(text)

        def flush(self) -> None:
            return None

    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    stream = FakeStream()
    bar = ProgressBar(
        "elastic",
        total=3,
        enabled=True,
        stream=stream,
        leave=True,
        refresh_interval_s=0.1,
    )

    now[0] = 0.01
    bar.advance()
    assert stream.buffer == ""

    now[0] = 0.11
    bar.advance()
    intermediate = stream.buffer
    assert "67%" in intermediate

    now[0] = 0.12
    bar.advance()
    assert len(stream.buffer) > len(intermediate)
    assert "100%" in stream.buffer
    assert bar._done == 3
    bar.close()


def test_progress_refresh_also_throttles_resume_after_streamed_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core import progress as progress_module

    class FakeStream:
        def __init__(self) -> None:
            self.buffer = ""

        def isatty(self) -> bool:
            return True

        def write(self, text: str) -> int:
            self.buffer += text
            return len(text)

        def flush(self) -> None:
            return None

    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    stream = FakeStream()
    bar = ProgressBar(
        "elastic",
        total=3,
        enabled=True,
        stream=stream,
        leave=True,
        render_initial=True,
        refresh_interval_s=0.1,
    )

    now[0] = 0.01
    assert bar.begin_output() is True
    after_pause = len(stream.buffer)
    bar.end_output()
    assert len(stream.buffer) == after_pause

    now[0] = 0.11
    assert bar.begin_output() is True
    after_second_pause = len(stream.buffer)
    bar.end_output()
    assert len(stream.buffer) > after_second_pause
    bar.close()


def test_debug_emits_effective_mass_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []

    class FakeConsole:
        def __init__(self, *, debug: bool) -> None:
            assert debug is True

        def set_structured_output(self, _enabled: bool) -> None:
            return None

        def info(self, message: str) -> None:
            messages.append(message)

        def warn(self, message: str) -> None:
            messages.append(message)

        def error(self, message: str) -> None:
            messages.append(message)

    monkeypatch.setattr(elastic_stage, "Console", FakeConsole)
    monkeypatch.setattr(elastic_stage, "_safe_mass_worker_limit", lambda _ceiling: 120)
    monkeypatch.setattr(
        elastic_stage.AuditCommandRunner,
        "run_plan",
        lambda _self, _plan: AuditCommandResult(
            records=[],
            detected_count=1,
            emitted_lines=0,
            typed_records=[],
        ),
    )
    args = parse_args(["elastic", "-d", "-t", "10.0.0.0/18"])

    assert elastic_stage.run_elastic_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 0
    profile_lines = [message for message in messages if message.startswith("elastic effective profile:")]
    assert len(profile_lines) == 1
    assert "endpoints=" in profile_lines[0]
    assert "ports=9200,19200,29200" in profile_lines[0]
    assert "workers=120" in profile_lines[0]
    assert "retries=0" in profile_lines[0]
    assert "automatic=workers,retries,timeout" in profile_lines[0]
