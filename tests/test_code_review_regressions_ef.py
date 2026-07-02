"""Regression tests for the E/F code-review batches (stage_runtime core + CLI/packaging).

E1  — BoundedScheduler shuts the executor down on worker exceptions
E2  — Password-only credentials propagate to host_stage instead of the raw arg
E3  — Anonymous open_no_auth fast-path is opt-in per module (kafka + spec flag)
E4  — AuditRecord.from_mapping annotates missing-port records
E5  — render_with_plan absorbs render exceptions without aborting the scan
E6  — retain_records=False emits a debug marker
E7  — build_render_plan falls back to `dir()` when __all__ is missing
E8  — attempted_credentials mutation no longer poisons the shared detect record
E9  — cached AuditConfig invalidates when args-derived sentinel changes
F1  — main() traps KeyboardInterrupt and returns 130
F2  — ProgressBar honors is_console_no_color()
F3  — Elastic accepts long --username/--password
F4  — --log tee opens before proxy parsing
F5  — Kafka --max-messages 0 rejected at parse time
F6  — exporters trigger --listen-seconds 0 rejected at parse time
F7  — cfg.token falls back to module-specific dests (pve_api_token/api_key/apitoken)
F8  — AuditConfig timeout=0.0 preserved (not silently upgraded to 5.0)
F9  — --save alias accepted by every module (postgres/mongo/docker/oracle aligned)
F10 — --log file starts each run with a "===== redposture run start ..." separator
"""

from __future__ import annotations

import argparse
import io
import threading
import time
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# E1 — BoundedScheduler cancels + shuts down on worker exceptions
# ---------------------------------------------------------------------------


def test_fix_e1_scheduler_iter_completed_shuts_down_on_worker_exception() -> None:
    """When a worker raises, iter_completed must still shutdown the executor
    (no leaked pool of daemon threads hammering the network in the background).
    """
    from redposture_core.scheduler import BoundedScheduler

    # Snapshot pre-existing ThreadPoolExecutor threads — an earlier test in the
    # suite may have left one alive; we only care about NEW leaks introduced
    # by this particular iter_completed call.
    baseline = {t.ident for t in threading.enumerate() if t.name.startswith("ThreadPoolExecutor")}

    scheduler: BoundedScheduler[int, int] = BoundedScheduler(max_workers=2)

    def _boom(x: int) -> int:
        if x == 1:
            raise ValueError("worker crashed")
        return x

    with pytest.raises(ValueError, match="worker crashed"):
        for _ in scheduler.iter_completed([0, 1, 2, 3, 4], _boom):
            pass

    # Give any leaked threads a chance to have surfaced.
    time.sleep(0.1)
    new_workers = [
        t
        for t in threading.enumerate()
        if t.name.startswith("ThreadPoolExecutor") and t.ident not in baseline and t.is_alive()
    ]
    assert not new_workers, (
        f"iter_completed leaked ThreadPoolExecutor workers on exception: {[t.name for t in new_workers]}"
    )


# ---------------------------------------------------------------------------
# E2 — Password-only credential
# ---------------------------------------------------------------------------


def test_fix_e2_password_only_credential_flows_through() -> None:
    """`credential.password` must reach host_stage even when
    `credential.username` is None (Redis AUTH-with-token, Kafka SASL/PLAIN)."""
    from redposture_core.audit_config import AuditConfig
    from redposture_core.stage_runtime import (
        AuditCredentialRun,
        AuditHookContext,
        _argument_value_for_hook,
    )

    cred = AuditCredentialRun(username=None, password="real-password", source="file")
    ctx = AuditHookContext(
        args=SimpleNamespace(),
        logger=None,
        host="127.0.0.1",
        port=6379,
        credential=cred,
    )
    cfg = AuditConfig(username=None, password="the-file-path.txt")

    got = _argument_value_for_hook("password", ctx, cfg)
    assert got == "real-password", "password-only credentials still fell back to cfg.password (the raw arg)"


# ---------------------------------------------------------------------------
# E3 — Anonymous open_no_auth fast-path is opt-in
# ---------------------------------------------------------------------------


def test_fix_e3_open_no_auth_fast_path_opt_in() -> None:
    """The G-batch extended E3 to more modules. Every audit module whose
    detect probe genuinely confirms "no credentials needed" (redis/docker/
    elastic/clickhouse/grpc/mongodb/postgres/qdrant/etcd/registry/zookeeper/
    kubeapi) opts in. Kafka keeps its hardcoded shortcut. Consul/proxmox/
    gitlab/oracle stay opted out — their auth model doesn't have a clean
    'anonymous' probe that guarantees future creds would be redundant."""
    from redposture_core.modules.clickhouse.stage import build_clickhouse_spec
    from redposture_core.modules.docker.stage import build_docker_spec
    from redposture_core.modules.elastic.stage import build_elastic_spec
    from redposture_core.modules.etcd.stage import build_etcd_spec
    from redposture_core.modules.grpc.stage import build_grpc_spec
    from redposture_core.modules.kubeapi.stage import build_kubeapi_spec
    from redposture_core.modules.mongodb.stage import build_mongodb_spec
    from redposture_core.modules.postgres.stage import build_postgres_spec
    from redposture_core.modules.qdrant.stage import build_qdrant_spec
    from redposture_core.modules.redis.stage import build_redis_spec
    from redposture_core.modules.registry.stage import build_registry_spec
    from redposture_core.modules.zookeeper.stage import build_zookeeper_spec

    for build in (
        build_redis_spec,
        build_docker_spec,
        build_elastic_spec,
        build_clickhouse_spec,
        build_grpc_spec,
        build_mongodb_spec,
        build_postgres_spec,
        build_qdrant_spec,
        build_etcd_spec,
        build_registry_spec,
        build_zookeeper_spec,
        build_kubeapi_spec,
    ):
        spec = build(SimpleNamespace())
        assert spec.keep_anonymous_open_no_auth is True, (
            f"{build.__name__} spec did not opt in to keep_anonymous_open_no_auth"
        )

    # Consul/proxmox stay opted OUT to avoid breaking their token-based flows.
    from redposture_core.modules.consul.stage import build_consul_spec
    from redposture_core.modules.proxmox.stage import build_proxmox_spec

    assert getattr(build_consul_spec(SimpleNamespace()), "keep_anonymous_open_no_auth", False) is False
    assert getattr(build_proxmox_spec(SimpleNamespace()), "keep_anonymous_open_no_auth", False) is False


# ---------------------------------------------------------------------------
# E4 — AuditRecord.from_mapping annotates missing-port records
# ---------------------------------------------------------------------------


def test_fix_e4_audit_record_missing_port_marks_extra() -> None:
    """A payload without a `port` should be annotated (was silently → 0)."""
    from redposture_core.audit_models import AuditRecord

    record = AuditRecord.from_mapping({"host": "1.2.3.4", "status": "ok"}, module="mymod")
    assert record.port == 0  # coercion preserved
    assert record.extra.get("port_missing_marker", "").startswith("module=mymod"), (
        "missing-port record was not annotated in extra"
    )


# ---------------------------------------------------------------------------
# E5 — render_with_plan absorbs render exceptions
# ---------------------------------------------------------------------------


def test_fix_e5_render_with_plan_absorbs_summary_exception() -> None:
    """A broken _format_record used to bring down the whole scan loop."""
    from redposture_core.stage_runtime import RenderPlan, render_with_plan

    def _broken_summary(record: dict, _format: str) -> str:
        raise KeyError("expected_field")

    plan = RenderPlan(detect=None, summary=_broken_summary, details=())
    lines = render_with_plan(plan, {"host": "x", "port": 1}, "txt")
    assert lines, "render must still produce a marker line"
    assert "render summary failed" in lines[0]


def test_fix_e5_render_with_plan_absorbs_detail_exception() -> None:
    from redposture_core.stage_runtime import RenderPlan, render_with_plan

    def _broken_detail(record: dict, _format: str) -> list[str]:
        raise AttributeError("record.foo")

    def _summary(record: dict, _format: str) -> str:
        return "OK"

    plan = RenderPlan(detect=None, summary=_summary, details=((_broken_detail, False),))
    lines = render_with_plan(plan, {"host": "x", "port": 1}, "txt")
    assert "OK" in lines
    assert any("render detail" in line and "AttributeError" in line for line in lines)


# ---------------------------------------------------------------------------
# E6 — retain_records=False debug marker
# ---------------------------------------------------------------------------


def test_fix_e6_retain_records_disabled_emits_debug_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import stage_runtime

    events: list[str] = []

    class _FakePlan:
        target_count = stage_runtime.DEFAULT_RECORD_RETENTION_LIMIT + 10
        output_format = "txt"
        output_path = None
        append = False
        workers = 1
        fallback_target_count = 0
        credential_runs = (stage_runtime.AuditCredentialRun(source="anonymous"),)

        def iter_target_windows(self):
            return iter([])

    class _FakeSpec:
        module = "test"
        label = "TEST"
        default_port = 1
        host_stage = None
        render = None
        render_module = None
        colorize = None
        detect = None
        auth = None
        capabilities = None
        data = None
        is_detected = None
        deep_gate = None
        keep_anonymous_open_no_auth = False

    args = argparse.Namespace(
        debug_emit=events.append,
        debug=True,
        timeout=1.0,
        retries=0,
        workers=1,
    )
    runner = stage_runtime.AuditCommandRunner(args=args, spec=_FakeSpec(), console=None)
    runner.run_plan(_FakePlan())
    assert any("record retention disabled" in event for event in events), f"E6 marker not emitted; events={events!r}"


# ---------------------------------------------------------------------------
# E7 — build_render_plan fallback without __all__
# ---------------------------------------------------------------------------


def test_fix_e7_build_render_plan_falls_back_to_dir_without_all() -> None:
    from redposture_core.stage_runtime import build_render_plan

    class _RenderMod:
        pass

    def _format_detect_record(record, output_format):
        return "detect"

    def _format_record(record, output_format):
        return "summary"

    def _format_things_records(record, output_format):
        return ["thing 1", "thing 2"]

    mod = _RenderMod()
    mod._format_detect_record = _format_detect_record
    mod._format_record = _format_record
    mod._format_things_records = _format_things_records
    # Deliberately DO NOT set __all__.

    plan = build_render_plan(mod)
    # The detail renderer must still be picked up.
    assert plan.details, "detail renderer was silently dropped when __all__ was missing"
    assert plan.details[0][0] is _format_things_records


# ---------------------------------------------------------------------------
# E8 — attempted_credentials mutation isolation
# ---------------------------------------------------------------------------


def test_fix_e8_attempted_credentials_does_not_mutate_shared_detect_record() -> None:
    """When _run_deep_lifecycle needs to attach attempted_credentials to a
    selected_record that IS the detect record, it must copy (dataclasses.replace)
    instead of mutating the shared record's extra dict."""
    import dataclasses as _dc

    from redposture_core.audit_models import AuditRecord

    original = AuditRecord(host="x", port=1, service="s", status="auth_required", extra={})
    updated = _dc.replace(original, extra={**original.extra, "attempted_credentials": [{"u": "root"}]})
    assert original.extra == {}, "shared detect record was mutated instead of copied"
    assert updated.extra.get("attempted_credentials") == [{"u": "root"}]


# ---------------------------------------------------------------------------
# E9 — cached AuditConfig invalidation on sentinel change
# ---------------------------------------------------------------------------


def test_fix_e9_cached_audit_config_invalidates_when_args_change(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import stage_runtime

    build_calls = {"n": 0}
    real_from_namespace = stage_runtime.AuditConfig.from_namespace

    def _counting(ns):
        build_calls["n"] += 1
        return real_from_namespace(ns)

    monkeypatch.setattr(stage_runtime.AuditConfig, "from_namespace", _counting)

    args = argparse.Namespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="txt",
        username=None,
        password=None,
        defcreds=False,
    )

    def _hook(host, port, timeout, retries):
        return {"host": host, "port": port, "status": "ok"}

    ctx = stage_runtime.AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=1,
        credential=stage_runtime.AuditCredentialRun(source="anonymous"),
    )

    stage_runtime._invoke_host_stage(_hook, module="m", ctx=ctx, run_deep_checks=True)
    first = build_calls["n"]
    stage_runtime._invoke_host_stage(_hook, module="m", ctx=ctx, run_deep_checks=True)
    assert build_calls["n"] == first, "cached cfg should NOT rebuild without sentinel change"

    # Mutate a sentinel field.
    args.timeout = 2.0
    stage_runtime._invoke_host_stage(_hook, module="m", ctx=ctx, run_deep_checks=True)
    assert build_calls["n"] == first + 1, "cached cfg did not invalidate when args.timeout changed"


# ---------------------------------------------------------------------------
# F1 — main() KeyboardInterrupt handler
# ---------------------------------------------------------------------------


def test_fix_f1_main_traps_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from redposture_core import cli

    # Point every side-effectful helper at a no-op stub so we can drive main().
    monkeypatch.setattr(
        cli,
        "parse_args",
        lambda _argv: argparse.Namespace(
            no_color=True,
            log="",
            proxy="",
            command="redis",
            _cached_audit_config=None,
        ),
    )
    monkeypatch.setattr(cli, "AttemptLogger", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "CommandProgressOwner", lambda enabled=True: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "RuntimeNetworkConfig", SimpleNamespace(from_args=lambda *_a, **_kw: None))

    class _ProxyCtx:
        def __enter__(self):
            raise KeyboardInterrupt

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(cli, "proxy_socket_context", lambda _cfg: _ProxyCtx())

    rc = cli.main(["redis", "-t", "127.0.0.1"])
    assert rc == 130
    assert "interrupted by user" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# F2 — ProgressBar honors is_console_no_color
# ---------------------------------------------------------------------------


def test_fix_f2_progress_bar_omits_ansi_when_no_color_set(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import console as console_mod
    from redposture_core import progress as progress_mod

    console_mod.set_console_no_color(True)
    try:
        bar = progress_mod.ProgressBar("SCAN", 10, stream=io.StringIO())
        bar._done = 5
        line = bar._line()
        assert "\x1b[" not in line, f"progress line still contains ANSI escapes: {line!r}"
    finally:
        console_mod.set_console_no_color(False)

    # Sanity: without no_color set, the same call DOES include ANSI escapes.
    bar2 = progress_mod.ProgressBar("SCAN", 10, stream=io.StringIO())
    bar2._done = 5
    assert "\x1b[" in bar2._line()


# ---------------------------------------------------------------------------
# F3 — Elastic --username/--password long options
# ---------------------------------------------------------------------------


def test_fix_f3_elastic_accepts_long_username_and_password() -> None:
    from redposture_core.cli_args import parse_args

    args = parse_args(
        [
            "elastic",
            "-t",
            "es.local:9200",
            "--username",
            "elastic",
            "--password",
            "changeme",
        ]
    )
    assert args.username == "elastic"
    assert args.password == "changeme"


# ---------------------------------------------------------------------------
# F4 — --log tee opens before proxy parsing
# ---------------------------------------------------------------------------


def test_fix_f4_log_tee_opens_before_proxy_parsing(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import cli

    log_path = tmp_path / "audit.log"

    monkeypatch.setattr(
        cli,
        "parse_args",
        lambda _argv: argparse.Namespace(
            no_color=True,
            log=str(log_path),
            proxy="garbage://not-real",
            command="redis",
        ),
    )
    monkeypatch.setattr(cli, "AttemptLogger", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "CommandProgressOwner", lambda enabled=True: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "RuntimeNetworkConfig", SimpleNamespace(from_args=lambda *_a, **_kw: None))

    # Make proxy parsing fail — its stderr must land INSIDE the log file now.
    monkeypatch.setattr(cli, "parse_proxy_config", lambda _raw: (None, "invalid proxy"))

    rc = cli.main(["redis"])
    assert rc == 2
    log_contents = log_path.read_text(encoding="utf-8")
    assert "failed to parse --proxy" in log_contents, (
        f"proxy error missed the --log tee; log contents: {log_contents!r}"
    )


# ---------------------------------------------------------------------------
# F5 — Kafka --max-messages 0 rejected
# ---------------------------------------------------------------------------


def test_fix_f5_kafka_max_messages_zero_rejected_at_parse() -> None:
    from redposture_core.cli_args import parse_args

    with pytest.raises(SystemExit) as exc:
        parse_args(["kafka", "-t", "127.0.0.1", "--max-messages", "0"])
    assert exc.value.code == 2


def test_fix_f5_kafka_max_messages_negative_rejected_at_parse() -> None:
    from redposture_core.cli_args import parse_args

    with pytest.raises(SystemExit) as exc:
        parse_args(["kafka", "-t", "127.0.0.1", "--max-messages", "-3"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# F6 — exporters trigger --listen-seconds 0 rejected
# ---------------------------------------------------------------------------


def test_fix_f6_listen_seconds_zero_rejected_at_parse() -> None:
    from redposture_core.cli_args import parse_args

    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "trigger", "-t", "10.0.0.0/24", "--listen-seconds", "0"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# F7 — cfg.token fallback picks up module-specific dests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("attr_name", "expected"),
    [
        ("token", "token-classic"),
        ("api_token", "api-token-classic"),
        ("apitoken", "elastic-api-token"),
        ("api_key", "qdrant-key"),
        ("pve_api_token", "audit@pve!tok=abc"),
    ],
)
def test_fix_f7_audit_config_token_fallback_picks_module_dest(attr_name: str, expected: str) -> None:
    from redposture_core.audit_config import AuditConfig

    ns = argparse.Namespace()
    setattr(ns, attr_name, expected)
    cfg = AuditConfig.from_namespace(ns)
    assert cfg.token == expected


# ---------------------------------------------------------------------------
# F8 — AuditConfig timeout=0.0 preserved
# ---------------------------------------------------------------------------


def test_fix_f8_audit_config_preserves_explicit_zero_timeout() -> None:
    """A programmatic caller that sets timeout=0.0 should get 0.0 back (not
    silently be upgraded to 5.0 via `or 5.0` short-circuit)."""
    from redposture_core.audit_config import AuditConfig

    ns = argparse.Namespace(timeout=0.0)
    cfg = AuditConfig.from_namespace(ns)
    assert cfg.timeout == 0.0


def test_fix_f8_audit_config_none_timeout_still_defaults() -> None:
    from redposture_core.audit_config import AuditConfig

    ns = argparse.Namespace(timeout=None)
    cfg = AuditConfig.from_namespace(ns)
    assert cfg.timeout == 5.0


# ---------------------------------------------------------------------------
# F9 — --save alias accepted by every datastore module
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ["postgres", "mongodb", "docker", "oracle"])
def test_fix_f9_save_alias_accepted_by_previously_holdout_modules(module: str) -> None:
    """--save was previously rejected by postgres/mongo/docker/oracle only."""
    from redposture_core.cli_args import parse_args

    argv = [module, "-t", "127.0.0.1", "--save", f"{module}_audit.jsonl"]
    if module == "docker":
        # Docker requires --container or another action-flag for a valid parse;
        # add a benign one so the parser reaches --save handling.
        argv += ["--containers"]
    if module == "oracle":
        argv += ["-u", "system", "-p", "oracle"]
    args = parse_args(argv)
    assert args.output == f"{module}_audit.jsonl"


# ---------------------------------------------------------------------------
# F10 — --log file gets a run separator
# ---------------------------------------------------------------------------


def test_fix_f10_log_file_gets_run_separator(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import cli

    log_path = tmp_path / "audit.log"
    log_path.write_text("previous partial line", encoding="utf-8")

    monkeypatch.setattr(
        cli,
        "parse_args",
        lambda _argv: argparse.Namespace(
            no_color=True,
            log=str(log_path),
            proxy="",
            command="redis",
        ),
    )
    monkeypatch.setattr(cli, "AttemptLogger", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "CommandProgressOwner", lambda enabled=True: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "RuntimeNetworkConfig", SimpleNamespace(from_args=lambda *_a, **_kw: None))
    monkeypatch.setattr(cli, "_run_command", lambda args, logger: 0)

    class _NoopCtx:
        def __enter__(self):
            return None

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(cli, "proxy_socket_context", lambda _cfg: _NoopCtx())

    rc = cli.main(["redis"])
    assert rc == 0

    contents = log_path.read_text(encoding="utf-8")
    # Previous content preserved (append mode) AND a fresh separator inserted.
    assert "previous partial line" in contents
    assert "===== redposture run start" in contents, f"log did not get a run-start separator; contents: {contents!r}"
