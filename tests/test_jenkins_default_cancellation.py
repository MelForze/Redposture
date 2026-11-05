"""The full default list must account for Ctrl+C without inventing failures."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.jenkins.stage import build_jenkins_plan
from redposture_core.stage_runtime import AuditCommandPlan
from tests.test_jenkins_credential_ledger import _runner, _verdict


def defaults():
    args = parse_args(["jenkins", "-t", "10.109.2.165:8443", "--defcreds"])
    credentials = tuple(item for item in build_jenkins_plan(args).credential_runs if item.username is not None)
    assert len(credentials) == 18
    return credentials


@pytest.mark.parametrize("completed", [0, 1, 17, 18, None])
@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_all_18_pairs_account_for_cancellation(tmp_path, monkeypatch, completed, output_format):
    credentials = defaults()
    cancelled = threading.Event()
    if completed == 0:
        cancelled.set()
    seen = []

    def auth(ctx, prior):
        assert not cancelled.is_set(), "new credential started after cancellation"
        seen.append((ctx.credential.username, ctx.credential.password))
        if completed is not None and len(seen) == completed:
            cancelled.set()
        return _verdict(ctx, prior, "valid_credentials" if len(seen) == 1 else "invalid_credentials")

    runner = _runner(auth, emitted=[])
    # Credential accounting is independent of executing a command probe.
    runner.spec = replace(runner.spec, rce_probe=lambda _ctx, record: record)
    original = runner._ctx

    def context(*args, **kwargs):
        ctx = original(*args, **kwargs)
        return SimpleNamespace(**{**vars(ctx), "cancelled": cancelled.is_set})

    monkeypatch.setattr(runner, "_ctx", context)
    output = tmp_path / f"result.{output_format}"
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={8443: ("10.109.2.165",)},
            credential_runs=credentials,
            workers=1,
            output_format=output_format,
            output_path=str(output),
        )
    )
    performed = 18 if completed is None else completed
    record = result.records[0]
    attempts = record["attempted_credentials"]
    assert seen == [(item.username, item.password) for item in credentials[:performed]]
    assert [(item["username"], item["password"]) for item in attempts] == [
        (item.username, item.password) for item in credentials
    ]
    assert record["credential_attempts_planned"] == 18
    assert record["credential_attempts_executed"] == performed
    assert record["credential_attempts_skipped"] == 18 - performed
    assert record["credential_attempts_unverified"] == 0
    assert all(item["status"] == "skipped" and item["reason"] == "cancelled" for item in attempts[performed:])
    if performed:
        assert attempts[0]["status"] == "valid_credentials"
    text = output.read_text()
    assert "\x1b" not in text
    if output_format == "json":
        assert json.loads(text)["attempted_credentials"] == attempts
    else:
        for index, credential in enumerate(credentials):
            pair = re.escape(f"{credential.username}:{credential.password}")
            matching = [
                line for line in text.splitlines() if re.search(r"\[(?:\+|-|\*)\]\s+" + pair + r"(?=\s|$)", line)
            ]
            assert len(matching) == 1
            assert ("(status:skipped)" in matching[0]) is (index >= performed)
        assert "Credential checks" not in text


def test_same_runner_clears_previous_interrupt_for_the_next_run(tmp_path):
    credentials = defaults()
    state = {"interrupt": True}
    seen = []

    def auth(ctx, prior):
        if state["interrupt"]:
            raise KeyboardInterrupt
        seen.append((ctx.credential.username, ctx.credential.password))
        return _verdict(ctx, prior, "invalid_credentials")

    runner = _runner(auth, emitted=[])
    runner.spec = replace(runner.spec, rce_probe=lambda _ctx, record: record)

    def plan(name):
        return AuditCommandPlan(
            targets_by_port={8443: ("10.109.2.165",)},
            credential_runs=credentials,
            workers=1,
            output_format="json",
            output_path=str(tmp_path / name),
        )

    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(plan("interrupted.json"))
    assert runner._audit_cancelled.is_set()
    state["interrupt"] = False
    result = runner.run_plan(plan("finished.json"))
    assert len(seen) == 18
    assert result.records[0]["credential_attempts_executed"] == 18
    assert result.records[0]["credential_attempts_skipped"] == 0


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_interrupt_during_detection_does_not_invent_credential_history(tmp_path, output_format):
    calls = []

    def auth(ctx, prior):
        calls.append(ctx.credential)
        raise AssertionError("authentication must not run before detection")

    def interrupted_detect(_ctx):
        raise KeyboardInterrupt

    runner = _runner(auth, emitted=[])
    runner.spec = replace(runner.spec, detect=interrupted_detect, rce_probe=None)
    output = tmp_path / f"detect-interrupted.{output_format}"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={8443: ("10.109.2.165",)},
                credential_runs=defaults(),
                workers=1,
                output_format=output_format,
                output_path=str(output),
            )
        )
    assert calls == []
    stored = output.read_text()
    assert "Jenkins (auth required:" not in stored
    if output_format == "json":
        rows = [json.loads(line) for line in stored.splitlines()]
        assert len(rows) == 1
        assert rows[0]["status"] == rows[0]["detection_status"] == "cancelled"
        assert rows[0]["cancelled_stage"] == "detect" and rows[0]["reason"] == "cancelled"
        assert not any(row.get("attempted_credentials") for row in rows)
    else:
        assert "admin:12345678" not in stored


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_interrupt_between_detection_and_auth_keeps_product_proof(tmp_path, monkeypatch, output_format):
    runner = _runner(lambda *_args: pytest.fail("auth must not start"), emitted=[])
    runner.spec = replace(runner.spec, rce_probe=None)

    def interrupted_deep(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "_run_deep_and_close_state", interrupted_deep)
    output = tmp_path / f"between-stages.{output_format}"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={8443: ("10.109.2.165",)},
                credential_runs=defaults(),
                workers=1,
                output_format=output_format,
                output_path=str(output),
            )
        )
    stored = output.read_text()
    if output_format == "json":
        record = json.loads(stored)
        assert record["is_jenkins"] is True
        assert record["credential_attempts_executed"] == 0
        assert record["credential_attempts_skipped"] == 18
    else:
        lines = stored.splitlines()
        assert len(lines) == 19
        assert "Jenkins (auth required:" in lines[0]
        assert all("(status:skipped)" in line and "reason=cancelled" in line for line in lines[1:])
    assert "Credential checks" not in stored and "\x1b" not in stored


def test_coordinator_cancel_during_output_keeps_detection_and_finished_pair(tmp_path, monkeypatch):
    from redposture_core import stage_runtime

    ready = threading.Event()
    release = threading.Event()
    workers = []
    errors = []
    calls = []
    emitted = []

    def auth(ctx, prior):
        calls.append(ctx.credential)
        return _verdict(ctx, prior, "invalid_credentials")

    runner = _runner(auth, emitted=emitted)
    runner.spec = replace(runner.spec, rce_probe=None)
    original_render = runner._render_record

    def paused_render(record, *args, **kwargs):
        rendered = original_render(record, *args, **kwargs)
        if record.extra.get("credential_results") and not ready.is_set():
            ready.set()
            assert release.wait(5)
        return rendered

    monkeypatch.setattr(runner, "_render_record", paused_render)

    def interrupted_scheduler(_self, items, worker):
        item = next(iter(items))

        def run():
            try:
                worker(item)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        workers.append(thread)
        thread.start()
        assert ready.wait(5)
        raise KeyboardInterrupt
        yield

    def release_emitter():
        assert ready.wait(5)
        # Interrupt after the phase guard, before the counted batch is written.
        # The final flush waits for the output lock and must see an emitted
        # batch, rather than counts for lines the live sink discarded.
        assert runner._audit_cancelled.wait(5)
        release.set()

    helper = threading.Thread(target=release_emitter, daemon=True)
    helper.start()
    monkeypatch.setattr(stage_runtime.BoundedScheduler, "iter_completed", interrupted_scheduler)
    output = tmp_path / "output-race.txt"
    try:
        with pytest.raises(KeyboardInterrupt):
            runner.run_plan(
                AuditCommandPlan(
                    targets_by_port={8443: ("10.109.2.165",)},
                    credential_runs=defaults(),
                    workers=1,
                    output_path=str(output),
                )
            )
    finally:
        release.set()
        helper.join(5)
        assert not helper.is_alive()
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()
    assert not errors
    stored = output.read_text()
    assert stored.splitlines() == emitted
    assert stored.count("Jenkins (auth required:") == 1
    assert stored.count("[-] admin:12345678") == 1
    assert calls == [defaults()[0]]
    for credential in defaults():
        pair = re.escape(f"{credential.username}:{credential.password}")
        assert len(re.findall(r"\[(?:\+|-|\*)\]\s+" + pair + r"(?=\s|$)", stored)) == 1
    assert "Credential checks" not in stored and "\x1b" not in stored


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_late_interrupt_preserves_completed_host_without_inventing_second_host_auth(tmp_path, output_format):
    calls = []

    def auth(ctx, prior):
        calls.append(ctx.host)
        return _verdict(ctx, prior, "invalid_credentials")

    runner = _runner(auth, emitted=[])
    detected = runner.spec.detect

    def detect(ctx):
        if ctx.host == "10.109.2.165":
            assert len(calls) == 18, "the interrupt must follow another host's full credential scan"
            raise KeyboardInterrupt
        assert detected is not None
        return detected(ctx)

    runner.spec = replace(runner.spec, detect=detect, rce_probe=lambda _ctx, record: record)
    output = tmp_path / f"late-interrupt.{output_format}"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={8443: ("10.109.2.164", "10.109.2.165")},
                credential_runs=defaults(),
                workers=1,
                output_format=output_format,
                output_path=str(output),
            )
        )
    assert calls == ["10.109.2.164"] * 18
    stored = output.read_text()
    if output_format == "json":
        records = [json.loads(line) for line in stored.splitlines()]
        first = [r for r in records if r["host"] == "10.109.2.164"]
        second = [r for r in records if r["host"] == "10.109.2.165"]
        assert len(first) == len(second) == 1
        assert first[0]["is_jenkins"] is True and first[0]["credential_attempts_executed"] == 18
        assert second[0]["status"] == "cancelled" and not second[0].get("attempted_credentials")
    else:
        lines = stored.splitlines()
        assert len(lines) == 19 and "Jenkins (auth required:" in lines[0]
        assert all("10.109.2.164" in line for line in lines)
    assert "Credential checks" not in stored and "\x1b" not in stored


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_async_detection_proof_survives_interrupt_before_auth(tmp_path, monkeypatch, output_format):
    from redposture_core import async_detection
    from tests.test_jenkins_credential_ledger import _detected

    calls = []

    def forbidden_sync_detect(_ctx):
        pytest.fail("native async detector must be used")

    async def detect(ctx, _http):
        calls.append(ctx.host)
        record = _detected(ctx)
        if ctx.host != "10.109.2.165":
            record = replace(record, status="not_jenkins", extra={"is_jenkins": False})
        return record

    runner = _runner(lambda *_args: pytest.fail("auth must not start"), emitted=[])
    runner.args.timeout = 1
    runner.args.retries = 0
    runner.args._async_detect_concurrency = 2
    runner.spec = replace(
        runner.spec,
        detect=forbidden_sync_detect,
        detect_async=detect,
        async_detect_sync_hook=forbidden_sync_detect,
        rce_probe=None,
    )

    def interrupted_deep(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "_run_deep_and_close_state", interrupted_deep)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _args: True)
    output = tmp_path / f"native-interrupt.{output_format}"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={8443: tuple(f"10.109.2.{n}" for n in range(165, 197))},
                credential_runs=defaults(),
                workers=1,
                output_format=output_format,
                output_path=str(output),
            )
        )
    assert "10.109.2.165" in calls
    stored = output.read_text()
    if output_format == "json":
        records = [json.loads(line) for line in stored.splitlines()]
        found = [r for r in records if r.get("is_jenkins") is True]
        assert len(found) == 1 and found[0]["host"] == "10.109.2.165"
        assert found[0]["credential_attempts_executed"] == 0
        assert found[0]["credential_attempts_skipped"] == 18
        assert all(not r.get("attempted_credentials") for r in records if not r.get("is_jenkins"))
    else:
        lines = stored.splitlines()
        assert len(lines) == 19 and "Jenkins (auth required:" in lines[0]
        assert all("10.109.2.165" in line for line in lines)
    assert "Credential checks" not in stored and "\x1b" not in stored
