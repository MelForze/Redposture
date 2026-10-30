"""An interruption during target handoff must neither duplicate nor lose pairs."""

import json
from dataclasses import replace

import pytest

from redposture_core import stage_runtime as runtime
from tests.test_jenkins_credential_ledger import _credentials, _runner, _verdict


def plan(path, hosts=("host",)):
    return runtime.AuditCommandPlan(
        targets_by_port={8080: hosts},
        credential_runs=_credentials("accepted"),
        workers=1,
        output_format="json",
        output_path=str(path),
    )


def interrupt_after_worker(monkeypatch):
    def results(_scheduler, items, run):
        item = next(iter(items))
        run(item)
        raise KeyboardInterrupt
        yield

    monkeypatch.setattr(runtime.BoundedScheduler, "iter_completed", results)


def test_cancel_between_completed_registration_and_worker_finally_keeps_one_record(monkeypatch, tmp_path):
    emitted = []
    runner = _runner(lambda ctx, prior: _verdict(ctx, prior, "valid_credentials"), emitted=emitted)

    class InterruptingRegistry(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            runner._audit_cancelled.set()

    runner._completed_credential_ledgers = InterruptingRegistry()
    interrupt_after_worker(monkeypatch)
    output = tmp_path / "handoff.json"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(plan(output))
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(records) == 1
    assert len(records[0]["attempted_credentials"]) == 1


def test_interrupt_before_final_render_retains_completed_pair_history(monkeypatch, tmp_path):
    emitted = []
    runner = _runner(lambda ctx, prior: _verdict(ctx, prior, "valid_credentials"), emitted=emitted)
    original = runtime._with_http_detection_diagnostics
    raised = False

    def interrupt_once(record, **kwargs):
        nonlocal raised
        if record.extra.get("attempted_credentials") and not raised:
            raised = True
            raise KeyboardInterrupt
        return original(record, **kwargs)

    monkeypatch.setattr(runtime, "_with_http_detection_diagnostics", interrupt_once)
    output = tmp_path / "finalize.json"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(plan(output))
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["attempted_credentials"][0]["password"] == "secret-accepted"


def test_cancelled_confirmed_duplicate_alias_does_not_reappear_as_skipped(monkeypatch, tmp_path):
    emitted = []
    runner = _runner(lambda ctx, prior: _verdict(ctx, prior, "valid_credentials"), emitted=emitted)
    seen = 0

    def same_confirmed_endpoint(record):
        nonlocal seen
        seen += 1
        if seen == 2:
            runner._audit_cancelled.set()
        return "http://same-confirmed-jenkins/ci"

    runner.spec = replace(runner.spec, logical_target_key=same_confirmed_endpoint)

    def results(_scheduler, items, run):
        for index, item in enumerate(items):
            outcome = run(item)
            if index:
                assert outcome.duplicate_target
                raise KeyboardInterrupt
            yield item, outcome

    monkeypatch.setattr(runtime.BoundedScheduler, "iter_completed", results)
    output = tmp_path / "alias.json"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(plan(output, ("host", "alias")))
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["host"] == "host"
