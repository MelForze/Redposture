"""NEXT_QA 5: observable completeness and uniqueness of Jenkins credentials.

These tests deliberately exercise the real renderer and command output sink.
Transport requests may retry; a planned credential still has one logical result.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jenkins import actions, render
from redposture_core.modules.jenkins.stage import build_jenkins_plan, build_jenkins_spec
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, AuditHookContext


def _credentials(*names: str) -> tuple[AuditCredentialRun, ...]:
    return tuple(AuditCredentialRun(username=name, password=f"secret-{name}", source="default") for name in names)


def _detected(ctx: Any) -> AuditRecord:
    return AuditRecord.from_mapping(
        {
            "host": ctx.host,
            "port": ctx.port,
            "is_jenkins": True,
            "status": "auth_required",
            "auth_required": True,
            "anonymous_jobs_access": False,
            "version": None,
            "api_endpoint": f"http://{ctx.host}:{ctx.port}/ci",
        },
        module="jenkins",
        service="jenkins",
    )


def _verdict(ctx: Any, prior: AuditRecord, status: str, reason: str = "") -> AuditRecord:
    accepted = status == "valid_credentials"
    rejected = status == "invalid_credentials"
    return AuditRecord.from_mapping(
        {
            **prior.to_dict(),
            "status": status,
            "credential_state": "valid" if accepted else "invalid" if rejected else "unknown",
            "provided_credentials_ok": True if accepted else False if rejected else None,
            "credential_results": [{"username": ctx.credential.username}],
            "credential_password": ctx.credential.password,
            "credential_verification_reason": reason,
            "auth_http_status": 200 if accepted else 401 if rejected else 429 if status == "rate_limited" else 0,
            "credential_jobs_access": "allowed" if accepted else "unknown",
            "credential_jobs_count": 0 if accepted else None,
            "version": "2.541.3" if accepted else prior.extra.get("version"),
        },
        module="jenkins",
        service="jenkins",
    )


def _runner(auth: Any, *, emitted: list[str], debug: list[str] | None = None) -> AuditCommandRunner:
    args = SimpleNamespace(defcreds=True, discover=False, enum_cve=False, debug=debug is not None)
    if debug is not None:
        args.debug_emit = debug.append
    spec = replace(
        build_jenkins_spec(args),
        detect=_detected,
        auth=auth,
        data=lambda _ctx, record: record,
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
    )
    return AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append)


def _run(
    tmp_path: Path,
    auth: Any,
    credentials: tuple[AuditCredentialRun, ...],
    *,
    output_format: str = "txt",
    hosts: tuple[str, ...] = ("host",),
    debug: list[str] | None = None,
) -> tuple[Any, list[str], str]:
    emitted: list[str] = []
    output = tmp_path / f"jenkins-ledger.{output_format}"
    result = _runner(auth, emitted=emitted, debug=debug).run_plan(
        AuditCommandPlan(
            targets_by_port={8080: hosts},
            credential_runs=credentials,
            workers=len(hosts),
            output_format=output_format,
            output_path=str(output),
        )
    )
    return result, emitted, output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("auth_required", "Basic authentication not supported"),
        ("error", "connection reset by peer"),
        ("rate_limited", "HTTP 429"),
        ("skipped", "cancelled"),
    ],
)
def test_txt_retains_unverified_and_skipped_attempt_with_reason(status: str, reason: str) -> None:
    record = {
        "host": "host",
        "port": 8080,
        "attempted_credentials": [
            {
                "username": "admin",
                "password": "full:password-value",
                "source": "default",
                "status": status,
                "credential_state": "unknown",
                "reason": reason,
            }
        ],
    }
    lines = render._format_credential_attempts_records(record, "txt")
    assert len(lines) == 1
    assert "admin:full:password-value" in lines[0]
    assert reason in lines[0]
    assert "[-]" not in lines[0] and "[+]" not in lines[0]


def test_json_keeps_full_pair_identity_and_history(tmp_path: Path) -> None:
    credentials = (
        AuditCredentialRun(username="admin", password="full:first-secret", source="default"),
        AuditCredentialRun(username="admin", password="full:second-secret", source="default"),
    )
    _, _, stored = _run(
        tmp_path,
        lambda ctx, prior: _verdict(ctx, prior, "invalid_credentials", "Jenkins rejected Basic credentials"),
        credentials,
        output_format="json",
    )
    records = [json.loads(line) for line in stored.splitlines()]
    assert len(records) == 1
    assert [(item["username"], item["password"], item["source"]) for item in records[0]["attempted_credentials"]] == [
        (item.username, item.password, item.source) for item in credentials
    ]
    assert "\x1b[" not in stored


def test_live_and_final_successes_have_one_stable_line_per_pair(tmp_path: Path) -> None:
    credentials = _credentials("first", "second", "rejected")
    result, emitted, stored = _run(
        tmp_path,
        lambda ctx, prior: _verdict(
            ctx, prior, "invalid_credentials" if ctx.credential.username == "rejected" else "valid_credentials"
        ),
        credentials,
    )
    for credential in credentials:
        pair = f"{credential.username}:{credential.password}"
        lines = [line for line in stored.splitlines() if pair in line]
        assert len(lines) == 1, (pair, lines)
    assert stored.splitlines() == emitted
    assert len(result.records[0]["attempted_credentials"]) == len(credentials)
    assert "\x1b[" not in stored


def test_auth_version_enrichment_does_not_repeat_detection(tmp_path: Path) -> None:
    _, _, stored = _run(
        tmp_path,
        lambda ctx, prior: _verdict(
            ctx, prior, "invalid_credentials" if ctx.credential.username == "rejected" else "valid_credentials"
        ),
        _credentials("rejected", "accepted"),
    )
    detection = [line for line in stored.splitlines() if "Jenkins (auth required:" in line]
    assert len(detection) == 1, detection


def test_auth_exception_is_visible_and_later_pairs_are_accounted(tmp_path: Path) -> None:
    def auth(ctx: Any, prior: AuditRecord) -> AuditRecord:
        if ctx.credential.username == "network-error":
            raise ConnectionError("connection reset by peer")
        return _verdict(ctx, prior, "invalid_credentials", "Jenkins rejected Basic credentials")

    result, _, stored = _run(tmp_path, auth, _credentials("network-error", "rejected"))
    attempts = result.records[0]["attempted_credentials"]
    assert [item["username"] for item in attempts] == ["network-error", "rejected"]
    failure_lines = [line for line in stored.splitlines() if "network-error:secret-network-error" in line]
    assert len(failure_lines) == 1
    assert "connection reset by peer" in failure_lines[0]
    assert "[-]" not in failure_lines[0] and "[+]" not in failure_lines[0]
    assert stored.count("rejected:secret-rejected") == 1


def test_rate_limit_accounts_for_remaining_pairs_in_txt_json_and_debug(tmp_path: Path) -> None:
    credentials = _credentials("accepted", "limited", "never-one", "never-two")

    def auth(ctx: Any, prior: AuditRecord) -> AuditRecord:
        return _verdict(
            ctx,
            prior,
            "rate_limited" if ctx.credential.username == "limited" else "valid_credentials",
            "HTTP 429" if ctx.credential.username == "limited" else "verified identity",
        )

    debug: list[str] = []
    result, _, stored = _run(tmp_path, auth, credentials, debug=debug)
    attempts = result.records[0]["attempted_credentials"]
    assert [(item["username"], item["status"]) for item in attempts] == [
        ("accepted", "valid_credentials"),
        ("limited", "rate_limited"),
        ("never-one", "skipped"),
        ("never-two", "skipped"),
    ]
    assert all(item.get("reason") == "rate_limited" for item in attempts[2:])
    for credential in credentials:
        assert stored.count(f"{credential.username}:{credential.password}") == 1
        assert any(credential.username in event for event in debug)
    _, _, structured = _run(tmp_path, auth, credentials, output_format="json")
    json_attempts = json.loads(structured.splitlines()[0])["attempted_credentials"]
    assert [(item["username"], item["password"], item["status"]) for item in json_attempts] == [
        (item["username"], item["password"], item["status"]) for item in attempts
    ]


def test_cancellation_accounts_for_unstarted_pairs_without_invalid_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cancelled = threading.Event()
    emitted: list[str] = []

    def auth(ctx: Any, prior: AuditRecord) -> AuditRecord:
        cancelled.set()
        return _verdict(ctx, prior, "auth_required", "cancelled during identity verification")

    runner = _runner(auth, emitted=emitted)
    original_ctx = runner._ctx

    def context_with_cancellation(*args: Any, **kwargs: Any) -> AuditHookContext:
        ctx = original_ctx(*args, **kwargs)
        return replace(ctx, cancelled=cancelled.is_set)

    monkeypatch.setattr(runner, "_ctx", context_with_cancellation)
    output = tmp_path / "cancelled.txt"
    credentials = _credentials("interrupted", "unstarted-one", "unstarted-two")
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={8080: ("host",)},
            credential_runs=credentials,
            output_path=str(output),
            workers=1,
        )
    )
    attempts = result.records[0]["attempted_credentials"]
    assert [item["username"] for item in attempts] == [item.username for item in credentials]
    assert [item["status"] for item in attempts[1:]] == ["skipped", "skipped"]
    assert all(item.get("reason") == "cancelled" for item in attempts[1:])
    stored = output.read_text(encoding="utf-8")
    for credential in credentials:
        assert stored.count(f"{credential.username}:{credential.password}") == 1
    assert "[-]" not in stored


def test_parallel_hosts_keep_each_pair_once_and_full_ledger(tmp_path: Path) -> None:
    credentials = _credentials("unknown", "accepted", "rejected")
    statuses = {"unknown": "auth_required", "accepted": "valid_credentials", "rejected": "invalid_credentials"}
    result, _, stored = _run(
        tmp_path,
        lambda ctx, prior: _verdict(ctx, prior, statuses[ctx.credential.username], "identity unavailable"),
        credentials,
        hosts=("first", "second"),
    )
    assert {record["host"] for record in result.records} == {"first", "second"}
    for record in result.records:
        assert [item["username"] for item in record["attempted_credentials"]] == [item.username for item in credentials]
        host_lines = [line for line in stored.splitlines() if f"\t{record['host']}\t" in line]
        for credential in credentials:
            assert sum(f"{credential.username}:{credential.password}" in line for line in host_lines) == 1


def test_target_aliases_collapse_trailing_slash_but_preserve_distinct_prefixes() -> None:
    args = parse_args(
        [
            "jenkins",
            "-t",
            "http://host:8080/ci,http://host:8080/ci/,http://host:8080/other,http://host:8080/ci",
            "--defcreds",
        ]
    )
    targets = list(build_jenkins_plan(args).iter_target_specs())
    assert len(targets) == 2
    assert {target.path.rstrip("/") for _, _, _, target in targets} == {"/ci", "/other"}
    credentials = build_jenkins_plan(args).credential_runs
    pairs = [(credential.username, credential.password) for credential in credentials]
    assert len(pairs) == len(set(pairs)) == 18


def test_unproven_http_and_https_targets_remain_distinct() -> None:
    args = parse_args(["jenkins", "-t", "http://host:8080/ci,https://host:8080/ci", "--defcreds"])
    targets = list(build_jenkins_plan(args).iter_target_specs())
    assert {target.scheme for _, _, _, target in targets} == {"http", "https"}


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [(429, "try later", "rate_limited"), (401, "Account has been locked", "account_locked")],
)
def test_auth_keeps_server_safety_evidence_and_does_not_call_lockout_invalid(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: str,
    expected: str,
) -> None:
    ctx = SimpleNamespace(
        credential=AuditCredentialRun(username="admin", password="full-secret", source="default"),
        args=SimpleNamespace(timeout=1, retries=0),
    )
    monkeypatch.setattr(actions, "_client", lambda _ctx: object())
    monkeypatch.setattr(actions, "_get", lambda *_args: HttpResponse(status, body.encode(), {"Retry-After": "120"}))
    record = actions.auth_record(ctx, {"api_endpoint": "http://host:8080/ci", "is_jenkins": True})
    assert record["status"] == expected
    assert record["credential_state"] == "unknown"
    assert record["provided_credentials_ok"] is None
    assert record["auth_retry_after"] == "120"
    assert record["auth_response_body"] == body
    assert record["credential_password"] == "full-secret"


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_coordinator_interrupt_flushes_active_credentials_before_closing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_format: str,
) -> None:
    from redposture_core import stage_runtime

    started = threading.Event()
    release = threading.Event()
    workers: list[threading.Thread] = []
    errors: list[BaseException] = []

    def auth(ctx: Any, prior: AuditRecord) -> AuditRecord:
        started.set()
        assert release.wait(timeout=5)
        return _verdict(ctx, prior, "valid_credentials", "response arrived after cancellation")

    def interrupted_scheduler(_self: Any, items: Any, worker: Any) -> Any:
        item = next(iter(items))

        def run_worker() -> None:
            try:
                worker(item)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run_worker, daemon=True)
        workers.append(thread)
        thread.start()
        assert started.wait(timeout=5)
        raise KeyboardInterrupt
        yield  # Keep the real scheduler's lazy iterator contract.

    monkeypatch.setattr(stage_runtime.BoundedScheduler, "iter_completed", interrupted_scheduler)
    output = tmp_path / f"interrupted.{output_format}"
    credentials = _credentials("in-flight", "unstarted-one", "unstarted-two")
    try:
        with pytest.raises(KeyboardInterrupt):
            _runner(auth, emitted=[]).run_plan(
                AuditCommandPlan(
                    targets_by_port={8080: ("host",)},
                    credential_runs=credentials,
                    output_format=output_format,
                    output_path=str(output),
                    workers=1,
                )
            )
        stored = output.read_text(encoding="utf-8")
        if output_format == "json":
            rows = [json.loads(line) for line in stored.splitlines()]
            assert len(rows) == 1
            attempts = rows[0]["attempted_credentials"]
            assert [item["status"] for item in attempts] == ["auth_required", "skipped", "skipped"]
            assert [(item["username"], item["password"]) for item in attempts] == [
                (credential.username, credential.password) for credential in credentials
            ]
            assert all(item["reason"] == "cancelled" for item in attempts)
        else:
            for credential in credentials:
                assert stored.count(f"{credential.username}:{credential.password}") == 1
            assert "[-]" not in stored and "[+]" not in stored
            assert "cancelled" in stored
        assert "\x1b[" not in stored
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=5)
            assert not worker.is_alive()
    assert errors == []


def test_confirmed_aliases_have_one_record_but_distinct_prefixes_remain_visible(tmp_path: Path) -> None:
    from redposture_core.targeting import ScanTargetSpec

    emitted: list[str] = []
    runner = _runner(lambda ctx, prior: _verdict(ctx, prior, "invalid_credentials"), emitted=emitted)

    def detect(ctx: Any) -> AuditRecord:
        record = _detected(ctx)
        prefix = "/ci" if ctx.target.path in {"/ci", "/redirect-to-ci"} else ctx.target.path
        return replace(record, extra={**record.extra, "api_endpoint": f"http://host:8080{prefix}"})

    runner.spec = replace(runner.spec, detect=detect)
    output = tmp_path / "aliases.txt"
    result = runner.run_plan(
        AuditCommandPlan(
            target_specs_by_port={
                8080: tuple(
                    ScanTargetSpec("host", scheme="http", explicit_port=8080, path=path)
                    for path in ("/ci", "/redirect-to-ci", "/other")
                )
            },
            credential_runs=_credentials("admin"),
            output_path=str(output),
            workers=2,
        )
    )
    assert len(result.records) == 2
    assert {record["api_endpoint"] for record in result.records} == {"http://host:8080/ci", "http://host:8080/other"}
    text = output.read_text(encoding="utf-8")
    attempts = [line for line in text.splitlines() if "admin:secret-admin" in line]
    assert len(attempts) == 2
    assert all("(endpoint:" not in line for line in text.splitlines())
