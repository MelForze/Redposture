"""Elastic service/auth headers stay together while discovery remains live."""

from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.elastic.stage import build_elastic_spec
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun


def _record(ctx, **values) -> AuditRecord:
    return AuditRecord.from_mapping(
        {
            "host": ctx.host,
            "port": ctx.port,
            "status": "auth_required",
            "auth_required": True,
            "is_elastic": True,
            "vendor": "opensearch",
            "server_version": "2.19.1",
            **values,
        },
        module="elastic",
        service="elastic",
    )


@pytest.mark.parametrize("same_host", [False, True])
def test_elastic_discovery_emits_atomic_header_and_credentials_before_live_findings(tmp_path: Path, same_host):
    first = ("127.0.0.1", 9200)
    second = ("127.0.0.1", 19200) if same_host else ("127.0.0.2", 9200)
    targets: dict[int, tuple[str, ...]] = {9200: (first[0],)}
    if same_host:
        targets[19200] = (second[0],)
    else:
        targets[9200] = (first[0], second[0])
    first_auth_done = threading.Event()
    second_capabilities_started = threading.Event()
    first_finding = threading.Event()
    both_findings = threading.Event()
    release = threading.Event()
    emitted = []
    errors = []
    output = tmp_path / "discover.txt"

    def detect(ctx):
        return _record(ctx)

    def auth(ctx, record):
        if (ctx.host, ctx.port) == first:
            first_auth_done.set()
        else:
            assert first_auth_done.wait(5)
        return _record(
            ctx,
            status="valid_credentials",
            auth_valid=True,
            provided_credentials=True,
            provided_username="logstash",
            provided_password="logstash",
            _credential_capabilities_pending=True,
        )

    def capabilities(ctx, record):
        if (ctx.host, ctx.port) == first:
            assert second_capabilities_started.wait(5)
        else:
            second_capabilities_started.set()
            assert first_finding.wait(5)
        return AuditRecord.from_mapping(
            {
                **record.to_dict(),
                "_credential_capabilities_pending": False,
                "credential_resource_access_checked": True,
                "credential_cluster_access": "allowed",
                "credential_nodes_access": "allowed",
                "credential_nodes_count": 2,
            },
            module="elastic",
            service="elastic",
        )

    def data(ctx, record):
        assert ctx.live_emit is not None
        ctx.live_emit([f"ELASTIC\t{ctx.host}\t{ctx.port}\t [!] streamed finding"])
        if (ctx.host, ctx.port) == first:
            first_finding.set()
        else:
            both_findings.set()
        assert release.wait(10)
        return record

    args = parse_args(["elastic", "-t", "127.0.0.1", "-u", "logstash", "-p", "logstash", "--discover"])
    spec = replace(
        build_elastic_spec(args),
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append)

    def run():
        try:
            runner.run_plan(
                AuditCommandPlan(
                    targets_by_port=targets,
                    workers=2,
                    output_format="txt",
                    output_path=str(output),
                    credential_runs=(AuditCredentialRun(username="logstash", password="logstash", source="provided"),),
                )
            )
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert both_findings.wait(10), errors
        # Both producers are blocked in data: output must already be visible.
        assert worker.is_alive()
        snapshot = list(emitted)
        assert output.read_text().splitlines() == snapshot
        for host, port in (first, second):
            prefix = f"ELASTIC\t{host}\t{port}\t"
            header = next(i for i, line in enumerate(snapshot) if line.startswith(prefix) and "OpenSearch API" in line)
            assert snapshot[header + 1].startswith(prefix + " [+] logstash:logstash")
            assert "(Nodes:2)" in snapshot[header + 1]
            finding = next(
                i for i, line in enumerate(snapshot) if line.startswith(prefix) and "streamed finding" in line
            )
            assert header + 1 < finding
    finally:
        release.set()
        worker.join(timeout=10)
    assert not worker.is_alive() and not errors
    assert emitted == output.read_text().splitlines()
    assert sum("OpenSearch API" in line for line in emitted) == 2
    assert sum("[+] logstash:logstash" in line for line in emitted) == 2
    assert sum("streamed finding" in line for line in emitted) == 2
    assert "\x1b" not in output.read_text()


def test_elastic_rejections_are_batched_with_detection_without_starting_discovery():
    args = parse_args(["elastic", "-t", "127.0.0.1", "--discover"])
    emitted = []

    def auth(ctx, record):
        return _record(
            ctx,
            auth_valid=False,
            provided_credentials=True,
            provided_username=ctx.credential.username,
            provided_password=ctx.credential.password,
            auth_probe_status="rejected",
        )

    spec = replace(
        build_elastic_spec(args),
        detect=_record,
        auth=auth,
        data=lambda *_: pytest.fail("discovery must not run for rejected credentials"),
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
    )
    AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("127.0.0.1",)},
            output_format="txt",
            credential_runs=(
                AuditCredentialRun(username="user", password="first", source="provided"),
                AuditCredentialRun(username="user", password="second", source="provided"),
            ),
        )
    )
    assert len(emitted) == 3
    assert "OpenSearch API" in emitted[0]
    assert emitted[1].endswith("[-] user:first")
    assert emitted[2].endswith("[-] user:second")
