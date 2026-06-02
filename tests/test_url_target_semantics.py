from __future__ import annotations

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.logger import AttemptLogger
from redposture_core.stage_collect import run_collect_stage
from redposture_core.stage_consul import run_consul_stage
from redposture_core.stage_elastic import run_elastic_stage
from redposture_core.stage_etcd import run_etcd_stage
from redposture_core.stage_gitlab import run_gitlab_stage
from redposture_core.stage_grafana import run_grafana_stage
from redposture_core.stage_kubeapi import run_kubeapi_stage
from redposture_core.stage_proxmox import run_proxmox_stage
from redposture_core.stage_qdrant import run_qdrant_stage
from redposture_core.stage_registry import run_registry_stage
from redposture_core.stage_scan import run_scan_stage
from redposture_core.stage_trigger import run_trigger_stage


@pytest.mark.parametrize(
    ("argv", "runner", "expected_error"),
    [
        (["exporters", "scan", "-t", "https://127.0.0.1:19100/metrics"], run_scan_stage, "accepts only http://"),
        (
            ["exporters", "collect", "-t", "https://127.0.0.1:19100/debug/vars"],
            run_collect_stage,
            "accepts only http://",
        ),
        (
            ["registry", "-t", "https://127.0.0.1:15000/v2/_catalog", "--docker", "--images"],
            run_registry_stage,
            "accepts only http://",
        ),
        (["grafana", "-t", "https://127.0.0.1:3000/login"], run_grafana_stage, "accepts only http://"),
        (
            ["etcd", "-t", "https://127.0.0.1:2379/v2/keys?recursive=true", "--show-keys"],
            run_etcd_stage,
            "accepts only http://",
        ),
        (
            ["qdrant", "-t", "https://127.0.0.1:6333/collections", "--collections"],
            run_qdrant_stage,
            "accepts only http://",
        ),
    ],
)
def test_pure_http_modules_reject_https_targets(
    argv: list[str], runner, expected_error: str, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse_args(argv)
    if runner is run_scan_stage:
        rc = runner(args)
    else:
        rc = runner(args, AttemptLogger())
    assert rc == 2
    assert expected_error in capsys.readouterr().err


def test_trigger_rejects_https_targets(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "https://127.0.0.1:19121/scrape",
            "--callback-dns",
            "host.docker.internal",
            "--no-with-listen",
        ]
    )
    monkeypatch.setattr(
        "redposture_core.stage_trigger.load_profiles", lambda *_args, **_kwargs: {"trigger_exporters": []}
    )

    rc = run_trigger_stage(args, AttemptLogger())
    assert rc == 2
    assert "accepts only http://" in capsys.readouterr().err


def test_scan_uses_explicit_url_port_over_ports_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_custom_ports: list[list[int] | None] = []

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        custom = kwargs.get("custom_ports")
        if custom is None:
            captured_custom_ports.append(None)
        else:
            captured_custom_ports.append([int(port) for port in custom])
        return 1, 0, {"127.0.0.1": []}

    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: {"discovery_exporters": [{"name": "node_exporter", "port": 9100}]},
    )
    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    args = parse_args(["exporters", "scan", "-t", "http://127.0.0.1:19100/metrics", "-p", "9100"])
    rc = run_scan_stage(args)

    assert rc == 0
    assert captured_custom_ports == [[19100]]


def test_trigger_uses_explicit_port_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], list[int]]] = []

    monkeypatch.setattr(
        "redposture_core.stage_trigger.load_profiles",
        lambda *_args, **_kwargs: {
            "trigger_exporters": [{"name": "redis_exporter", "port": 9121, "target_fmt": "redis://{our_host}:6379"}]
        },
    )

    def fake_run_trigger_requests(
        _args,
        _logger,
        _console,
        hosts,
        _callback_targets,
        trigger_exporters,
        **_kwargs,
    ) -> None:
        calls.append((list(hosts), [int(item.get("port") or 0) for item in trigger_exporters]))

    monkeypatch.setattr("redposture_core.stage_trigger._run_trigger_requests", fake_run_trigger_requests)

    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1,http://10.0.0.2:19121/scrape",
            "--callback-dns",
            "host.docker.internal",
            "--no-with-listen",
            "-p",
            "19150",
        ]
    )
    rc = run_trigger_stage(args, AttemptLogger())

    assert rc == 0
    assert calls == [(["10.0.0.1"], [19150]), (["10.0.0.2"], [19121])]


def test_gitlab_url_scheme_overrides_global_https(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, int, str, str]] = []

    def fake_host_hook(ctx) -> AuditRecord:  # type: ignore[no-untyped-def]
        captured.append((ctx.target.scheme if ctx.target else None, ctx.port, ctx.target.path, ctx.target.query))
        return AuditRecord(host=ctx.host, port=ctx.port, module="gitlab", service="gitlab", status="open_no_auth")

    monkeypatch.setattr("redposture_core.modules.gitlab.actions.host_hook", fake_host_hook)

    args = parse_args(["gitlab", "-t", "http://127.0.0.1:18080/users/sign_in?ref=matrix", "--https"])
    rc = run_gitlab_stage(args, AttemptLogger())

    assert rc == 0
    assert captured == [
        ("http", 18080, "/users/sign_in", "ref=matrix"),
        ("http", 18080, "/users/sign_in", "ref=matrix"),
    ]


def test_kubeapi_url_scheme_overrides_global_https(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, int, str]] = []

    def fake_host_hook(ctx) -> AuditRecord:  # type: ignore[no-untyped-def]
        captured.append((ctx.target.scheme if ctx.target else None, ctx.port, ctx.target.path))
        return AuditRecord(host=ctx.host, port=ctx.port, module="kubeapi", service="kubeapi", status="open_no_auth")

    monkeypatch.setattr("redposture_core.modules.kubeapi.actions.host_hook", fake_host_hook)

    args = parse_args(["kubeapi", "-t", "https://127.0.0.1:26443/api", "--no-https", "--namespaces"])
    rc = run_kubeapi_stage(args, AttemptLogger())

    assert rc == 0
    assert captured == [("https", 26443, "/api"), ("https", 26443, "/api")]


def test_proxmox_url_scheme_overrides_global_https(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, int, str]] = []

    def fake_host_hook(ctx) -> AuditRecord:  # type: ignore[no-untyped-def]
        captured.append((ctx.target.scheme if ctx.target else None, ctx.port, ctx.target.path))
        return AuditRecord(
            host=ctx.host, port=ctx.port, module="proxmox", service="proxmox", status="valid_credentials"
        )

    monkeypatch.setattr("redposture_core.modules.proxmox.actions.host_hook", fake_host_hook)

    args = parse_args(
        [
            "proxmox",
            "-t",
            "https://127.0.0.1:18006/api2/json/access/ticket",
            "--no-https",
            "--insecure",
            "--pveapitoken",
            "audit@pve!redposture=pve-redposture-token-2026",
        ]
    )
    rc = run_proxmox_stage(args, AttemptLogger())

    assert rc == 0
    assert captured == [("https", 18006, "/api2/json/access/ticket"), ("https", 18006, "/api2/json/access/ticket")]


def test_consul_passes_preferred_scheme_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, int, str]] = []

    def fake_host_hook(ctx) -> AuditRecord:  # type: ignore[no-untyped-def]
        captured.append((ctx.target.scheme if ctx.target else None, ctx.port, ctx.target.path))
        return AuditRecord(host=ctx.host, port=ctx.port, module="consul", service="consul", status="open_no_auth")

    monkeypatch.setattr("redposture_core.modules.consul.actions.host_hook", fake_host_hook)

    args = parse_args(["consul", "-t", "http://127.0.0.1:8500/v1/status/leader", "--dump"])
    rc = run_consul_stage(args, AttemptLogger())

    assert rc == 0
    assert captured == [("http", 8500, "/v1/status/leader"), ("http", 8500, "/v1/status/leader")]


def test_elastic_passes_preferred_scheme_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, int, str]] = []

    def fake_host_hook(ctx) -> AuditRecord:  # type: ignore[no-untyped-def]
        captured.append((ctx.target.scheme if ctx.target else None, ctx.port, ctx.target.path))
        return AuditRecord(host=ctx.host, port=ctx.port, module="elastic", service="elastic", status="auth_required")

    monkeypatch.setattr("redposture_core.modules.elastic.actions.host_hook", fake_host_hook)

    args = parse_args(["elastic", "-t", "https://127.0.0.1:19201/"])
    rc = run_elastic_stage(args, AttemptLogger())

    assert rc == 0
    assert captured == [("https", 19201, "/")]
