from __future__ import annotations

import inspect
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.logger import AttemptLogger
from redposture_core.modules.consul import actions as consul_actions
from redposture_core.modules.elastic import actions as elastic_actions
from redposture_core.modules.gitlab import actions as gitlab_actions
from redposture_core.modules.kubeapi import actions as kubeapi_actions
from redposture_core.modules.proxmox import actions as proxmox_actions
from redposture_core.stage_collect import run_collect_stage
from redposture_core.stage_consul import run_consul_stage
from redposture_core.stage_elastic import run_elastic_stage
from redposture_core.stage_etcd import run_etcd_stage
from redposture_core.stage_gitlab import build_gitlab_plan, run_gitlab_stage
from redposture_core.stage_grafana import run_grafana_stage
from redposture_core.stage_kubeapi import run_kubeapi_stage
from redposture_core.stage_proxmox import run_proxmox_stage
from redposture_core.stage_qdrant import run_qdrant_stage
from redposture_core.stage_registry import run_registry_stage
from redposture_core.stage_scan import run_scan_stage
from redposture_core.stage_trigger import run_trigger_stage


class _HostStageCapture:
    def __init__(self, original: Any, module: str, status: str) -> None:
        self.__signature__ = inspect.signature(original)
        self.module = module
        self.status = status
        self.calls: list[dict[str, Any]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> AuditRecord:
        bound = self.__signature__.bind(*args, **kwargs)
        bound.apply_defaults()
        call = dict(bound.arguments)
        self.calls.append(call)
        return AuditRecord(
            host=str(call["host"]),
            port=int(call["port"]),
            module=self.module,
            service=self.module,
            status=self.status,
        )


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
    captured = _HostStageCapture(gitlab_actions.host_stage, "gitlab", "open_no_auth")
    monkeypatch.setattr(gitlab_actions, "host_stage", captured)

    args = parse_args(["gitlab", "-t", "http://127.0.0.1:18080/users/sign_in?ref=matrix", "--https"])
    rc = run_gitlab_stage(args, AttemptLogger())

    assert rc == 0
    assert len(captured.calls) == 2
    assert all(call["host"] == "127.0.0.1" and call["port"] == 18080 for call in captured.calls)
    assert all(call["use_https"] is False for call in captured.calls)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["gitlab", "-t", "gitlab.local"], [("gitlab.local", 80)]),
        (["gitlab", "-t", "gitlab.local", "--https"], [("gitlab.local", 443)]),
        (["gitlab", "-t", "https://gitlab.local"], [("gitlab.local", 443)]),
        (["gitlab", "-t", "http://gitlab.local"], [("gitlab.local", 80)]),
        (["gitlab", "-t", "https://gitlab.local", "--port", "8443"], [("gitlab.local", 8443)]),
        (
            ["gitlab", "-t", "http://http.local,https://https.local,bare.local"],
            [("http.local", 80), ("bare.local", 80), ("https.local", 443)],
        ),
    ],
)
def test_gitlab_scheme_aware_default_ports(argv: list[str], expected: list[tuple[str, int]]) -> None:
    args = parse_args(argv)
    plan = build_gitlab_plan(args)

    assert [(host, port) for _idx, host, port, _target in plan.iter_target_specs()] == expected


def test_kubeapi_url_scheme_overrides_global_https(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _HostStageCapture(kubeapi_actions.host_stage, "kubeapi", "open_no_auth")
    monkeypatch.setattr(kubeapi_actions, "host_stage", captured)

    args = parse_args(["kubeapi", "-t", "https://127.0.0.1:26443/api", "--no-https", "--namespaces"])
    rc = run_kubeapi_stage(args, AttemptLogger())

    assert rc == 0
    assert len(captured.calls) == 2
    assert all(call["host"] == "127.0.0.1" and call["port"] == 26443 for call in captured.calls)
    assert all(call["use_https"] is True for call in captured.calls)


def test_proxmox_url_scheme_overrides_global_https(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _HostStageCapture(proxmox_actions.host_stage, "proxmox", "valid_credentials")
    monkeypatch.setattr(proxmox_actions, "host_stage", captured)

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
    # The phase-aware lifecycle classifies anonymously, then executes the
    # selected token's authenticated work once; data reuses that result.
    assert len(captured.calls) == 2
    assert all(call["host"] == "127.0.0.1" and call["port"] == 18006 for call in captured.calls)
    assert all(call["use_https"] is True for call in captured.calls)


def test_consul_passes_preferred_scheme_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _HostStageCapture(consul_actions.host_stage, "consul", "open_no_auth")
    monkeypatch.setattr(consul_actions, "host_stage", captured)

    args = parse_args(["consul", "-t", "http://127.0.0.1:8500/v1/status/leader", "--dump"])
    rc = run_consul_stage(args, AttemptLogger())

    assert rc == 0
    assert len(captured.calls) == 2
    assert all(call["preferred_scheme"] == "http" for call in captured.calls)


def test_elastic_passes_preferred_scheme_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _HostStageCapture(elastic_actions.host_stage, "elastic", "auth_required")
    monkeypatch.setattr(elastic_actions, "host_stage", captured)

    args = parse_args(["elastic", "-t", "https://127.0.0.1:19201/"])
    rc = run_elastic_stage(args, AttemptLogger())

    assert rc == 0
    assert len(captured.calls) == 1
    assert captured.calls[0]["preferred_scheme"] == "https"
