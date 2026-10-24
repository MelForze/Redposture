"""Native Oracle detection must preserve listener targets and the downstream cache."""

import asyncio
from types import SimpleNamespace

import pytest

from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.modules.oracle import async_detect, stage


def ctx(**args):
    return SimpleNamespace(
        host="127.0.0.1",
        port=1521,
        args=SimpleNamespace(timeout=1, retries=0, **args),
        lifecycle_state={},
        debug_emit=None,
    )


def test_listener_and_driver_target_evidence(monkeypatch):
    calls = []

    async def listener(host, port, command, **kwargs):
        calls.append(command)
        return {
            "ok": True,
            "text": "TNSLSNR (SERVICE_NAME=XE)",
            "protocol": "tcp",
            "listener_password_protected": False,
            "listener_restricted": False,
        }

    async def targets(*args, **kwargs):
        calls.append(kwargs["target_candidates"])
        return [
            {
                "protocol": "tcp",
                "service": "XE",
                "sid": None,
                "status": "available",
                "exists": True,
                "auth_required": True,
                "error": "invalid credentials",
            }
        ]

    monkeypatch.setattr(async_detect, "listener_command", listener)
    monkeypatch.setattr(async_detect, "probe_targets", targets)
    context = ctx(service="XE")
    record = asyncio.run(async_detect.detect(context, None))
    assert record.status == "auth_required"
    assert record.extra["is_oracle"] is True
    assert calls == ["status", [{"service": "XE", "sid": None}]]
    cached = context.lifecycle_state["oracle_detection"]
    assert cached["auth_target"] is True
    assert cached["listener_targets"] == record.extra["listener_targets"]
    assert cached["service"] == "XE"


def test_thick_mode_requests_full_legacy(monkeypatch):
    monkeypatch.setattr(
        async_detect.client_helpers,
        "_load_oracledb",
        lambda: SimpleNamespace(
            is_thin_mode=lambda: False, connect_async=lambda **kw: pytest.fail("thick async unsupported")
        ),
    )
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(
            async_detect.connect_probe(
                "127.0.0.1",
                1521,
                timeout=1,
                protocol="tcp",
                service="XE",
                sid=None,
                wallet=None,
                ssl_server_dn=None,
                insecure=True,
            )
        )


def test_spec_registers_matching_sync_hook():
    spec = stage.build_oracle_spec(SimpleNamespace())
    assert spec.detect_async is async_detect.detect
    assert spec.async_detect_sync_hook is spec.detect


@pytest.mark.parametrize(
    "error,status,exists,required",
    [
        ("ORA-01017: invalid username/password", "available", True, True),
        ("ORA-28000: account is locked", "available", True, True),
        ("ORA-12514: listener does not know service", "unknown", False, None),
        ("ORA-12528: instance blocking", "restricted", True, True),
        ("DPY-4011: connection closed", "fail", None, None),
    ],
)
def test_async_driver_probe_classification(monkeypatch, error, status, exists, required):
    calls = []

    async def connect(**kwargs):
        calls.append(kwargs)
        raise RuntimeError(error)

    monkeypatch.setattr(
        async_detect.client_helpers,
        "_load_oracledb",
        lambda: SimpleNamespace(is_thin_mode=lambda: True, connect_async=connect),
    )
    rows = asyncio.run(
        async_detect.probe_targets(
            "127.0.0.1",
            1521,
            1,
            protocol_candidates=["tcp"],
            target_candidates=[{"service": "XE", "sid": None}],
            wallet=None,
            ssl_server_dn=None,
            insecure=True,
        )
    )
    assert (rows[0]["status"], rows[0]["exists"], rows[0]["auth_required"]) == (status, exists, required)
    assert calls[0]["user"] == "REDPOSTURE_PROBE"
    assert calls[0]["tcp_connect_timeout"] == 1.0


def test_restricted_listener_skips_guessed_targets(monkeypatch):
    async def listener(*args, **kwargs):
        return {
            "ok": True,
            "text": "TNS-01194 (ERR=1194)",
            "protocol": "tcp",
            "listener_restricted": True,
            "listener_password_protected": False,
        }

    async def targets(*args, **kwargs):
        pytest.fail("restricted listener should not trigger guessed descriptor probes")

    monkeypatch.setattr(async_detect, "listener_command", listener)
    monkeypatch.setattr(async_detect, "probe_targets", targets)
    context = ctx()
    record = asyncio.run(async_detect.detect(context, None))
    assert record.status == "auth_required"
    assert record.extra["listener_restricted"] is True
    assert context.lifecycle_state["oracle_detection"]["auth_probes"] == []
