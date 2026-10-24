"""Spray must retain its bounded TNS guard before invoking Oracle's SDK."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from redposture_core.clients import async_oracle_detect
from redposture_core.modules.oracle import async_detect
from redposture_core.spray_async_detect import prepare_target
from redposture_core.targeting import ScanTargetSpec


def test_foreign_listener_never_enters_oracle_sdk(monkeypatch):
    calls = []

    async def listener(*args, **kw):
        calls.append("tns status")
        return {"ok": False, "error": "not a listener", "packets": [], "text": "", "fields": {}}

    async def probe(*args, **kw):
        calls.append("SDK")
        raise AssertionError("foreign endpoint reached Oracle SDK")

    monkeypatch.setattr(async_detect, "listener_command", listener)
    monkeypatch.setattr(async_oracle_detect, "listener_command", listener)
    monkeypatch.setattr(async_detect, "connect_probe", probe)
    args = SimpleNamespace(
        timeout=0.1,
        retries=0,
        protocol="tcp",
        service="XE",
        sid=None,
        service_list=None,
        sid_list=None,
        secure=False,
        debug=False,
    )
    target = ScanTargetSpec("127.0.0.1", explicit_port=1, raw="127.0.0.1:1")
    prepared = asyncio.run(prepare_target(("oracle", args, "127.0.0.1", 1, target), None))
    try:
        assert "SDK" not in calls
        assert prepared is not None and not prepared[2]._is_detected(prepared[4].record)
    finally:
        if prepared is not None:
            prepared[2]._close_all_lifecycle_states()
