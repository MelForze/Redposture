"""Native ClickHouse IO interpreter for the original detection decisions."""

from __future__ import annotations

import asyncio
from typing import Any

from ...audit_models import AuditRecord
from ...clients.async_clickhouse_detect import NativeClickHouseIO
from ...clients.async_http_detect import AsyncHttpFallback
from ...detection_io import DetectCall, DetectDelay
from . import actions

_CONNECT = actions._connect_and_probe
_VERSION = actions._read_clickhouse_version
_OPEN = actions._open_clickhouse_client
_LOAD_DRIVER = actions._load_clickhouse_driver_client
_LOAD_CONNECT = actions._load_clickhouse_connect_module
_DETECT = actions.detect_clickhouse
_STEPS = actions.detect_clickhouse_steps


async def detect(ctx: Any, _http: Any, options: Any) -> AuditRecord:
    if (
        actions.detect_clickhouse is not _DETECT
        or actions.detect_clickhouse_steps is not _STEPS
        or actions._open_clickhouse_client is not _OPEN
        or actions._load_clickhouse_driver_client is not _LOAD_DRIVER
        or actions._load_clickhouse_connect_module is not _LOAD_CONNECT
    ):
        raise AsyncHttpFallback("ClickHouse lifecycle/client helper override")
    transport = NativeClickHouseIO()
    steps = actions.detect_clickhouse_steps(ctx, options)
    completed = False
    try:
        step = next(steps)
        while True:
            try:
                if isinstance(step, DetectDelay):
                    await asyncio.sleep(step.seconds)
                    value = None
                elif isinstance(step, DetectCall) and step.function is _CONNECT:
                    value = await transport.connect_and_probe(*step.args, **step.kwargs)
                elif isinstance(step, DetectCall) and step.function is _VERSION:
                    value = await transport.read_version(*step.args, **step.kwargs)
                else:
                    raise AsyncHttpFallback("ClickHouse detection helper override")
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                step = steps.throw(exc)
            else:
                step = steps.send(value)
    except StopIteration as result:
        transport.adopt()
        completed = True
        return AuditRecord.from_mapping(result.value, module="clickhouse", service="clickhouse")
    finally:
        steps.close()
        if not completed:
            transport.close()
