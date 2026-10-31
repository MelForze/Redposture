"""Small, correlated command probes for modules with an execution surface."""

from __future__ import annotations

import copy
import secrets
from collections.abc import Callable
from typing import Any

from ..audit_models import AuditRecord

_PROBE_TIMEOUT_SECONDS = 5.0
_PROBE_COMMAND_PREFIX = "echo REDPOSTURE_RCE_"


def probe_execution(
    ctx: Any,
    record: AuditRecord,
    state: Any,
    execute: Callable[..., dict[str, Any]],
    *,
    stateful: bool = True,
) -> AuditRecord:
    """Run a harmless marker command and record only correlated completion proof."""

    marker = _PROBE_COMMAND_PREFIX + secrets.token_hex(12)
    expected_output = marker.removeprefix("echo ")
    args = copy.copy(ctx.args)
    args.execute = marker
    args._rce_probe = True
    args.execute_timeout = min(
        float(getattr(ctx.args, "execute_timeout", _PROBE_TIMEOUT_SECONDS)), _PROBE_TIMEOUT_SECONDS
    )
    args.execute_max_bytes = max(int(getattr(ctx.args, "execute_max_bytes", 0) or 0), 4096)
    probe_state = copy.copy(state) if stateful and state is not None else state
    if probe_state is not None:
        # Execution helpers cache the first command on lifecycle state. Keep
        # this detection probe isolated from a later user-requested --execute.
        for name in ("execution", "ui_execution"):
            if hasattr(probe_state, name):
                setattr(probe_state, name, None)
    probe_ctx = copy.copy(ctx)
    try:
        probe_ctx.args = args
    except (AttributeError, TypeError):
        object.__setattr__(probe_ctx, "args", args)
    if record.extra.get("rce") is False:
        return AuditRecord.from_mapping(
            {**record.to_dict(), "rce_probe_performed": False},
            module=record.module or "unknown",
            service=record.service or record.module or "unknown",
        )
    try:
        result = execute(probe_ctx, record.to_dict(), probe_state)
        details = result.get("execution") if isinstance(result, dict) else None
        if details is None and isinstance(result, dict) and "executed" in result:
            details = result
        if isinstance(details, dict):
            completed = details.get("executed") is True
            stdout = details.get("stdout")
            verified = completed and isinstance(stdout, str) and expected_output in stdout
            if verified:
                verdict: bool | None = True
            elif details.get("status") in {"unsupported", "denied", "forbidden"}:
                verdict = False
            else:
                error = str(details.get("error") or "").casefold()
                verdict = (
                    False
                    if any(
                        token in error
                        for token in (
                            "http 401",
                            "http 403",
                            "access denied",
                            "not authorized",
                            "not verified",
                            "permission denied",
                            "not enabled",
                            "unsupported",
                        )
                    )
                    else None
                )
        else:
            verdict = None
    except Exception:
        verdict = None
    return AuditRecord.from_mapping(
        {**record.to_dict(), "rce": verdict, "rce_probe_performed": verdict is not None},
        module=record.module or "unknown",
        service=record.service or record.module or "unknown",
    )


__all__ = ["probe_execution"]
