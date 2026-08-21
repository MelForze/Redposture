"""Policy helpers for the kubeapi audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="kubeapi", pure_http=False)
    if common_rc is not None:
        return common_rc
    pod = str(getattr(args, "pod", "") or "").strip()
    command = str(getattr(args, "exec_command", "") or "").strip()
    if bool(pod) != bool(command):
        console.error("use --pod together with -X/--exec-command")
        return 2
    return None


__all__ = ["validate_args"]
