"""Policy helpers for the docker audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="docker", pure_http=False)
    if common_rc is not None:
        return common_rc
    if bool(getattr(args, "container", None)) != bool(getattr(args, "exec_cmd", None)):
        console.error("--container and --exec-cmd must be used together")
        return 2
    tls_cert = getattr(args, "tls_cert", None)
    tls_key = getattr(args, "tls_key", None)
    if bool(tls_cert) != bool(tls_key):
        console.error("--tls-cert and --tls-key must be used together")
        return 2
    return None


__all__ = ["validate_args"]
