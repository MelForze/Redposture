"""Policy helpers for the redis audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="redis", pure_http=False)
    if common_rc is not None:
        return common_rc
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be used together")
        return 2
    if getattr(args, "tls_ca", None) and bool(getattr(args, "insecure", False)):
        console.error("--tls-ca cannot be combined with --insecure")
        return 2
    return None


__all__ = ["validate_args"]
