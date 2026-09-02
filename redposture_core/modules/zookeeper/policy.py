"""Policy helpers for the zookeeper audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_zookeeper_protocol_args(args: Any, console: Any, *, module: str) -> int | None:
    common_rc = validate_basic_module_args(args, console, module=module, pure_http=False)
    if common_rc is not None:
        return common_rc
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be used together")
        return 2
    if bool(getattr(args, "ca_file", None)) and bool(getattr(args, "insecure", False)):
        console.error("--ca-file cannot be combined with --insecure")
        return 2
    max_znodes = getattr(args, "max_znodes", None)
    if max_znodes is not None and int(max_znodes) <= 0:
        console.error("--max-znodes must be > 0")
        return 2
    return None


def validate_args(args: Any, console: Any) -> int | None:
    return validate_zookeeper_protocol_args(args, console, module="zookeeper")


__all__ = ["validate_args", "validate_zookeeper_protocol_args"]
