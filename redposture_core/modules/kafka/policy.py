"""Policy helpers for the kafka audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="kafka", pure_http=False)
    if common_rc is not None:
        return common_rc
    max_messages = getattr(args, "max_messages", None)
    if max_messages is not None and int(max_messages) <= 0:
        console.error("--max-messages must be > 0")
        return 2
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be provided together")
        return 2
    if bool(getattr(args, "insecure", False)) and getattr(args, "tls_ca", None):
        console.error("--insecure cannot be combined with --tls-ca")
        return 2
    if bool(getattr(args, "plaintext", False)) and any(
        (
            bool(getattr(args, "insecure", False)),
            bool(getattr(args, "tls_ca", None)),
            bool(getattr(args, "tls_cert", None)),
            bool(getattr(args, "tls_server_name", None)),
        )
    ):
        console.error("--plaintext cannot be combined with TLS options")
        return 2
    return None


__all__ = ["validate_args"]
