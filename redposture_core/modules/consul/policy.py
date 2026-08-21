"""Policy helpers for the consul audit module."""

from __future__ import annotations

import re
from typing import Any

from ...stage_runtime import validate_basic_module_args
from .actions import _normalize_ssrf_urls

_HOST_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="consul", pure_http=False)
    if common_rc is not None:
        return common_rc

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
        )
    ):
        console.error("--plaintext cannot be combined with TLS options")
        return 2

    if (getattr(args, "ssrf_port", None) or getattr(args, "ssrf_path", None)) and not getattr(
        args, "ssrf_target", None
    ):
        console.error("--ssrf-port/--ssrf-path require --ssrf-target")
        return 2
    if getattr(args, "ssrf_target", None):
        try:
            ssrf_urls = _normalize_ssrf_urls(
                getattr(args, "ssrf_target", None),
                getattr(args, "ssrf_port", None),
                getattr(args, "ssrf_path", None),
            )
        except ValueError as exc:
            message = str(exc)
            if "port" in message.lower():
                console.error(f"failed to parse --ssrf-port: {message}")
            else:
                console.error(f"failed to parse SSRF targets/ports: {message}")
            return 2
        if not ssrf_urls:
            console.error("no valid SSRF targets generated")
            return 2
        args.ssrf_urls = ssrf_urls

    dump_requested = bool(getattr(args, "dump", False))
    if getattr(args, "kv_key", None) and not dump_requested:
        console.error("--key requires --dump")
        return 2
    if getattr(args, "service_dump_name", None) and not dump_requested:
        console.error("--service requires --dump")
        return 2
    if getattr(args, "agent_name", None) and not dump_requested:
        console.error("--agent requires --dump")
        return 2
    if getattr(args, "node_name", None) and not dump_requested:
        console.error("--node requires --dump")
        return 2

    delete_revshell = bool(getattr(args, "delete_revshell", False))
    check_id = str(getattr(args, "revshell_check_id", "") or "")
    revshell = bool(getattr(args, "revshell", False))
    if delete_revshell and not (revshell or check_id):
        console.error("--delete requires --revshell or --check-id")
        return 2
    if check_id == "id:":
        console.error("--check-id id:<value> requires a non-empty check id")
        return 2
    if check_id and not (revshell or delete_revshell or dump_requested):
        console.error("--check-id requires --revshell, --delete, or --dump")
        return 2
    if bool(getattr(args, "revshell_listen", False)) and not revshell:
        console.error("--listen requires --revshell")
        return 2
    if revshell and bool(getattr(args, "revshell_listen", False)) and not getattr(args, "revshell_port", None):
        console.error("--listen requires --lport")
        return 2
    if revshell and not getattr(args, "revshell_payload", None) and not delete_revshell:
        if not getattr(args, "revshell_host", None):
            console.error("--lhost is required when --revshell is set")
            return 2
        if not _HOST_RE.fullmatch(str(args.revshell_host)):
            console.error("--lhost must be a plain IPv4/DNS hostname")
            return 2
    return None


__all__ = ["validate_args"]
