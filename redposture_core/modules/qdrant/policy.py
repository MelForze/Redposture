"""Policy helpers for the qdrant audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="qdrant")
    if common_rc is not None:
        return common_rc
    if bool(getattr(args, "ssrf_listen", False)) and not getattr(args, "ssrf_target", None):
        console.error("--listen requires --ssrf-target")
        return 2
    if getattr(args, "ssrf_target", None) and not getattr(args, "collection", None):
        console.error("--ssrf-target requires --collection")
        return 2
    if getattr(args, "ssrf_target", None) or getattr(args, "ssrf_port", None) or getattr(args, "ssrf_path", None):
        from .actions import _normalize_ssrf_urls

        try:
            urls = _normalize_ssrf_urls(
                getattr(args, "ssrf_target", None),
                getattr(args, "ssrf_port", None),
                getattr(args, "ssrf_path", None),
            )
        except ValueError as exc:
            console.error(f"failed to parse SSRF targets/ports: {exc}")
            return 2
        if not urls:
            console.error("failed to build SSRF URLs")
            return 2
        args.ssrf_urls = urls
    return None


__all__ = ["validate_args"]
