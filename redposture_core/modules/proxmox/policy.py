"""Policy helpers for the proxmox audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args
from . import actions


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="proxmox", pure_http=False)
    if common_rc is not None:
        return common_rc
    token = str(getattr(args, "pve_api_token", None) or getattr(args, "pveapitoken", "") or "").strip()
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if not token and not (username is not None and password is not None) and not bool(getattr(args, "defcreds", False)):
        console.error("--pveapitoken, -u/-p, or --defcreds is required")
        return 2
    proxy = getattr(args, "proxy", None)
    if proxy:
        _config, error = actions._parse_proxy_config(str(proxy))
        if error:
            console.error(f"failed to parse --proxy: {error}")
            return 2
    return None


__all__ = ["validate_args"]
