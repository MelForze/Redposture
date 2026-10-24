"""Portainer input validation."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args
from ..execution_api import validate as validate_execution
from ..token_api import validate_token_args


def validate_args(args: Any, console: Any) -> int | None:
    rc = validate_basic_module_args(args, console, module="portainer", pure_http=False)
    if rc is not None:
        return rc
    if (execution_rc := validate_execution(args, console)) is not None:
        return execution_rc
    rc = validate_token_args(args, console, "portainer")
    if rc is not None:
        return rc
    token = args._portainer_token
    endpoint = getattr(args, "endpoint", None)
    if endpoint is not None and (not endpoint.strip() or any(ch in endpoint for ch in "\r\n\x00")):
        console.error("--endpoint requires a nonempty environment ID or name")
        return 2
    container = getattr(args, "container", None)
    if container is not None and (not container.strip() or any(ch in container for ch in "\r\n\x00")):
        console.error("--container requires a nonempty container ID or name")
        return 2
    if getattr(args, "execute", None) is not None and not endpoint:
        console.error("--execute requires --endpoint ID|NAME")
        return 2
    if getattr(args, "execute", None) is not None and not container:
        console.error("--execute requires --container ID|NAME")
        return 2
    args.token = token
    return None


__all__ = ["validate_args"]
