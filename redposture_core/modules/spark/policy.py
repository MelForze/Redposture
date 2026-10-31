"""Validate Spark TLS and discovery options before network access."""

from typing import Any

from ...discovery_options import validate_discovery_budget
from ..execution_api import validate as validate_execution
from ..execution_api import validate_os_shell


def validate_args(args: Any, console: Any) -> int | None:
    if (result := validate_discovery_budget(args, console)) is not None:
        return result
    if (result := validate_execution(args, console)) is not None:
        return result
    if (
        result := validate_os_shell(
            args,
            console,
            unsupported_reason=(
                "Spark submits a temporary driver and reads output from a worker log; "
                "the remote log route does not provide a reliable interactive command result"
            ),
        )
    ) is not None:
        return result
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be supplied together")
        return 2
    return None
