"""YARN read budgets and TLS input validation."""

from typing import Any

from ...discovery_options import validate_discovery_budget
from ..execution_api import validate as validate_execution
from ..execution_api import validate_os_shell


def validate_args(args: Any, console: Any) -> int | None:
    if (error := validate_discovery_budget(args, console)) is not None:
        return error
    if (error := validate_execution(args, console)) is not None:
        return error
    if (
        error := validate_os_shell(
            args,
            console,
            unsupported_reason=(
                "YARN submits a temporary application and reads output from a node log; "
                "the remote log route does not provide a reliable interactive command result"
            ),
        )
    ) is not None:
        return error
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be supplied together")
        return 2
    return None
