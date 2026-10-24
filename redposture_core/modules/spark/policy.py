"""Validate Spark TLS and discovery options before network access."""

from typing import Any

from ...discovery_options import validate_discovery_budget
from ..execution_api import validate as validate_execution


def validate_args(args: Any, console: Any) -> int | None:
    if (result := validate_discovery_budget(args, console)) is not None:
        return result
    if (result := validate_execution(args, console)) is not None:
        return result
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be supplied together")
        return 2
    return None
