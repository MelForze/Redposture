"""Shared CLI contract for bounded secret discovery."""

from __future__ import annotations

import argparse
import math
from typing import Any


def add_discovery_budget_flags(
    group: argparse._ArgumentGroup, *, default_time: float | None, default_bytes: int | None
) -> None:
    group.add_argument(
        "--discover-time",
        type=float,
        default=default_time,
        metavar="seconds",
        help="Total discovery time per target (unlimited by default)."
        if default_time is None
        else "Total discovery time per target.",
    )
    group.add_argument(
        "--discover-max-bytes",
        type=int,
        default=default_bytes,
        metavar="bytes",
        help="Maximum content bytes inspected per target (unlimited by default)."
        if default_bytes is None
        else "Maximum content bytes inspected per target.",
    )


def validate_discovery_budget(args: Any, console: Any) -> int | None:
    seconds = getattr(args, "discover_time", None)
    if seconds is not None and (
        isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0
    ):
        console.error("--discover-time must be a finite number > 0")
        return 2
    byte_limit = getattr(args, "discover_max_bytes", None)
    if byte_limit is not None and (isinstance(byte_limit, bool) or not isinstance(byte_limit, int) or byte_limit <= 0):
        console.error("--discover-max-bytes must be > 0")
        return 2
    return None


__all__ = ["add_discovery_budget_flags", "validate_discovery_budget"]
