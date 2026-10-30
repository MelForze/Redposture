"""Shared CLI contract for bounded secret discovery."""

from __future__ import annotations

import argparse
import math
import sys
from typing import Any

DEFAULT_DISCOVER_TIME = 900.0
UNLIMITED_DISCOVER_BYTES = sys.maxsize
# Internal readers retain a bounded per-request or per-value portion. The CLI
# no longer exposes this as a target-wide cumulative budget.
DEFAULT_DISCOVER_MAX_BYTES = 300_000_000


def add_discovery_budget_flags(
    group: argparse._ArgumentGroup,
    *,
    default_time: float | None = DEFAULT_DISCOVER_TIME,
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


def validate_discovery_budget(args: Any, console: Any) -> int | None:
    seconds = getattr(args, "discover_time", None)
    if seconds is not None and (
        isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0
    ):
        console.error("--discover-time must be a finite number > 0")
        return 2
    return None


__all__ = [
    "DEFAULT_DISCOVER_MAX_BYTES",
    "DEFAULT_DISCOVER_TIME",
    "UNLIMITED_DISCOVER_BYTES",
    "add_discovery_budget_flags",
    "validate_discovery_budget",
]
