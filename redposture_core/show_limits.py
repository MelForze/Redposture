"""Helpers for optional ``--show-*`` count limits."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Any, TypeVar

T = TypeVar("T")


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return number


def non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return number


def optional_show_count_kwargs(help_text: str) -> dict[str, Any]:
    return {
        "nargs": "?",
        "const": True,
        "default": False,
        "type": positive_int,
        "metavar": "count",
        "help": help_text,
    }


def optional_dump_count_kwargs(help_text: str) -> dict[str, Any]:
    return {
        "nargs": "?",
        "const": True,
        "default": False,
        "type": positive_int,
        "metavar": "count",
        "help": help_text,
    }


def show_flag_enabled(value: Any) -> bool:
    return bool(value)


def show_flag_limit(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return int(value)
    return None


def dump_flag_enabled(value: Any) -> bool:
    return bool(value)


def dump_flag_limit(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return int(value)
    return None


def limit_sequence(items: Sequence[T], limit: int | None) -> list[T]:
    values = list(items)
    if limit is None:
        return values
    return values[:limit]


def limit_metadata(items: Sequence[Any], limit: int | None) -> dict[str, Any]:
    total = len(items)
    shown = total if limit is None else min(total, limit)
    return {"limit": limit, "shown": shown, "total": total, "truncated": limit is not None and total > limit}
