from __future__ import annotations

import argparse

import pytest

from redposture_core.show_limits import (
    dump_flag_enabled,
    dump_flag_limit,
    limit_metadata,
    limit_sequence,
    optional_dump_count_kwargs,
    optional_show_count_kwargs,
    positive_int,
    show_flag_enabled,
    show_flag_limit,
)


def test_positive_int_and_optional_argparse_kwargs() -> None:
    assert positive_int("7") == 7
    with pytest.raises(argparse.ArgumentTypeError, match="integer"):
        positive_int("abc")
    with pytest.raises(argparse.ArgumentTypeError, match="> 0"):
        positive_int("0")

    show_kwargs = optional_show_count_kwargs("show things")
    dump_kwargs = optional_dump_count_kwargs("dump things")
    assert show_kwargs["nargs"] == "?"
    assert show_kwargs["const"] is True
    assert show_kwargs["type"] is positive_int
    assert dump_kwargs["metavar"] == "count"
    assert dump_kwargs["help"] == "dump things"


def test_show_dump_flags_limits_and_metadata() -> None:
    assert show_flag_enabled(True) is True
    assert show_flag_enabled(False) is False
    assert dump_flag_enabled(3) is True
    assert dump_flag_enabled(False) is False

    assert show_flag_limit(True) is None
    assert show_flag_limit(4) == 4
    assert show_flag_limit(0) is None
    assert dump_flag_limit(True) is None
    assert dump_flag_limit(5) == 5
    assert dump_flag_limit("bad") is None

    assert limit_sequence(("a", "b", "c"), None) == ["a", "b", "c"]
    assert limit_sequence(("a", "b", "c"), 2) == ["a", "b"]
    assert limit_metadata([1, 2, 3], None) == {"limit": None, "shown": 3, "total": 3, "truncated": False}
    assert limit_metadata([1, 2, 3], 2) == {"limit": 2, "shown": 2, "total": 3, "truncated": True}
