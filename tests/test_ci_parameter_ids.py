"""Verbose CI output must not embed full large payloads in node IDs."""

from __future__ import annotations

import pytest

from tests.conftest import pytest_make_parametrize_id


@pytest.mark.parametrize("value", ["short", b"short", "a" * 128, 123, None])
def test_small_values_keep_pytest_default_ids(value):
    assert pytest_make_parametrize_id(None, value, "payload") is None


@pytest.mark.parametrize("value", ["a" * 200_000, b"b" * 200_000, "☃" * 200_000, "\ud800" * 129])
def test_large_ids_are_bounded_deterministic_and_distinguish_the_tail(value):
    actual = pytest_make_parametrize_id(None, value, "payload")
    assert actual is not None
    assert len(actual) < 100
    assert f"len{len(value)}" in actual
    assert actual == pytest_make_parametrize_id(None, value, "payload")
    tail = b"z" if isinstance(value, bytes) else "z"
    assert actual != pytest_make_parametrize_id(None, value[:-1] + tail, "payload")
    assert actual != pytest_make_parametrize_id(None, value, "other")


def test_text_and_bytes_ids_do_not_collide_for_the_same_ascii_payload():
    assert pytest_make_parametrize_id(None, "a" * 129, "data") != pytest_make_parametrize_id(None, b"a" * 129, "data")
