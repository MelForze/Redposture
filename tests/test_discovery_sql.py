"""SQL grammar keeps exact values consistently across source sizes and chunks."""

from __future__ import annotations

import pytest

from redposture_core.discovery_engine import _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText


def text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("inactive''quote-password", "inactive'quote-password"),
        (r"inactive\nraw-password", r"inactive\nraw-password"),
        ("inactive-" + "Ab0λ " * 20000, "inactive-" + "Ab0λ " * 20000),
    ],
)
@pytest.mark.parametrize("portion", [3, 64, 65536])
def test_unknown_sql_dialect_preserves_backslashes_and_decodes_doubled_delimiter(raw, expected, portion):
    body = "ALTER USER qa IDENTIFIED BY '" + raw + "';\n"
    small = {text(row.value) for row in analyze_value(body) if row.available}
    found, complete = _scan_text_chunks((body[i : i + portion] for i in range(0, len(body), portion)), "$", 64)
    assert complete, getattr(found, "incomplete_reason", None)
    assert {text(row.value) for row in found} == small == {expected}


def test_interrupted_sql_retains_only_preceding_completed_password():
    body = "CREATE USER first IDENTIFIED BY 'inactive-first-password';\nALTER USER second IDENTIFIED BY 'unfinished"
    found, complete = _scan_text_chunks(iter([body]), "$", 64)
    assert not complete
    assert {text(row.value) for row in found} == {"inactive-first-password"}


@pytest.mark.parametrize(
    "dialect,raw,expected",
    [
        ("unknown", r"inactive\npassword", r"inactive\npassword"),
        ("standard", r"inactive\npassword", r"inactive\npassword"),
        ("mysql", r"inactive\npassword", "inactive\npassword"),
    ],
)
def test_declared_dialect_matches_scalar_and_stream(dialect, raw, expected):
    from redposture_core.discovery_text import DiscoveryTextStream
    from redposture_core.secret_detection import SecretMatch

    body = "ALTER USER qa IDENTIFIED BY '" + raw + "';"
    emitted, errors = [], []
    scanner = DiscoveryTextStream(emitted.append, errors.append, portion=64, sql_dialect=dialect)
    try:
        for char in body:
            scanner.feed(char)
        scanner.finish()
    finally:
        scanner.close()
    assert not errors
    assert [text(item.value) for item in emitted if isinstance(item, SecretMatch)] == [expected]
    assert {text(row.value) for row in analyze_value(body, sql_dialect=dialect) if row.available} == {expected}
