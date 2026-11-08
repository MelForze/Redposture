"""CSV known answers cross row, chunk and disk boundaries without a row cap."""

from __future__ import annotations

import hashlib

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_values import DiskBackedText


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("size", [1, 3, 64, 8191])
def test_csv_quoted_delimiters_unicode_and_newlines_are_literal(size):
    source = 'username,password\r\nqa,"inactive, λ\\path ""quoted""\r\npassword"\r\n'
    matches, complete = _scan_text_chunks((source[n : n + size] for n in range(0, len(source), size)), "$.file", 64, 0)
    assert complete, getattr(matches, "incomplete_reason", None)
    assert [(m.detector, plain(m.value), m.object_path) for m in matches] == [
        ("password", 'inactive, λ\\path "quoted"\r\npassword', "$.file.csv[1].password")
    ]


@pytest.mark.parametrize("route", ["materialized", "stream"])
def test_csv_reads_beyond_100_rows_and_retains_each_equal_value_place(route):
    source = "username,password\n" + "qa,inactive-repeated-csv-password\n" * 140
    if route == "materialized":
        matches, _size, complete = _scan_portioned_value(source, "$.file", 65_536)
    else:
        matches, complete = _scan_text_chunks((source[n : n + 17] for n in range(0, len(source), 17)), "$.file", 64, 0)
    assert complete and len(matches) == 140
    assert {m.object_path for m in matches} == {f"$.file.csv[{n}].password" for n in range(1, 141)}
    assert {plain(m.value) for m in matches} == {"inactive-repeated-csv-password"}


def test_csv_long_value_is_disk_backed_and_complete_at_closed_field():
    secret = "inactive-large-λ" * 10000
    source = 'user,password\nqa,"' + secret + '"\n'
    matches, complete = _scan_text_chunks(
        (source[n : n + 8191] for n in range(0, len(source), 8191)), "$.file", 1024, 0
    )
    assert complete and len(matches) == 1
    assert isinstance(matches[0].value, DiskBackedText)
    assert matches[0].value.digest == hashlib.sha256(secret.encode()).hexdigest()


def test_csv_incomplete_cell_does_not_publish_prefix_and_keeps_completed_row():
    source = 'user,password\nqa,first-completed-csv-password\nqa,"interrupted-csv-value'
    matches, complete = _scan_text_chunks((source[n : n + 7] for n in range(0, len(source), 7)), "$.file", 64, 0)
    assert not complete
    assert getattr(matches, "incomplete_reason", None) == "unterminated_csv_value"
    assert [plain(m.value) for m in matches] == ["first-completed-csv-password"]


@pytest.mark.parametrize("source", ["name,status\nqa,complete\n", "just,ordinary words\nno,secrets\n"])
def test_csv_neutral_headers_do_not_imply_secret_values(source):
    matches, complete = _scan_text_chunks((source[n : n + 3] for n in range(0, len(source), 3)), "$.file", 64, 0)
    assert complete and not matches
