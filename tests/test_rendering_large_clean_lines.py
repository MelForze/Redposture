"""Large clean report values must not need a second full payload copy."""

from __future__ import annotations

import hashlib
import tracemalloc

import pytest

from redposture_core.rendering import (
    format_report_line_for_console,
    normalize_report_line_for_storage,
    order_detection_fields,
    sanitize_report_line,
)


def test_large_clean_finding_preserves_every_byte_without_copying_payload():
    line = 'ELASTIC\t127.0.0.1\t9200\t[!] Token Value="' + "a" * 10_000_000 + '" Place="/source"'
    expected = hashlib.sha256(line.encode()).digest()
    tracemalloc.start()
    try:
        result = sanitize_report_line(line)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert hashlib.sha256(result.encode()).digest() == expected
    assert peak < 256 * 1024, f"clean-line processing copied a large payload: {peak} bytes"


@pytest.mark.parametrize("control", ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85"])
def test_large_value_scrubs_only_controls_after_structural_separators(control):
    value = "a" * 100_000
    line = f"ELASTIC\thost\t9200\t[!] {value}{control}tail"
    assert sanitize_report_line(line) == f"ELASTIC\thost\t9200\t[!] {value} tail"


@pytest.mark.parametrize("line", ['{"value":"unchanged"}', "summary", "a\tb\tc", "a\tb"])
def test_non_record_lines_keep_their_existing_contract(line):
    assert sanitize_report_line(line) == line


@pytest.mark.parametrize(
    ("function", "prefix", "suffix"),
    [
        (normalize_report_line_for_storage, "ELASTIC\thost\t9200\t[!] ", ""),
        (format_report_line_for_console, f"{'ELASTIC':<15}\thost\t9200\t[!] ", ""),
        (order_detection_fields, 'ELASTIC\thost\t9200\t[!] Value="', '(version:literal)"'),
        (order_detection_fields, "ELASTIC\thost\t9200\t[*] Elastic (auth required:True) ", " (version:8.0.0)"),
    ],
)
def test_unchanged_large_line_does_not_copy_its_payload(function, prefix, suffix):
    line = prefix + "a" * 10_000_000 + suffix
    expected = hashlib.sha256(line.encode()).digest()
    tracemalloc.start()
    try:
        result = function(line)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert hashlib.sha256(result.encode()).digest() == expected
    assert peak < 256 * 1024, f"unchanged-line processing copied its payload: {peak} bytes"


@pytest.mark.parametrize("size", [65535, 65536, 65537])
@pytest.mark.parametrize("position", [0, 1023, 1024, -1])
@pytest.mark.parametrize("control", [chr(value) for value in (*range(32), 127)])
def test_large_ascii_path_scrubs_every_control_at_chunk_and_size_boundaries(size, position, control):
    payload = "a" * size
    position %= size
    dirty = payload[:position] + control + payload[position + 1 :]
    expected = payload[:position] + " " + payload[position + 1 :]
    assert sanitize_report_line("M\thost\t1\t" + dirty) == "M\thost\t1\t" + expected


@pytest.mark.parametrize("control", [chr(value) for value in range(127, 160)])
def test_non_ascii_c1_controls_remain_scrubbed_in_large_utf8_values(control):
    payload = "текст " * 12000
    assert sanitize_report_line("M\thost\t1\t" + payload + control) == "M\thost\t1\t" + payload + " "


def test_large_clean_unicode_remains_complete_without_temporary_copy():
    line = "M\thost\t1\t" + "текст " * 100000
    tracemalloc.start()
    try:
        result = sanitize_report_line(line)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == line and peak < 256 * 1024
