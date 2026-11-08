"""Credential URIs retain exact spelling even when userinfo spills to disk."""

from __future__ import annotations

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.secret_detection import fingerprint


def test_non_utf8_percent_password_keeps_full_carrier_identity():
    import json
    from hashlib import sha256

    from redposture_core.discovery_spool import SpoolingRecords
    from redposture_core.discovery_values import iter_json_chunks

    values = [
        next(row.value for row in analyze_value("postgres://qa:" + spelling + "@db.invalid/app") if row.available)
        for spelling in ("%FF", "%25FF", "%ff")
    ]
    assert fingerprint(values[0]) == sha256(b"postgres://qa:%FF@db.invalid/app").hexdigest()
    assert fingerprint(values[1]) == sha256(b"postgres://qa:%25FF@db.invalid/app").hexdigest()
    assert fingerprint(values[2]) != fingerprint(values[0])
    records = SpoolingRecords()
    for value in values:
        records.append({"value": value})
    records.finish()
    restored = [row["value"] for row in records]
    assert [fingerprint(value) for value in restored] == [fingerprint(value) for value in values]
    assert json.loads("".join(iter_json_chunks(restored[0]))) == "postgres://qa:%FF@db.invalid/app"
    assert json.loads("".join(iter_json_chunks(restored[1]))) == "postgres://qa:%25FF@db.invalid/app"


@pytest.mark.parametrize("entry", ["scalar", "disk", "stream"])
def test_long_binary_password_keeps_full_uri_hash_and_spelling(entry):
    import hashlib
    import json

    from redposture_core.discovery_spool import SpoolingRecords
    from redposture_core.discovery_values import iter_json_chunks

    password = "%FF" + "Ab0%CE%BB" * 12000
    body = f"postgres://qa:{password}@db.invalid/app"
    adopted = SpoolingRecords()
    if entry == "scalar":
        values = [row.value for row in analyze_value(body) if row.available]
    elif entry == "disk":
        with DiskBackedText() as disk:
            disk.append_text(body)
            disk.finish()
            rows, _, complete = _scan_portioned_value(disk, "$", 64)
            assert complete
            values = [row.value for row in rows]
            # The source lease belongs to this context. Adopt it while open.
            adopted.append({"value": values[0]})
            adopted.finish()
            values = [adopted[0]["value"]]
    else:
        rows, complete = _scan_text_chunks((body[i : i + 127] for i in range(0, len(body), 127)), "$", 64)
        assert complete
        values = [row.value for row in rows]
    assert len(values) == 1
    records = SpoolingRecords()
    records.append({"value": values[0]})
    records.finish()
    restored = records[0]["value"]
    assert fingerprint(restored) == hashlib.sha256(body.encode()).hexdigest()
    assert json.loads("".join(iter_json_chunks(restored))) == body


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize(
    "password",
    [
        "inactive%40password%CE%BB",
        "inactive%FFpassword",
        "Ab0%CE%BB" * 30000,
        "inactive@previous",
    ],
)
@pytest.mark.parametrize("entry", ["scalar", "disk", "stream"])
def test_full_carrier_exact_across_uri_source_sizes(password, entry):
    body = f"postgres://qa:{password}@db.invalid/app"
    if entry == "scalar":
        found = [row.value for row in analyze_value(body) if row.available]
    elif entry == "disk":
        with DiskBackedText() as disk:
            disk.append_text(body)
            disk.finish()
            rows, _size, complete = _scan_portioned_value(disk, "$.body", 64)
            assert complete
            found = [plain(row.value) for row in rows]
    else:
        rows, complete = _scan_text_chunks((body[i : i + 127] for i in range(0, len(body), 127)), "$.body", 64)
        assert complete
        found = [plain(row.value) for row in rows]
    assert [plain(value) for value in found] == [body]


@pytest.mark.parametrize("suffix", ["&plain,semicolon;tail", "%25%40%CE%BB", "@prior-host"])
def test_long_embedded_uri_keeps_authority_punctuation(suffix):
    password = "inactive" + "Ab0" * 30000 + suffix
    body = "connect: postgres://qa:" + password + "@db.invalid/app end"
    expected = next(row.value for row in analyze_value(body) if row.available)
    found, complete = _scan_text_chunks((body[i : i + 113] for i in range(0, len(body), 113)), "$", 64)
    assert complete
    assert [plain(row.value) for row in found] == [expected]
