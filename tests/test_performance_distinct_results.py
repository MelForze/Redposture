"""Known full rows and bounded independent JSON/TXT quality checks."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import sqlite3
from argparse import Namespace
from contextlib import closing
from typing import Any

import pytest

from scripts.profile_result_performance import (
    PLACE,
    JSONCursor,
    measure,
    unique_value,
    verify_json,
    verify_txt,
    write_payload,
)


def corpus(tmp_path, count=3):
    data, expected = tmp_path / "input", tmp_path / "expected.sqlite3"
    assert write_payload(data, count * 1024 + 13, expected) == count
    findings = [
        {
            "type": "password",
            "confidence": "high",
            "value": unique_value(index),
            "fingerprint": hashlib.sha256(unique_value(index).encode()).hexdigest(),
            "object_path": PLACE,
            "source": "anonymous",
        }
        for index in range(count)
    ]
    result: dict[str, Any] = {
        "status": "complete",
        "bytes_read": data.stat().st_size,
        "bytes_inspected": data.stat().st_size,
        "source": "anonymous",
        "findings": findings,
        "partial_reasons": [],
        "live_emitted": True,
        "emitted_fingerprints": sorted(row["fingerprint"] for row in findings),
    }
    return data, expected, result


def test_exact_length_unique_golden_rows_and_disk_identity_catalogue(tmp_path):
    data, expected, result = corpus(tmp_path)
    assert unique_value(0) == "processing-unique-000000000-5feceb66ffc86f38d952786c6d696c79"
    raw = data.read_bytes()
    assert len(raw) == 3085 and raw[-13:] == b" " * 13
    assert all(
        raw[index * 1024 : (index + 1) * 1024].startswith(("password=" + unique_value(index)).encode())
        for index in range(3)
    )
    with closing(sqlite3.connect(expected)) as db:
        assert [row[0] for row in db.execute("SELECT fingerprint FROM known ORDER BY fingerprint")] == result[
            "emitted_fingerprints"
        ]


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 1024])
def test_independent_decoder_handles_escapes_unicode_and_numbers_across_chunks(chunk):
    value = {"name": '雪❄"\\', "rows": [12345678, -123, 1.25, True, None]}
    cursor = JSONCursor(io.StringIO(json.dumps(value, ensure_ascii=False)), chunk=chunk)
    assert cursor.value() == value and cursor.peek() == ""


def test_full_serialized_result_and_live_txt_pass(tmp_path):
    _, expected, result = corpus(tmp_path)
    path = tmp_path / "result.json"
    path.write_text(json.dumps(result))
    verify_json(path, 3, expected)
    txt = tmp_path / "result.txt"
    txt.write_text(
        "".join(f'JENKINS\tqa\t80\t [!] Pass Value="{unique_value(index)}" Place="{PLACE}"\n' for index in range(3))
    )
    verify_txt(txt, 3)


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "duplicate",
        "order",
        "value",
        "type",
        "place",
        "fingerprint",
        "source",
        "confidence",
        "partial",
        "emission",
        "emission-missing",
        "negative-bytes",
        "false-complete",
        "truncated",
        "extra-root",
        "duplicate-root",
    ],
)
def test_json_gate_rejects_wrong_values_even_when_counts_match(tmp_path, damage):
    _, expected, original = corpus(tmp_path)
    result = copy.deepcopy(original)
    rows = result["findings"]
    if damage == "missing":
        rows.pop()
    elif damage == "duplicate":
        rows[-1] = rows[0]
    elif damage == "order":
        rows.reverse()
    elif damage in {"value", "type", "source", "confidence", "fingerprint"}:
        rows[0][damage] = "wrong"
    elif damage == "place":
        rows[0]["object_path"] = "$.wrong"
    elif damage == "partial":
        result["status"] = "partial"
        result["partial_reasons"] = ["interrupted"]
    elif damage == "emission":
        result["emitted_fingerprints"][1] = result["emitted_fingerprints"][0]
    elif damage == "emission-missing":
        result["emitted_fingerprints"].pop()
    elif damage == "negative-bytes":
        result["bytes_read"] = -1
    elif damage == "false-complete":
        result["partial_reasons"] = ["interrupted"]
    elif damage == "extra-root":
        result["unexpected"] = True
    raw = json.dumps(result)
    if damage == "truncated":
        raw = raw[:-1]
    if damage == "duplicate-root":
        raw = '{"status":"complete",' + raw[1:]
    path = tmp_path / "bad.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        verify_json(path, 3, expected)


@pytest.mark.parametrize("damage", ["missing", "extra", "order", "truncation", "ansi", "kind"])
def test_txt_gate_rejects_partial_or_changed_full_values(tmp_path, damage):
    rows = [f'JENKINS\tqa\t80\t [!] Pass Value="{unique_value(index)}" Place="{PLACE}"\n' for index in range(3)]
    if damage == "missing":
        rows.pop()
    elif damage == "extra":
        rows.append(rows[0])
    elif damage == "order":
        rows.reverse()
    elif damage == "truncation":
        rows[0] = rows[0].replace(unique_value(0), unique_value(0)[:12] + "...")
    elif damage == "ansi":
        rows[0] = "\x1b[31m" + rows[0]
    elif damage == "kind":
        rows[0] = rows[0].replace("Pass", "Token")
    path = tmp_path / "bad.txt"
    path.write_text("".join(rows))
    with pytest.raises(ValueError):
        verify_txt(path, 3)


def test_bounded_verifier_does_not_accept_unterminated_giant_fixture_scalar():
    cursor = JSONCursor(io.StringIO('"' + "x" * 300000))
    with pytest.raises(ValueError, match="bounded verifier"):
        cursor.value()


def test_profile_requires_real_snapshot_and_never_imports_live_core_for_empty_source(tmp_path):
    with pytest.raises(ValueError, match="source must contain"):
        measure(Namespace(source=tmp_path))


def test_fixture_rejects_too_short_size_and_preexisting_catalogue(tmp_path):
    with pytest.raises(ValueError):
        write_payload(tmp_path / "input", 1000, tmp_path / "expected")
    (tmp_path / "expected").touch()
    with pytest.raises(ValueError):
        write_payload(tmp_path / "input", 1024, tmp_path / "expected")


def test_main_retains_explicit_failed_artifact_instead_of_missing_result(tmp_path, monkeypatch):
    from scripts import profile_result_performance as profile

    source = tmp_path / "source"
    (source / "redposture_core").mkdir(parents=True)
    (source / "redposture_core/__init__.py").write_text("")
    destination = tmp_path / "failed.json"

    def fail(_args):
        raise RuntimeError("intentional verifier failure")

    monkeypatch.setattr(profile, "measure", fail)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    monkeypatch.setattr(profile.sys, "argv", ["profile", "--source", str(source), "--output", str(destination)])
    with pytest.raises(RuntimeError, match="intentional verifier failure"):
        profile.main()
    result = json.loads(destination.read_text())
    assert result["quality"] == "FAIL" and result["error_type"] == "RuntimeError"
    assert result["error"] == "intentional verifier failure"
    assert len(result["source_sha256"]) == len(result["profile_sha256"]) == 64
