"""A large discovery scalar stays on disk through output encoding."""

from __future__ import annotations

import gc
import hashlib
import json
import warnings

import pytest

from redposture_core.discovery_rendering import format_discovery_finding_line, iter_disk_discovery_finding_line_chunks
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks


def test_disk_value_streams_exact_unicode_json_and_cleans_up(tmp_path) -> None:
    value = DiskBackedText(directory=tmp_path)
    pieces = ["a" * 70_000, 'é🔑\n\\"', "tail"]
    for piece in pieces:
        value.append_text(piece)
    assert value.byte_length == len("".join(pieces).encode("utf-8"))
    assert value.digest == hashlib.sha256("".join(pieces).encode("utf-8")).hexdigest()
    with pytest.raises(RuntimeError, match="incomplete"):
        list(value.iter_text_chunks(max_chars=1024))
    value.finish()
    assert "".join(value.iter_text_chunks(max_chars=1024)) == "".join(pieces)
    assert json.loads("".join(value.iter_json_chunks(max_chars=1024))) == "".join(pieces)
    assert all(len(chunk) <= 2048 for chunk in value.iter_json_chunks(max_chars=1024))
    path = value.path
    assert path.exists()
    value.close()
    assert not path.exists()


def test_disk_value_rejects_partial_and_double_finish(tmp_path) -> None:
    value = DiskBackedText(directory=tmp_path)
    value.append_text("unclosed")
    with pytest.raises(RuntimeError, match="incomplete"):
        list(value.iter_json_chunks())
    value.finish()
    with pytest.raises(RuntimeError, match="finished"):
        value.append_text("more")
    with pytest.raises(RuntimeError, match="finished"):
        value.finish()
    value.close()


def test_disk_value_releases_temporary_file_when_last_reference_is_dropped(tmp_path) -> None:
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        value = DiskBackedText(directory=tmp_path)
        value.append_text("qa-token-abc")
        path = value.path
        del value
        gc.collect()
    assert not path.exists()
    assert not [warning for warning in caught if "redposture-discover-value" in str(warning.message)]


def test_nested_json_stream_keeps_full_disk_value_without_str_conversion(tmp_path) -> None:
    value = DiskBackedText(directory=tmp_path)
    expected = 'λ\n"' + ("opaque" * 200_000)
    for offset in range(0, len(expected), 4096):
        value.append_text(expected[offset : offset + 4096])
    value.finish()
    document = {"findings": [{"type": "secret", "value": value, "locations": ["/source"]}]}
    chunks = list(iter_json_chunks(document, max_chars=4096))
    assert json.loads("".join(chunks)) == {
        "findings": [{"type": "secret", "value": expected, "locations": ["/source"]}]
    }
    assert max(map(len, chunks)) <= 24_576
    value.close()


def test_disk_value_txt_chunks_match_short_value_format(tmp_path) -> None:
    text = "glpat-" + "x" * 1_200_000 + '\n"tail'
    with DiskBackedText(directory=tmp_path) as value:
        for offset in range(0, len(text), 4096):
            value.append_text(text[offset : offset + 4096])
        value.finish()
        actual = "".join(
            iter_disk_discovery_finding_line_chunks(
                "GITLAB", "qa", 80, finding_type="token", value=value, place="$.project/foo"
            )
        )
    expected = format_discovery_finding_line(
        "GITLAB", "qa", 80, severity="high", finding_type="token", value=text, place="$.project/foo"
    )
    assert actual == expected


def test_disk_value_preserves_crlf_and_bare_cr_in_full_output(tmp_path) -> None:
    text = "qa-secret\r\nvalue\rtail"
    with DiskBackedText(directory=tmp_path) as value:
        value.append_text(text)
        value.finish()
        assert "".join(value.iter_text_chunks(max_chars=3)) == text
        assert json.loads("".join(value.iter_json_chunks(max_chars=3))) == text
        assert value.digest == hashlib.sha256(text.encode()).hexdigest()


def test_materialized_strings_are_json_encoded_in_bounded_chunks() -> None:
    text = "ordinary-λ\r\n" * 10000
    chunks = list(iter_json_chunks({"value": text}, max_chars=1024))
    assert max(map(len, chunks)) <= 6144
    assert json.loads("".join(chunks)) == {"value": text}
