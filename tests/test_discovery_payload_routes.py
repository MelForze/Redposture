"""Product-neutral byte sources use the same formats and exact-value policy."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

import pytest

from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText

PASSWORD = "inactive payload phrase 2026!"
TEXT = f'password="{PASSWORD}"\n'


def archive(kind: str, body: bytes) -> bytes:
    stream = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("config/app.env", body)
    else:
        with tarfile.open(fileobj=stream, mode="w") as output:
            info = tarfile.TarInfo("config/app.env")
            info.size = len(body)
            output.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize(
    "payload",
    [
        TEXT.encode(),
        TEXT.encode("utf-16"),
        b"\xfe\xff" + TEXT.encode("utf-16be"),
        b"\xef\xbb\xbf" + TEXT.encode(),
        gzip.compress(TEXT.encode()),
        archive("zip", TEXT.encode()),
        archive("tar", TEXT.encode()),
        gzip.compress(archive("tar", TEXT.encode())),
        archive("zip", TEXT.encode("utf-16")),
    ],
    ids=["utf8", "utf16le", "utf16be", "utf8bom", "gzip", "zip", "tar", "tgz", "zip-utf16"],
)
@pytest.mark.parametrize("wrapped", [False, True])
def test_common_engine_reads_full_supported_byte_source(payload, wrapped):
    value = {"body": payload} if wrapped else payload
    matches, consumed, complete = _scan_portioned_value(value, "$.source", 65536)
    assert complete, getattr(matches, "incomplete_reason", None)
    assert {text(item.value) for item in matches} == {PASSWORD}
    assert consumed >= len(payload)
    for item in matches:
        assert text(item.object_path).startswith("$.source")
        if b"config/app.env" in payload:  # uncompressed archive member locators
            assert "config/app.env" in text(item.object_path)


def test_unknown_binary_keeps_completed_text_and_reports_partial():
    payload = b'password="inactive-completed-before-binary"\n\x00\xffpassword="unfinished'
    matches, _size, complete = _scan_portioned_value(payload, "$.source", 65536)
    assert not complete
    assert getattr(matches, "incomplete_reason", None) == "binary_or_unsupported_encoding"
    assert {text(item.value) for item in matches} == {"inactive-completed-before-binary"}


def test_corrupt_gzip_reports_partial_instead_of_complete():
    payload = gzip.compress(TEXT.encode())[:-6]
    matches, _size, complete = _scan_portioned_value(payload, "$.source", 65536)
    assert not complete
    assert getattr(matches, "incomplete_reason", None) == "invalid_archive_or_payload"


def test_invalid_deflate_blocks_are_partial_instead_of_uncaught_zlib_error():
    payload = gzip.compress(TEXT.encode())
    payload = payload[:10] + b"\xff" + payload[11:]
    matches, _, complete = _scan_portioned_value(payload, "$.source", 64)
    assert not complete
    assert not matches
    assert matches.incomplete_reason == "invalid_archive_or_payload"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("quote", ['"', ""])
def test_truncated_gzip_keeps_closed_values_but_not_the_interrupted_candidate(encoding, quote):
    body = 'password="complete-before-gzip-eof"\npassword=' + quote + "interrupted-without-delimiter"
    payload = gzip.compress(body.encode(encoding))[:-6]
    matches, _size, complete = _scan_portioned_value(payload, "$.source", 64)
    assert not complete
    assert {text(item.value) for item in matches} == {"complete-before-gzip-eof"}


@pytest.mark.parametrize("prefix", [b"PK ordinary log ", b" " * 257 + b"ustar" + b" " * 250])
def test_text_lookalikes_do_not_become_false_archives(prefix):
    matches, _size, complete = _scan_portioned_value(prefix + TEXT.encode(), "$.source", 65536)
    assert complete, getattr(matches, "incomplete_reason", None)
    assert {text(item.value) for item in matches} == {PASSWORD}
