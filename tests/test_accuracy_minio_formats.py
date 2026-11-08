"""Object bytes must be parsed or explicitly reported as unsupported/partial."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.minio.discover import Budget, discover_secrets
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.modules.minio.payloads import scan_payload_file
from redposture_core.scheduler import NestedSchedulerCancelled


def _zip(body):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("settings.env", body)
    return stream.getvalue()


def _tar(body):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo("settings.env")
        entry.size = len(body)
        archive.addfile(entry, io.BytesIO(body))
    return stream.getvalue()


class Reader:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    def get_object_range(self, bucket, key, *, start, length, signed):
        self.calls.append((key, start, length, signed))
        body = self.bodies[key]
        return MinioResponse(
            http_status=206 if start < len(body) else 416, headers={}, body=body[start : start + length]
        )


@pytest.mark.parametrize("kind", ["zip", "gzip", "tar", "tgz", "utf16le", "utf16be", "utf16le-bom", "utf8-bom"])
@pytest.mark.parametrize("portion", [1, 3, 64])
def test_formats_preserve_full_secret_and_report_actual_complete(kind, portion):
    secret = "Audit Only λ;Full-Secret!2026"
    text = f'password="{secret}"\n'
    raw = text.encode()
    bodies = {
        "zip": _zip(raw),
        "gzip": gzip.compress(raw),
        "tar": _tar(raw),
        "tgz": gzip.compress(_tar(raw)),
        "utf16le": text.encode("utf-16le"),
        "utf16be": text.encode("utf-16be"),
        "utf16le-bom": text.encode("utf-16"),
        "utf8-bom": text.encode("utf-8-sig"),
    }
    key = "settings." + kind
    reader = Reader({key: bodies[kind]})
    result = discover_secrets(
        reader, [ObjectInfo("qa", key, len(bodies[kind]))], budget=Budget(chunk_size=portion, max_total_bytes=portion)
    )
    assert result.coverage_complete, result.partial_reasons
    values = [
        "".join(x["value"].iter_text_chunks()) if isinstance(x["value"], DiskBackedText) else x["value"]
        for x in result.findings
    ]
    assert values == [secret]
    assert result.bytes_read == len(bodies[kind]) and result.objects_scanned == 1
    assert all(length <= portion and signed for _, _, length, signed in reader.calls)
    if kind in {"zip", "tar", "tgz"}:
        assert "settings.env" in str(result.findings[0]["object_path"])
    encoded = "".join(iter_json_chunks(result.findings))
    assert "\x1b" not in encoded and "object at" not in encoded
    assert json.loads(encoded)[0]["value"] == secret


@pytest.mark.parametrize(
    "key,body",
    [
        ("broken.zip", b"PK\x03\x04incomplete"),
        ("broken.gz", gzip.compress(b'password="unfinished"')[:-5]),
        ("broken-utf16.txt", b"\xff\xfep\x00a"),
        ("binary.txt", b"\x00\x01\x00\xffpassword=not-a-text-secret\x00\xff"),
    ],
)
def test_unparsed_or_corrupt_payload_is_partial_and_next_object_survives(key, body):
    reader = Reader({key: body, "next.env": b'password="next-completed-secret"\n'})
    result = discover_secrets(reader, [ObjectInfo("qa", name, len(value)) for name, value in reader.bodies.items()])
    assert not result.coverage_complete and result.partial_reasons
    assert [x["value"] for x in result.findings] == ["next-completed-secret"]


@pytest.mark.parametrize("error", [TimeoutError, NestedSchedulerCancelled])
def test_archive_cancellation_and_deadline_propagate_and_close_spools(monkeypatch, error):
    from redposture_core.modules.minio import payloads

    spools = []
    factory = payloads.tempfile.SpooledTemporaryFile

    def retained(*args, **kwargs):
        stream = factory(*args, **kwargs)
        spools.append(stream)
        return stream

    monkeypatch.setattr(payloads.tempfile, "SpooledTemporaryFile", retained)
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == 4:
            raise error("stopped")

    with pytest.raises(error):
        scan_payload_file(
            io.BytesIO(gzip.compress(b"ordinary text\n" * 20000)),
            "$",
            publish=lambda *_: pytest.fail("interrupted source must not emit an unfinished candidate"),
            partial=lambda _: pytest.fail("cancellation must not become an archive error"),
            check=check,
        )
    assert spools and all(stream.closed for stream in spools)


def test_identical_values_in_different_archive_members_keep_both_places():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ["first.env", "second.env"]:
            archive.writestr(name, 'password="repeated-value"\n')
    body = stream.getvalue()
    result = discover_secrets(Reader({"config.zip": body}), [ObjectInfo("qa", "config.zip", len(body))])
    assert result.coverage_complete and len(result.findings) == 2
    assert [item["value"] for item in result.findings] == ["repeated-value", "repeated-value"]
    assert len({item["object_path"] for item in result.findings}) == 2


@pytest.mark.parametrize("key,encoding", [("plain.zip", "utf-8"), ("plain.gz", "utf-8"), ("ordinary.txt", "cp1251")])
def test_mislabeled_or_non_utf8_text_does_not_silently_become_complete(key, encoding):
    # Separate mislabeled valid text from the legacy text reader's completed
    # ASCII finding followed by an undecodable comment. Archive members use
    # strict whole-member validation and must not guess arbitrary encodings.
    body = 'password="ascii-secret"\n# комментарий'.encode(encoding)
    result = discover_secrets(Reader({key: body}), [ObjectInfo("qa", key, len(body))])
    assert not result.coverage_complete and result.partial_reasons
    assert [item["value"] for item in result.findings] == ["ascii-secret"]


@pytest.mark.parametrize("portion", [1, 7, 128])
@pytest.mark.parametrize("kind", ["late-nul", "utf8-fault-between", "utf8-in-value", "nul-in-value", "utf16-trailer"])
def test_partial_binary_or_encoding_keeps_only_completed_values(kind, portion):
    first = "completed-λ;first"
    second = "completed-λ;second"
    if kind == "late-nul":
        body = b"ordinary prefix\n\0" + f'password="{first}"\n'.encode() + b"\0end"
        expected = [first]
    elif kind == "utf8-fault-between":
        body = f'password="{first}"\n'.encode() + b"\xff" + f'password="{second}"\n'.encode()
        expected = [first, second]
    elif kind in {"utf8-in-value", "nul-in-value"}:
        body = b'ordinary prefix\npassword="must-not' + (b"\xff" if kind == "utf8-in-value" else b"\0") + b'-join"\n'
        expected = []
    else:
        body = f'password="{first}"\n'.encode("utf-16") + b"\x00"
        expected = [first]
    result = discover_secrets(
        Reader({"mixed.bin": body}), [ObjectInfo("qa", "mixed.bin", len(body))], budget=Budget(chunk_size=portion)
    )
    assert not result.coverage_complete and result.partial_reasons
    assert [_text_value(finding["value"]) for finding in result.findings] == expected
    assert result.bytes_read == len(body) and result.objects_scanned == 1


def _text_value(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value
