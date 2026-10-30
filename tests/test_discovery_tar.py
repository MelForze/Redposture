"""Focused contracts for the bounded TAR reader (run by the root QA owner)."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import tracemalloc

import pytest

from redposture_core.discovery_tar import open_tar_stream
from redposture_core.discovery_values import DiskBackedText


def _archive(entries, *, format=tarfile.PAX_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=format) as archive:
        for name, body, headers in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.pax_headers = headers
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def _text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("encode", [lambda value: value, gzip.compress, bz2.compress, lzma.compress])
def test_regular_members_short_nonseekable_reads_and_external_ownership(encode):
    data = encode(_archive([(".env", b"password=complete-secret\n", {})]))

    class ShortInput(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 65536
            return super().read(min(size, 7))

        def seek(self, *args):
            raise AssertionError("caller input must not be seeked")

    source = ShortInput(data)
    with open_tar_stream(source) as archive:
        member = next(iter(archive))
        assert member.name == ".env"
        with archive.extractfile(member) as stream:
            assert stream.read(65536) == b"password=complete-secret\n"
        assert list(archive) == []
    assert not source.closed


def test_large_pax_comment_and_long_path_remain_bounded_and_exact():
    name = "nested/" + "p" * 2_000_000 + "/.env"
    data = _archive([(name, b"password=complete-secret\n", {"comment": "c" * 10_000_000})])
    tracemalloc.start()
    retained_name = None
    try:
        with open_tar_stream(io.BytesIO(data)) as archive:
            member = next(iter(archive))
            retained_name = member.name
            assert isinstance(retained_name, DiskBackedText)
            assert isinstance(member.pax_headers["comment"], DiskBackedText)
            with archive.extractfile(member) as stream:
                assert stream.read(65536) == b"password=complete-secret\n"
            peak = tracemalloc.get_traced_memory()[1]
            assert peak < 8_000_000
        assert _text(retained_name) == name
    finally:
        tracemalloc.stop()
        if isinstance(retained_name, DiskBackedText):
            retained_name.close()


def test_many_members_do_not_build_a_tarinfo_catalog():
    data = _archive([(f"part-{i}", b"", {}) for i in range(40_000)])
    tracemalloc.start()
    try:
        with open_tar_stream(io.BytesIO(data)) as archive:
            count = sum(1 for _ in archive)
            peak = tracemalloc.get_traced_memory()[1]
        assert count == 40_000
        assert peak < 8_000_000
    finally:
        tracemalloc.stop()


def test_gnu_long_name_is_exact_and_disk_backed():
    name = "g" * 1_000_000 + "/.env"
    data = _archive([(name, b"password=gnu-secret\n", {})], format=tarfile.GNU_FORMAT)
    with open_tar_stream(io.BytesIO(data)) as archive:
        member = next(iter(archive))
        assert isinstance(member.name, DiskBackedText)
        assert _text(member.name) == name
        assert archive.extractfile(member).read(65536) == b"password=gnu-secret\n"


def test_deadline_checked_while_skipping_directories_and_metadata():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as writer:
        for index in range(100):
            member = tarfile.TarInfo(f"dir-{index}/")
            member.type = tarfile.DIRTYPE
            writer.addfile(member)
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == 30:
            raise TimeoutError("deadline")

    with pytest.raises(TimeoutError, match="deadline"):
        with open_tar_stream(io.BytesIO(output.getvalue()), check=check) as archive:
            list(archive)
    assert calls == 30


def test_invalid_checksum_and_truncated_member_raise():
    data = bytearray(_archive([(".env", b"password=tail-secret\n", {})]))
    data[0] ^= 1
    with pytest.raises(tarfile.ReadError):
        with open_tar_stream(io.BytesIO(data)) as archive:
            list(archive)
    good = _archive([(".env", b"x" * 4096, {})])
    with pytest.raises(tarfile.ReadError):
        with open_tar_stream(io.BytesIO(good[:1024])) as archive:
            member = next(iter(archive))
            archive.extractfile(member).read(65536)


def test_completed_member_precedes_later_truncation():
    data = _archive([("one.env", b"password=first-secret", {}), ("two.env", b"y" * 4096, {})])
    with open_tar_stream(io.BytesIO(data[:1800])) as archive:
        first = next(iter(archive))
        assert archive.extractfile(first).read(65536) == b"password=first-secret"
        second = next(iter(archive))
        with pytest.raises(tarfile.ReadError):
            archive.extractfile(second).read(65536)


def test_gzip_crc_fault_is_not_hidden_by_tar_end_padding():
    data = bytearray(gzip.compress(_archive([(".env", b"password=crc-secret", {})])))
    data[-8] ^= 1
    with pytest.raises((OSError, EOFError)):
        with open_tar_stream(io.BytesIO(data)) as archive:
            for member in archive:
                archive.extractfile(member).read(65536)


def _pax_record(key, value):
    payload = key.encode() + b"=" + value.encode() + b"\n"
    size = len(payload) + 2
    while len(str(size)) + 1 + len(payload) != size:
        size = len(str(size)) + 1 + len(payload)
    return str(size).encode() + b" " + payload


def _manual_pax_tar(records, stored, *, regular_size=None):
    extended = b"".join(_pax_record(key, value) for key, value in records)
    extension = tarfile.TarInfo("PaxHeader")
    extension.type, extension.size = tarfile.XHDTYPE, len(extended)
    member = tarfile.TarInfo("sparse.env")
    member.size = len(stored) if regular_size is None else regular_size
    return (
        extension.tobuf()
        + extended
        + b"\0" * (-len(extended) % 512)
        + member.tobuf()
        + stored
        + b"\0" * (-len(stored) % 512)
        + b"\0" * 1024
    )


@pytest.mark.parametrize("version", ["0.0", "0.1", "1.0"])
def test_sparse_extents_reconstruct_file_content(version):
    records = [("GNU.sparse.realsize", "14")]
    stored = b"abcxyz"
    if version == "0.0":
        records = [
            ("GNU.sparse.size", "14"),
            ("GNU.sparse.offset", "2"),
            ("GNU.sparse.numbytes", "3"),
            ("GNU.sparse.offset", "9"),
            ("GNU.sparse.numbytes", "3"),
        ]
    elif version == "0.1":
        records += [("GNU.sparse.map", "2,3,9,3")]
    else:
        records += [("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0")]
        rawmap = b"2\n2\n3\n9\n3\n"
        stored = rawmap + b"\0" * (-len(rawmap) % 512) + stored
    data = _manual_pax_tar(records, stored)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as expected:
        reference = next(iter(expected))
        body = expected.extractfile(reference).read()
    with open_tar_stream(io.BytesIO(data)) as archive:
        member = next(iter(archive))
        assert member.size == 14
        assert list(member.sparse) == [(2, 3), (9, 3)]
        stream = archive.extractfile(member)
        assert stream.read(4) + stream.read(65536) == body == b"\0\0abc\0\0\0\0xyz\0\0"
        assert list(archive) == []


def test_nested_extensions_have_no_python_recursion_depth_limit():
    extension = tarfile.TarInfo("PaxHeader")
    extension.type, extension.size = tarfile.XHDTYPE, 0
    member = tarfile.TarInfo(".env")
    member.size = 3
    data = extension.tobuf() * 1500 + member.tobuf() + b"abc" + b"\0" * 509 + b"\0" * 1024
    with open_tar_stream(io.BytesIO(data)) as archive:
        current = next(iter(archive))
        assert current.name == ".env"
        assert archive.extractfile(current).read(65536) == b"abc"
        assert list(archive) == []


def test_global_headers_snapshot_and_local_override_are_preserved():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", pax_headers={"comment": "global", "uid": "42"}) as writer:
        first = tarfile.TarInfo("first")
        first.pax_headers = {"comment": "local", "uid": "99"}
        writer.addfile(first)
        writer.addfile(tarfile.TarInfo("second"))
    with open_tar_stream(io.BytesIO(output.getvalue())) as archive:
        first = next(iter(archive))
        second = next(iter(archive))
        assert first.uid == 99 and first.pax_headers["comment"] == "local"
        assert second.uid == 42 and second.pax_headers["comment"] == "global"
        assert list(archive) == []


def test_sparse_pax_stored_size_does_not_confuse_logical_size_or_next_header():
    rawmap = b"1\n4096\n3\n"
    stored = rawmap + b"\0" * (-len(rawmap) % 512) + b"abc"
    records = [
        ("size", str(len(stored))),
        ("GNU.sparse.realsize", "8192"),
        ("GNU.sparse.major", "1"),
        ("GNU.sparse.minor", "0"),
    ]
    first = _manual_pax_tar(records, stored, regular_size=0)[:-1024]
    last = tarfile.TarInfo("last.env")
    last.size = 3
    data = first + last.tobuf() + b"xyz" + b"\0" * 509 + b"\0" * 1024
    with open_tar_stream(io.BytesIO(data)) as archive:
        sparse = next(iter(archive))
        assert sparse.size == 8192
        reader = archive.extractfile(sparse)
        body = reader.read(65536)
        assert body == b"\0" * 4096 + b"abc" + b"\0" * (8192 - 4099)
        following = next(iter(archive))
        assert following.name == "last.env"
        assert archive.extractfile(following).read(65536) == b"xyz"
        assert list(archive) == []


def test_pax_binary_header_uses_archive_encoding_and_preserves_unknown_metadata():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", encoding="latin-1") as writer:
        member = tarfile.TarInfo("ignored")
        member.pax_headers = {"hdrcharset": "BINARY", "path": "caf\udce9.env", "custom": "value"}
        writer.addfile(member)
    with open_tar_stream(io.BytesIO(output.getvalue()), encoding="latin-1") as archive:
        member = next(iter(archive))
        assert member.name == "caf\u00e9.env"
        assert member.pax_headers["custom"] == "value"
        assert list(archive) == []


def test_initial_sqlite_connect_failure_cleans_files_with_retained_exception(tmp_path, monkeypatch):
    import sqlite3

    import redposture_core.discovery_tar as module

    monkeypatch.setattr(module.tempfile, "tempdir", str(tmp_path))

    def failed_connect(*args, **kwargs):
        raise sqlite3.OperationalError("injected storage unavailable")

    monkeypatch.setattr(module.sqlite3, "connect", failed_connect)
    source = io.BytesIO(_archive([(".env", b"x", {})]))
    caught = None
    try:
        with open_tar_stream(source):
            pytest.fail("failed constructor yielded an archive")
    except OSError as exc:
        caught = exc
    assert caught is not None
    assert not list(tmp_path.iterdir())
    assert not source.closed


def test_pax_disk_integer_honors_runtime_digit_guard_without_dropping_raw_value():
    import sys

    old_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    raw_uid = "9" * 200_000
    try:
        data = _archive([(".env", b"x", {"uid": raw_uid})])
        with open_tar_stream(io.BytesIO(data)) as archive:
            member = next(archive)
            assert member.uid == 0
            assert isinstance(member.pax_headers["uid"], DiskBackedText)
            assert _text(member.pax_headers["uid"]) == raw_uid
            assert archive.extractfile(member).read(65536) == b"x"
    finally:
        sys.set_int_max_str_digits(old_limit)


def test_scope_finalizers_tolerate_closed_database():
    data = _archive([(".env", b"x", {"comment": "retained"})])
    with open_tar_stream(io.BytesIO(data)) as archive:
        member = next(archive)
        archive._spool.db.close()
        member.pax_headers.__del__()
        archive.pax_headers.__del__()


def test_zstd_when_available_preserves_content_short_reads_and_source_ownership():
    zstd = pytest.importorskip("compression.zstd")
    data = zstd.compress(_archive([(".env", b"password=zstd-secret\n", {})]))

    class ShortInput(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 65536
            return super().read(min(size, 7))

    source = ShortInput(data)
    with open_tar_stream(source) as archive:
        member = next(archive)
        assert archive.extractfile(member).read(65536) == b"password=zstd-secret\n"
        assert list(archive) == []
    assert not source.closed


def test_zstd_invalid_frame_is_reported_as_archive_failure_when_available():
    zstd = pytest.importorskip("compression.zstd")
    data = bytearray(zstd.compress(_archive([(".env", b"x", {})])))
    del data[-5:]
    with pytest.raises((tarfile.ReadError, EOFError, OSError)):
        with open_tar_stream(io.BytesIO(data)) as archive:
            for member in archive:
                archive.extractfile(member).read(65536)
