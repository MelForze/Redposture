"""Bounded ZIP catalog contracts; the root QA owner runs these sequentially."""

from __future__ import annotations

import gc
import io
import sqlite3
import struct
import tracemalloc
import warnings
import zipfile
from collections.abc import Mapping, Sequence

import pytest

from redposture_core.discovery_zip import BoundedZipFile, ZipDeadlineExceeded


def _archive(entries, *, compression=zipfile.ZIP_STORED, comment=b""):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            archive.comment = comment
            for name, value in entries:
                archive.writestr(name, value)
    return output.getvalue()


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_standard_member_order_duplicates_metadata_and_compression(compression):
    raw = _archive(
        [("folder/", b""), ("same.txt", b"first"), ("caf\u00e9.txt", b"unicode"), ("same.txt", b"last")],
        compression=compression,
        comment=b"archive comment",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as expected, BoundedZipFile(io.BytesIO(raw)) as actual:
        infos = actual.infolist()
        assert isinstance(infos, Sequence)
        assert not isinstance(infos, list)
        assert isinstance(actual.NameToInfo, Mapping)
        assert not isinstance(actual.NameToInfo, dict)
        assert actual.namelist() == expected.namelist()
        assert actual.comment == expected.comment
        assert len(infos) == 4
        assert [info.filename for info in infos[::-1]] == expected.namelist()[::-1]
        assert infos[-1].filename == "same.txt"
        assert list(actual.NameToInfo) == list(expected.NameToInfo)
        assert dict(actual.NameToInfo)["same.txt"].header_offset == expected.getinfo("same.txt").header_offset
        for got, want in zip(infos, expected.infolist(), strict=True):
            assert isinstance(got, zipfile.ZipInfo)
            for field in zipfile.ZipInfo.__slots__:
                if hasattr(want, field):
                    assert getattr(got, field) == getattr(want, field), field
            assert actual.read(got) == expected.read(want)
        assert actual.read("same.txt") == b"last"
        with pytest.raises(KeyError):
            actual.getinfo("missing")


def test_legacy_name_encoding_and_utf8_precedence():
    raw = _archive([("a.txt", b"legacy"), ("\u044e.txt", b"utf8")])
    raw = raw.replace(b"a.txt", b"\xe0.txt")
    for encoding in (None, "cp1251"):
        with zipfile.ZipFile(io.BytesIO(raw), metadata_encoding=encoding) as expected:
            with BoundedZipFile(io.BytesIO(raw), metadata_encoding=encoding) as actual:
                assert actual.namelist() == expected.namelist()
                for info in actual.infolist():
                    assert actual.read(info) == expected.read(info.filename)


def test_unicode_path_extra_field_retains_original_local_name():
    info = zipfile.ZipInfo("ascii.txt")
    unicode_name = "folder/caf\u00e9.txt".encode()
    extra = struct.pack("<BL", 1, zipfile.crc32(b"ascii.txt")) + unicode_name
    info.extra = struct.pack("<HH", 0x7075, len(extra)) + extra
    info.comment = b"member comment"
    raw = _archive([(info, b"contents")])
    with zipfile.ZipFile(io.BytesIO(raw)) as expected, BoundedZipFile(io.BytesIO(raw)) as actual:
        got = actual.infolist()[0]
        want = expected.infolist()[0]
        assert got.filename == want.filename
        assert got.orig_filename == want.orig_filename == "ascii.txt"
        assert got.extra == want.extra
        assert got.comment == want.comment
        assert actual.read(got) == expected.read(want) == b"contents"


@pytest.mark.parametrize("prefix", [b"executable-prefix", _archive([("old", b"old archive")])])
def test_prepended_and_concatenated_archive_offsets(prefix):
    raw = prefix + _archive([("new", b"new archive")])
    with zipfile.ZipFile(io.BytesIO(raw)) as expected, BoundedZipFile(io.BytesIO(raw)) as actual:
        assert actual.namelist() == expected.namelist() == ["new"]
        assert actual.getinfo("new").header_offset == expected.getinfo("new").header_offset
        assert actual.read("new") == b"new archive"


@pytest.mark.parametrize("prefix", [b"", b"prepended-prefix"])
def test_zip64_directory_and_member_fields(monkeypatch, prefix):
    with monkeypatch.context() as patch:
        patch.setattr(zipfile, "ZIP64_LIMIT", 1)
        patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
        raw = prefix + _archive([("one", b"first"), ("two", b"second")])
    with zipfile.ZipFile(io.BytesIO(raw)) as expected, BoundedZipFile(io.BytesIO(raw)) as actual:
        assert actual.namelist() == expected.namelist()
        for got, want in zip(actual.infolist(), expected.infolist(), strict=True):
            assert got.header_offset == want.header_offset
            assert got.file_size == want.file_size
            assert got.compress_size == want.compress_size
            assert actual.read(got) == expected.read(want)


def test_unsigned_zip64_header_offset_is_not_limited_by_sqlite_integer_width():
    raw = bytearray(_archive([("member", b"contents")]))
    central = raw.index(b"PK\x01\x02")
    extra_at = central + 46 + len(b"member")
    extra = struct.pack("<HHQ", 1, 8, (1 << 64) - 1)
    struct.pack_into("<H", raw, central + 30, len(extra))
    struct.pack_into("<L", raw, central + 42, 0xFFFFFFFF)
    raw[extra_at:extra_at] = extra
    eocd = raw.index(b"PK\x05\x06")
    old_size = struct.unpack_from("<L", raw, eocd + 12)[0]
    struct.pack_into("<L", raw, eocd + 12, old_size + len(extra))
    with zipfile.ZipFile(io.BytesIO(raw)) as expected, BoundedZipFile(io.BytesIO(raw)) as actual:
        assert actual.getinfo("member").header_offset == expected.getinfo("member").header_offset == (1 << 64) - 1


def test_directory_import_never_requests_a_whole_large_directory():
    class ReadRequests(io.BytesIO):
        largest = 0

        def read(self, size=-1):
            assert size >= 0
            self.largest = max(self.largest, size)
            return super().read(size)

    source = ReadRequests(_archive((f"folder/member-{index:06d}", b"") for index in range(2000)))
    with BoundedZipFile(source) as archive:
        assert len(archive.infolist()) == 2000
    assert source.largest <= 65535 + 22  # Maximum format-defined EOCD comment search.


def test_short_seekable_reads_are_coalesced_without_closing_caller_stream():
    class ShortReads(io.BytesIO):
        def read(self, size=-1):
            assert size >= 0
            return super().read(min(size, 7))

    source = ShortReads(_archive([("a.txt", b"full contents"), ("b.txt", b"second contents")], comment=b"comment"))
    with BoundedZipFile(source) as archive:
        assert archive.read("a.txt") == b"full contents"
        assert archive.read("b.txt") == b"second contents"
    assert not source.closed


def test_crc_failure_preserves_previously_read_member():
    raw = bytearray(_archive([("first", b"complete"), ("broken", b"damaged-payload")]))
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo("broken")
    raw[info.header_offset + 30 + len(info.filename)] ^= 1
    with BoundedZipFile(io.BytesIO(raw)) as archive:
        assert archive.read("first") == b"complete"
        with pytest.raises(zipfile.BadZipFile, match="CRC"):
            archive.read("broken")


@pytest.mark.parametrize("case", ["encryption", "compression", "extract_version", "truncated", "central_signature"])
def test_malformed_or_unsupported_archive_errors_match_stdlib(case):
    raw = bytearray(_archive([("member", b"a sufficiently long body for encryption checks")]))
    central = raw.index(b"PK\x01\x02")
    if case == "encryption":
        struct.pack_into("<H", raw, 6, 1)
        struct.pack_into("<H", raw, central + 8, 1)
    elif case == "compression":
        struct.pack_into("<H", raw, 8, 99)
        struct.pack_into("<H", raw, central + 10, 99)
    elif case == "extract_version":
        raw[central + 6] = 99
    elif case == "truncated":
        del raw[-10:]
    else:
        raw[central] ^= 1

    def consume(cls):
        with cls(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                archive.read(info)

    with pytest.raises(Exception) as expected:
        consume(zipfile.ZipFile)
    with pytest.raises(type(expected.value)):
        consume(BoundedZipFile)


def test_overlapping_member_boundary_matches_stdlib():
    raw = bytearray(_archive([("first", b"one"), ("second", b"two")]))
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<L", raw, central + 20, 1000)
    for cls in (zipfile.ZipFile, BoundedZipFile):
        with cls(io.BytesIO(raw)) as archive:
            with pytest.raises(zipfile.BadZipFile, match="Overlapped"):
                archive.read(archive.infolist()[0])


def test_directory_only_import_and_iteration_check_deadline():
    raw = _archive([(f"folder-{index}/", b"") for index in range(100)])
    checks = 0

    def checkpoint():
        nonlocal checks
        checks += 1
        return checks < 60

    with pytest.raises(ZipDeadlineExceeded):
        BoundedZipFile(io.BytesIO(raw), check_deadline=checkpoint)
    assert checks == 60

    active = True
    with BoundedZipFile(io.BytesIO(raw), check_deadline=lambda: active) as archive:
        active = False
        with pytest.raises(ZipDeadlineExceeded):
            next(iter(archive.infolist()))


@pytest.mark.parametrize("exception", [None, TimeoutError("expired"), OSError("callback failure")])
def test_eocd_seek_does_not_swallow_deadline_callback(exception):
    checks = 0

    def checkpoint():
        nonlocal checks
        checks += 1
        # The negative EOCD seek is inside stdlib's `except OSError` block.
        if checks == 4:
            if exception is not None:
                raise exception
            return False
        return True

    expected = ZipDeadlineExceeded if exception is None else type(exception)
    with pytest.raises(expected) as caught:
        BoundedZipFile(io.BytesIO(_archive([("member", b"contents")])), check_deadline=checkpoint)
    assert checks == 4
    if exception is not None:
        assert caught.value is exception


def test_deadline_checked_after_a_decompressor_returns(monkeypatch):
    raw = _archive([("member", b"contents" * 1000)], compression=zipfile.ZIP_DEFLATED)
    active = True
    with BoundedZipFile(io.BytesIO(raw), check_deadline=lambda: active) as archive:
        with archive.open("member") as member:
            original = zipfile.ZipExtFile.read

            def read_and_expire(self, *args, **kwargs):
                nonlocal active
                result = original(self, *args, **kwargs)
                active = False
                return result

            monkeypatch.setattr(zipfile.ZipExtFile, "read", read_and_expire)
            with pytest.raises(ZipDeadlineExceeded):
                member.read(65536)


def test_deadline_checked_after_decompression_and_member_survives_archive_close():
    raw = _archive([("member", b"large contents\n" * 10000)], compression=zipfile.ZIP_DEFLATED)
    active = True
    archive = BoundedZipFile(io.BytesIO(raw), check_deadline=lambda: active)
    member = archive.open("member")
    archive.close()
    assert member.read(20) == (b"large contents\n" * 2)[:20]
    active = False
    with pytest.raises(ZipDeadlineExceeded):
        member.read(20)
    member.close()


def test_catalog_is_removed_on_close_and_failed_import(tmp_path, monkeypatch):
    import redposture_core.discovery_zip as module

    original = module.tempfile.TemporaryDirectory

    def temporary(*args, **kwargs):
        return original(*args, **kwargs, dir=tmp_path)

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)
    with BoundedZipFile(io.BytesIO(_archive([("member", b"body")]))) as archive:
        info = archive.infolist()[0]
        assert list(tmp_path.iterdir())
    assert not list(tmp_path.iterdir())
    assert info.filename == "member"
    with pytest.raises(zipfile.BadZipFile):
        BoundedZipFile(io.BytesIO(b"not a zip"))
    assert not list(tmp_path.iterdir())


def _local_catalog_directory(module, tmp_path, monkeypatch):
    original = module.tempfile.TemporaryDirectory

    def temporary(*args, **kwargs):
        return original(*args, **kwargs, dir=tmp_path)

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)


def test_catalog_disk_full_is_oserror_and_cleans_partial_import(tmp_path, monkeypatch):
    import redposture_core.discovery_zip as module

    _local_catalog_directory(module, tmp_path, monkeypatch)
    connect = module.sqlite3.connect

    class FullDatabase:
        def __init__(self, *args, **kwargs):
            self.source = connect(*args, **kwargs)

        def execute(self, sql, *args, **kwargs):
            if sql.startswith("INSERT INTO entries"):
                raise sqlite3.OperationalError("database or disk is full")
            return self.source.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.source, name)

    monkeypatch.setattr(module.sqlite3, "connect", FullDatabase)
    source = io.BytesIO(_archive([("member", b"contents")]))
    with pytest.raises(OSError) as caught:
        BoundedZipFile(source)
    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert "full" in str(caught.value.__cause__)
    assert not source.closed
    assert not list(tmp_path.iterdir())


def test_catalog_iterator_failure_is_oserror_and_preserves_read_prefix(monkeypatch):
    class BrokenCursor:
        def __init__(self, source):
            self.source = source
            self.seen = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self.seen == 1:
                raise sqlite3.DatabaseError("catalog read failed")
            self.seen += 1
            return next(self.source)

        def close(self):
            self.source.close()

    class BrokenReader:
        def __init__(self, source):
            self.source = source

        def execute(self, sql, *args, **kwargs):
            cursor = self.source.execute(sql, *args, **kwargs)
            if sql.startswith("SELECT metadata") and "BETWEEN" in sql:
                return BrokenCursor(cursor)
            return cursor

        def __getattr__(self, name):
            return getattr(self.source, name)

    with BoundedZipFile(io.BytesIO(_archive([("first", b"complete"), ("second", b"unread")]))) as archive:
        monkeypatch.setattr(archive._catalog, "_db", BrokenReader(archive._catalog.db))
        completed = []
        with pytest.raises(OSError) as caught:
            for info in archive.infolist():
                completed.append((info.filename, archive.read(info)))
        assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)
        assert completed == [("first", b"complete")]


def test_catalog_close_failure_is_oserror_and_still_removes_database(tmp_path, monkeypatch):
    import redposture_core.discovery_zip as module

    _local_catalog_directory(module, tmp_path, monkeypatch)

    class BrokenClose:
        def __init__(self, source):
            self.source = source

        def close(self):
            self.source.close()
            raise sqlite3.OperationalError("catalog close failed")

    archive = BoundedZipFile(io.BytesIO(_archive([("member", b"contents")])))
    monkeypatch.setattr(archive._catalog, "_db", BrokenClose(archive._catalog.db))
    with pytest.raises(OSError) as caught:
        archive.close()
    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert not list(tmp_path.iterdir())
    archive.close()


def test_temporary_directory_creation_failure_keeps_caller_stream_open(monkeypatch):
    import redposture_core.discovery_zip as module

    failure = OSError("temporary directory unavailable")

    def unavailable(*args, **kwargs):
        raise failure

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", unavailable)
    source = io.BytesIO(_archive([("member", b"contents")]))
    with pytest.raises(OSError) as caught:
        BoundedZipFile(source)
    assert caught.value is failure
    assert not source.closed


def test_many_member_catalog_and_extraction_keep_heap_bounded():
    count = 40000
    raw = _archive((f"folder/member-{index:06d}", b"") for index in range(count))
    gc.collect()
    tracemalloc.start()
    try:
        with BoundedZipFile(io.BytesIO(raw)) as archive:
            assert len(archive.infolist()) == count
            for index, info in enumerate(archive.infolist()):
                assert info.filename == f"folder/member-{index:06d}"
                with archive.open(info) as member:
                    assert member.read(1) == b""
            assert index + 1 == count
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8_000_000, f"ZIP catalog allocated {peak} bytes"
