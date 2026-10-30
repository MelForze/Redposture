"""TAR storage faults must reach discovery's OSError/partial contract."""

from __future__ import annotations

import io
import sqlite3
import tarfile

import pytest

from redposture_core.discovery_tar import open_tar_stream


def _source():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in ("first.txt", "second.txt"):
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    output.seek(0)
    return output


def test_tar_sqlite_failure_after_first_member_is_normalized_oserror():
    source = _source()
    with open_tar_stream(source) as archive:
        first = next(archive)
        with archive.extractfile(first) as reader:
            assert reader.read(1) == b"x"
        original = archive._spool.db

        class FailingDatabase:
            def execute(self, sql, *args):
                if sql == "DELETE FROM actions":
                    raise sqlite3.OperationalError("injected disk full")
                return original.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(original, name)

        archive._spool.db = FailingDatabase()
        with pytest.raises(OSError):
            next(archive)
    assert not source.closed


def test_tar_initialization_failure_cleans_owned_files_with_retained_traceback(tmp_path, monkeypatch):
    import redposture_core.discovery_tar as module

    monkeypatch.setattr(module.tempfile, "tempdir", str(tmp_path))
    source = _source()
    caught = None

    def expired():
        raise TimeoutError("discover_time")

    try:
        with open_tar_stream(source, check=expired):
            pytest.fail("expired constructor unexpectedly succeeded")
    except TimeoutError as exc:
        caught = exc
    assert caught is not None
    assert not list(tmp_path.iterdir()), "traceback retained unfinished TAR temporary storage"
    assert not source.closed


def test_tar_pax_huge_uid_preserves_stdlib_invalid_numeric_fallback():
    import sys

    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w", format=tarfile.PAX_FORMAT) as writer:
            info = tarfile.TarInfo("app/.env")
            info.pax_headers = {"uid": "9" * 10000}
            info.size = 1
            writer.addfile(info, io.BytesIO(b"x"))
        raw = source.getvalue()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|") as baseline:
            assert next(iter(baseline)).uid == 0
        with open_tar_stream(io.BytesIO(raw)) as archive:
            member = next(archive)
            matches_fallback = member.uid == 0
            assert matches_fallback, "huge invalid PAX numeric metadata must use the stdlib fallback"
            with archive.extractfile(member) as reader:
                assert reader.read(1) == b"x"
    finally:
        sys.set_int_max_str_digits(previous)
