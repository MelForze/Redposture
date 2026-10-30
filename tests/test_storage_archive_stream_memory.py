"""Compressed OCI layers must stay bounded before member scanning starts."""

from __future__ import annotations

import hashlib
import io
import tarfile
import tracemalloc
from types import SimpleNamespace

from redposture_core.storage_discovery import DiscoveryCollector


def test_gzip_tar_expansion_is_bounded_before_member_reader():
    size = 100_000_000

    class Repeat:
        remaining = size

        def read(self, amount):
            count = min(amount, self.remaining)
            self.remaining -= count
            return b"Z" * count

    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        info = tarfile.TarInfo("app/data.txt")
        info.size = size
        archive.addfile(info, Repeat())
    compressed.seek(0)
    expected = hashlib.sha256()
    for _ in range(1000):
        expected.update(b"Z" * 100000)
    seen = []

    class Collector(DiscoveryCollector):
        def _scan_member_stream(self, source, name, stream, *, object_path=None, charge=True, prefer_specific=False):
            digest = hashlib.sha256()
            count = 0
            while piece := stream.read(65536):
                assert len(piece) <= 65536
                count += len(piece)
                digest.update(piece)
            seen.append((name, count, digest.hexdigest()))

    context = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    collector = Collector("harbor", context, {"status": "open_no_auth"})
    tracemalloc.start()
    try:
        collector.scan_archive_file("image/qa/layer", compressed, "tar")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert seen == [("app/data.txt", size, expected.hexdigest())]
    assert peak < 8_000_000, f"gzip expansion allocated {peak} bytes before bounded member reads"


def test_gzip_tar_bad_trailer_is_partial_and_preserves_completed_finding():
    content = b"PASSWORD=qa-archive-secret\n"
    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        info = tarfile.TarInfo("app/.env")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    damaged = bytearray(compressed.getvalue())
    damaged[-8] ^= 1
    context = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    collector = DiscoveryCollector("harbor", context, {"status": "open_no_auth"})
    collector.scan_archive_file("image/qa/layer", io.BytesIO(damaged), "tar")
    result = collector.result()
    assert result["status"] == "partial"
    assert any("archive_error" in item for item in result["partial_reasons"])
    assert any(finding["value"] == "qa-archive-secret" for finding in result["findings"])


def test_gzip_tar_probe_preserves_nonseekable_short_reads():
    content = b"PASSWORD=qa-nonseekable-secret\n"
    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        info = tarfile.TarInfo("app/.env")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    class NonSeekable:
        source = io.BytesIO(compressed.getvalue())

        def read(self, amount):
            assert amount >= 0
            return self.source.read(min(amount, 7))

    context = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    collector = DiscoveryCollector("harbor", context, {"status": "open_no_auth"})
    collector.scan_archive_file("image/qa/layer", NonSeekable(), "tar")
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [finding["value"] for finding in result["findings"]] == ["qa-nonseekable-secret"]


def _many_members(kind, count):
    import zipfile

    output = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w") as archive:
            for index in range(count):
                archive.writestr(f"app/file-{index:06d}.txt", b"")
    else:
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for index in range(count):
                archive.addfile(tarfile.TarInfo(f"app/file-{index:06d}.txt"))
    output.seek(0)
    return output


def _check_member_catalog_memory(kind):
    import gc

    count = 40000
    compressed = _many_members(kind, count)
    seen = 0

    class Collector(DiscoveryCollector):
        def _scan_member_stream(self, source, name, stream, *, object_path=None, charge=True, prefer_specific=False):
            nonlocal seen
            assert name == f"app/file-{seen:06d}.txt"
            assert stream.read(1) == b""
            seen += 1

    gc.collect()
    collector = Collector(
        "harbor", SimpleNamespace(args=SimpleNamespace(discover_time=900)), {"status": "open_no_auth"}
    )
    tracemalloc.start()
    try:
        collector.scan_archive_file("image/qa/layer", compressed, kind)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert seen == count
    assert peak < 8_000_000, f"{kind} catalog retained {peak} bytes for {count} members"


def test_tar_member_catalog_does_not_accumulate_all_tarinfo_objects():
    _check_member_catalog_memory("tar")


def test_zip_member_catalog_does_not_materialize_the_central_directory():
    _check_member_catalog_memory("zip")


def test_tar_large_pax_comment_does_not_materialize_metadata_before_small_secret():
    import gc

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("app/.env")
        info.pax_headers = {"comment": "metadata" * 3125000}
        content = b"PASSWORD=qa-after-pax-secret\n"
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    del archive, info
    output.seek(0)
    gc.collect()
    collector = DiscoveryCollector(
        "harbor", SimpleNamespace(args=SimpleNamespace(discover_time=900)), {"status": "open_no_auth"}
    )
    tracemalloc.start()
    try:
        collector.scan_archive_file("image/qa/layer", output, "tar")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [finding["value"] for finding in result["findings"]] == ["qa-after-pax-secret"]
    assert peak < 8_000_000, f"PAX metadata allocated {peak} heap bytes"


def _check_directory_archive_deadline(kind, monkeypatch):
    import zipfile

    import redposture_core.storage_discovery as module

    source = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(source, "w") as archive:
            for index in range(2000):
                archive.writestr(f"directory-{index:06d}/", b"")
    else:
        with tarfile.open(fileobj=source, mode="w") as tar_archive:
            for index in range(2000):
                info = tarfile.TarInfo(f"directory-{index:06d}/")
                info.type = tarfile.DIRTYPE
                tar_archive.addfile(info)
    clock = [0.0]

    class TimedReader(io.BytesIO):
        def read(self, size=-1):
            data = super().read(size)
            clock[0] += len(data) / 4096
            return data

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    collector = DiscoveryCollector(
        "harbor", SimpleNamespace(args=SimpleNamespace(discover_time=1)), {"status": "open_no_auth"}
    )
    collector.scan_archive_file("image/qa/layer", TimedReader(source.getvalue()), kind)
    result = collector.result()
    assert result["status"] == "partial", result
    assert "discover_time" in result["partial_reasons"]


def test_tar_directory_only_archive_obeys_deadline(monkeypatch):
    _check_directory_archive_deadline("tar", monkeypatch)


def test_zip_directory_only_archive_obeys_deadline(monkeypatch):
    _check_directory_archive_deadline("zip", monkeypatch)


def test_archive_member_disk_name_preserves_full_plaintext_and_json_paths():
    from redposture_core.discovery_values import DiskBackedText

    name = "app/" + "q" * 100000 + ".env"
    disk = DiskBackedText()
    disk.append_text(name)
    disk.finish()
    try:
        for content in (b"PASSWORD=qa-long-path-secret\n", b'{"password":"qa-long-path-secret"}'):
            values = []
            for member_name in (name, disk):
                collector = DiscoveryCollector(
                    "harbor", SimpleNamespace(args=SimpleNamespace(discover_time=900)), {"status": "open_no_auth"}
                )
                collector._scan_member_stream("image/qa/layer", member_name, io.BytesIO(content))
                result = collector.result()
                assert result["status"] == "complete", result["partial_reasons"]
                assert len(result["findings"]) == 1
                finding = result["findings"][0]
                found_value = finding["value"]
                text = (
                    "".join(found_value.iter_text_chunks()) if isinstance(found_value, DiskBackedText) else found_value
                )
                assert text == "qa-long-path-secret"
                path = finding["object_path"]
                values.append("".join(path.iter_text_chunks()) if isinstance(path, DiskBackedText) else path)
            assert values[0] == values[1]
            assert name in values[1]
    finally:
        disk.close()


def test_readable_empty_zip_is_complete_without_findings():
    import zipfile

    source = io.BytesIO()
    with zipfile.ZipFile(source, "w"):
        pass
    source.seek(0)
    collector = DiscoveryCollector(
        "harbor", SimpleNamespace(args=SimpleNamespace(discover_time=900)), {"status": "open_no_auth"}
    )
    collector.scan_archive_file("image/qa/layer", source, "zip")
    result = collector.result()
    assert result["status"] == "complete", result
    assert result["findings"] == []
