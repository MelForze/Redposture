"""MinIO failed reads release reservations and retain later object findings."""

from __future__ import annotations

from typing import Any

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio import discover
from redposture_core.modules.minio.enumerate import ObjectInfo


@pytest.mark.parametrize("failure", ["exception", "transport", "server", "parse"])
def test_minio_bad_object_does_not_starve_later_object(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    paths = []
    scanner = discover._scan_portioned_value
    secret = b"password=RetainedObjectSecret2026"

    class Client:
        def get_object_range(self, bucket: str, key: str, **kwargs: Any) -> MinioResponse:
            paths.append((key, kwargs))
            if key == "bad.env":
                if failure == "exception":
                    raise OSError("reset")
                if failure == "transport":
                    return MinioResponse(0, {}, b"", transport_error="reset")
                if failure == "server":
                    return MinioResponse(503, {}, b"")
                return MinioResponse(200, {}, b"badchunk")
            return MinioResponse(200, {}, secret)

    def scan(value: Any, *args: Any, **kwargs: Any) -> Any:
        if failure == "parse" and value == "badchunk":
            raise ValueError("malformed scanner input")
        return scanner(value, *args, **kwargs)

    monkeypatch.setattr(discover, "_scan_portioned_value", scan)
    budget = discover.Budget(max_total_bytes=100, chunk_size=64)
    result = discover.discover_secrets(
        Client(), [ObjectInfo("bucket", "bad.env", 10), ObjectInfo("bucket", "good.env", len(secret))], budget=budget
    )
    assert [key for key, _ in paths] == ["bad.env", "good.env"]
    assert result.coverage_complete is False
    assert result.partial_reasons == ["parse_failure" if failure == "parse" else "read_failure"]
    assert any(f["value"] == "RetainedObjectSecret2026" for f in result.findings)
    assert budget._active_claims == 0 and budget._claimed_bytes == 0
    assert result.bytes_read == len(secret) + (8 if failure == "parse" else 0)


def test_minio_media_content_type_skips_unknown_extension_without_reading() -> None:
    class Client:
        def get_object_range(self, *args: Any, **kwargs: Any) -> Any:
            pytest.fail("Media content must not consume ranged read budget")

    result = discover.discover_secrets(
        Client(), [ObjectInfo("bucket", "neutral.blob", 100, content_type="image/png; charset=binary")]
    )
    assert result.coverage_complete is True and result.candidates == result.findings == []
    assert result.bytes_read == result.objects_scanned == 0


def test_minio_disk_full_preserves_completed_finding_and_continues_next_object(monkeypatch) -> None:
    import errno

    bodies = {
        "bad.env": b'password=BeforeDiskFullSecret\npassword="' + b"Ab0" * 1000 + b'"\n',
        "good.env": b"password=AfterDiskFullSecret\n",
    }

    class Client:
        def get_object_range(self, bucket, key, *, start, length, signed):
            return MinioResponse(206, {}, bodies[key][start : start + length])

    def full_disk(self, text):
        raise OSError(errno.ENOSPC, "No space left on device")

    from redposture_core.discovery_values import DiskBackedText

    monkeypatch.setattr(DiskBackedText, "append_text", full_disk)
    budget = discover.Budget(max_total_bytes=128, chunk_size=64)
    result = discover.discover_secrets(
        Client(), [ObjectInfo("bucket", key, len(body)) for key, body in bodies.items()], budget=budget
    )
    assert not result.coverage_complete
    assert result.partial_reasons == ["storage_failure"]
    assert {(item["type"], item["value"]) for item in result.findings} == {
        ("password", "BeforeDiskFullSecret"),
        ("password", "AfterDiskFullSecret"),
    }
    assert budget._active_claims == 0 and budget._claimed_bytes == 0
