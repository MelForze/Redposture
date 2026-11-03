"""Small plain objects must not allocate the unused JSON/replay pipeline."""

from __future__ import annotations

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio import discover
from redposture_core.modules.minio.enumerate import ObjectInfo


@pytest.mark.parametrize("resource", ["json", "replay"])
def test_plain_text_object_does_not_construct_unused_resources(monkeypatch: pytest.MonkeyPatch, resource: str) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError(f"plain text does not need {resource}")

    if resource == "json":
        monkeypatch.setattr(discover, "_JSONDocuments", unexpected)
    else:
        monkeypatch.setattr(discover.tempfile, "SpooledTemporaryFile", unexpected)

    class Client:
        def get_object_range(self, *args, **kwargs):
            return MinioResponse(http_status=206, headers={}, body=b'password="completed-secret"\n')

    result = discover.discover_secrets(Client(), [ObjectInfo(bucket="qa", key="config.env", size=28)])
    assert result.coverage_complete and result.objects_scanned == 1
    assert [(v["type"], v["value"], v["object_path"]) for v in result.findings] == [
        ("password", "completed-secret", "$")
    ]


@pytest.mark.parametrize("chunk_size", [1, 3, 64])
@pytest.mark.parametrize("format", ["json", "ndjson", "plain"])
def test_lazy_readers_keep_chunked_unicode_paths_and_values(chunk_size: int, format: str) -> None:
    import json

    if format == "json":
        body = json.dumps({"service": {"password": "секрет-λ"}}, ensure_ascii=False).encode()
        expected = [("секрет-λ", "$.service.password")]
    elif format == "ndjson":
        body = b'{"password":"first-secret"}\n{"password":"second-secret"}'
        expected = [("first-secret", "$.password"), ("second-secret", "$.password")]
    else:
        body = '   password="секрет-λ"\n'.encode()
        expected = [("секрет-λ", "$")]

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    result = discover.discover_secrets(
        Client(),
        [ObjectInfo(bucket="qa", key="config." + ("env" if format == "plain" else "json"), size=len(body))],
        budget=discover.Budget(chunk_size=chunk_size),
    )
    assert result.coverage_complete and result.objects_scanned == 1
    assert result.bytes_read == len(body)
    assert [(item["value"], item["object_path"]) for item in result.findings] == expected
