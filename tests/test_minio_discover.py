from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import discover
from redposture_core.modules.minio.enumerate import ObjectInfo


class _Client:
    def __init__(self, bodies):
        self._bodies = bodies  # dict key -> (status, body) or Exception
        self.ranges: list[tuple[str, int, int]] = []

    def get_object_range(self, bucket, key, *, start=0, length, signed):
        self.ranges.append((key, start, length))
        v = self._bodies.get(key)
        if isinstance(v, Exception):
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error=str(v))
        status, body = v
        # Real S3 answers a range that starts past the object end with 416.
        if status == 200 and start >= len(body) and length > 0:
            return MinioResponse(http_status=416, headers={}, body=b"", error=S3Error(416, "InvalidRange", ""))
        # Honor the requested byte range so chunked reads advance through the object.
        return MinioResponse(
            http_status=status,
            headers={},
            body=body[start : start + length],
            error=None if status < 400 else S3Error(status, "AccessDenied", ""),
        )


def _obj(key, size=10, bucket="b"):
    return ObjectInfo(bucket=bucket, key=key, size=size)


def test_is_candidate_key():
    assert discover.is_candidate_key(".env")
    assert discover.is_candidate_key("app/id_rsa")
    assert discover.is_candidate_key("infra/terraform.tfstate")
    assert discover.is_candidate_key("k8s/kubeconfig")
    assert discover.is_candidate_key("neutral.txt") is None


def test_discover_finds_secret_via_shared_engine_with_full_value():
    body = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    client = _Client({".env": (200, body)})
    res = discover.discover_secrets(client, [_obj(".env")])
    assert res.objects_scanned == 1
    assert res.findings
    finding = res.findings[0]
    # the full value is kept for output; masked is still available for JSON callers
    assert finding["value"] and finding["value"] != finding["masked_value"]
    assert res.coverage_complete is True


def test_large_object_scanned_in_chunks_not_skipped():
    # A secret near the start, then padding beyond the per-object cap: the object is
    # read in ranged chunks up to max_object_size (not skipped), and flagged truncated.
    body = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" + b"z" * 500
    client = _Client({"big.env": (200, body)})
    budget = discover.Budget(max_object_size=200, chunk_size=64)
    res = discover.discover_secrets(client, [_obj("big.env", size=len(body))], budget=budget)
    assert res.objects_scanned == 1  # scanned, never skipped
    assert res.bytes_read == 200  # read up to the per-object cap, in chunks
    assert len({r[1] for r in client.ranges}) > 1  # multiple ranged reads (chunked)
    assert res.findings  # secret in the first chunk still found
    assert "object_truncated" in res.partial_reasons
    assert "object_too_large" not in res.partial_reasons


def test_secret_across_chunk_boundary_is_found_via_overlap():
    secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    body = ("x" * 20 + secret).encode()  # secret straddles small chunk boundaries
    client = _Client({".env": (200, body)})
    budget = discover.Budget(chunk_size=24, max_object_size=10_000)
    res = discover.discover_secrets(client, [_obj(".env", size=len(body))], budget=budget)
    assert len({r[1] for r in client.ranges}) > 1  # actually chunked
    assert res.findings  # found despite crossing a chunk boundary
    # overlap must not double-count the same secret
    assert len(res.findings) == len({(f["type"], f["value"]) for f in res.findings})


def test_object_size_exact_chunk_multiple_ends_cleanly():
    # body length is an exact multiple of the chunk size: the read at EOF returns
    # 416, which must be treated as end-of-object (not read_failure / not truncated).
    secret = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    body = secret + b"z" * (128 - len(secret))  # exactly 128 bytes
    assert len(body) == 128
    client = _Client({".env": (200, body)})
    budget = discover.Budget(chunk_size=64, max_object_size=10_000)
    res = discover.discover_secrets(client, [_obj(".env", size=128)], budget=budget)
    assert res.objects_scanned == 1
    assert res.findings
    assert "read_failure" not in res.partial_reasons
    assert "object_truncated" not in res.partial_reasons
    assert res.coverage_complete is True


def test_object_limit_makes_partial():
    client = _Client({"a.env": (200, b"x"), "b.env": (200, b"y")})
    budget = discover.Budget(max_objects=1)
    res = discover.discover_secrets(client, [_obj("a.env"), _obj("b.env")], budget=budget)
    assert "object_limit" in res.partial_reasons
    assert res.coverage_complete is False


def test_permission_denied_partial():
    client = _Client({"secret.env": (403, b"")})
    res = discover.discover_secrets(client, [_obj("secret.env")])
    assert "permission_denied" in res.partial_reasons
    assert res.objects_scanned == 0


def test_binary_object_does_not_crash():
    client = _Client({"dump.bak": (200, bytes(range(256)))})
    res = discover.discover_secrets(client, [_obj("dump.bak")])
    assert res.objects_scanned == 1  # decoded with errors='replace', no crash


def test_non_candidate_keys_are_skipped():
    client = _Client({})
    res = discover.discover_secrets(client, [_obj("photo.png"), _obj("readme.md")])
    assert res.objects_scanned == 0
    assert res.candidates == []


def test_truncated_listing_marks_partial_not_complete():
    client = _Client({})
    budget = discover.Budget(max_objects=2)
    objs = [_obj("a.txt"), _obj("b.txt"), _obj("c.txt")]  # non-candidates, just enumerated
    res = discover.discover_secrets(client, objs, budget=budget)
    assert "object_limit" in res.partial_reasons
    assert res.coverage_complete is False


def test_full_listing_within_budget_is_complete():
    client = _Client({})
    res = discover.discover_secrets(client, [_obj("a.txt"), _obj("b.txt")], budget=discover.Budget(max_objects=100))
    assert res.coverage_complete is True
    assert res.partial_reasons == []
