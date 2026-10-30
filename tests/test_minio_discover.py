from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.minio import discover
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.scheduler import SharedNestedScheduler


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
    assert discover.is_candidate_key("neutral.txt") == "suffix:.txt"


def test_discover_finds_secret_via_shared_engine_with_full_value():
    body = b"AWS_SECRET_ACCESS_KEY=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
    client = _Client({".env": (200, body)})
    res = discover.discover_secrets(client, [_obj(".env")])
    assert res.objects_scanned == 1
    assert res.findings
    finding = res.findings[0]
    assert finding["value"] == "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
    assert "masked_value" not in finding
    assert res.coverage_complete is True


def test_default_discovery_checks_candidate_after_more_than_thousand_objects():
    body = b"password=secret-after-thousand"
    client = _Client(
        {**{f"plain-{index}.txt": (200, b"ordinary text") for index in range(1001)}, "last.env": (200, body)}
    )
    objects = (_obj(f"plain-{index}.txt") for index in range(1001))
    result = discover.discover_secrets(client, (*objects, _obj("last.env")))
    assert result.coverage_complete is True
    assert result.objects_scanned == 1002
    assert any(finding["value"] == "secret-after-thousand" for finding in result.findings)


def test_discover_finds_camelcase_secret_key_in_json_object():
    body = b'{"service":{"accessToken":"S3cretValue123"}}'
    client = _Client({"config.json": (200, body)})
    res = discover.discover_secrets(client, [_obj("config.json", size=len(body))])
    assert any(
        finding["type"] == "access_token"
        and finding["value"] == "S3cretValue123"
        and finding["object_path"] == "$.service.accessToken"
        for finding in res.findings
    )


def test_large_object_scanned_in_chunks_not_skipped():
    # A secret near the start, then padding beyond the per-object cap: the object is
    # read in ranged chunks up to max_object_size (not skipped), and flagged truncated.
    body = b"AWS_SECRET_ACCESS_KEY=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0\n" + b"z" * 500
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
    secret = "AWS_SECRET_ACCESS_KEY=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
    body = ("x" * 20 + secret).encode()  # secret straddles small chunk boundaries
    client = _Client({".env": (200, body)})
    budget = discover.Budget(chunk_size=24, max_object_size=10_000)
    res = discover.discover_secrets(client, [_obj(".env", size=len(body))], budget=budget)
    assert len({r[1] for r in client.ranges}) > 1  # actually chunked
    assert res.findings  # found despite crossing a chunk boundary
    assert len(res.findings) == len({(f["type"], f["value"]) for f in res.findings})


def test_chunked_secret_never_emits_truncated_password_prefix() -> None:
    body = b"password=supersecretvalue"
    client = _Client({".env": (200, body)})
    result = discover.discover_secrets(
        client,
        [_obj(".env", size=len(body))],
        budget=discover.Budget(max_total_bytes=12, chunk_size=12),
    )
    values = {finding["value"] for finding in result.findings}
    assert values == {"supersecretvalue"}
    assert result.coverage_complete is True


def test_long_assignment_spanning_ranged_reads_is_returned_in_full() -> None:
    token = "Ab0" * 100_000
    body = f"API_TOKEN={token}\nordinary=1\n".encode()
    result = discover.discover_secrets(
        _Client({".env": (200, body)}),
        [_obj(".env", size=len(body))],
        budget=discover.Budget(chunk_size=64 * 1024),
    )
    assert result.coverage_complete is True, result.partial_reasons
    values = [finding["value"] for finding in result.findings if finding["type"] == "generic_secret"]
    assert len(values) == 1
    assert isinstance(values[0], DiskBackedText)
    assert "".join(values[0].iter_text_chunks()) == token
    from redposture_core.modules.minio import render

    line = render.format_finding_line("127.0.0.1", 9000, result.findings[0])
    assert f'Value="{token}"' in line
    assert "\x1b" not in line
    values[0].close()


def test_long_assignment_read_failure_does_not_emit_a_prefix() -> None:
    class InterruptedClient(_Client):
        def get_object_range(self, bucket, key, *, start=0, length, signed):
            if start >= 64 * 1024:
                return MinioResponse(http_status=0, headers={}, body=b"", transport_error="connection closed")
            return super().get_object_range(bucket, key, start=start, length=length, signed=signed)

    body = ("API_TOKEN=" + "Ab0" * 100_000).encode()
    result = discover.discover_secrets(
        InterruptedClient({".env": (200, body)}),
        [_obj(".env", size=len(body))],
        budget=discover.Budget(chunk_size=64 * 1024),
    )
    assert result.coverage_complete is False
    assert "read_failure" in result.partial_reasons
    assert result.findings == []


def test_long_placeholder_assignment_is_not_a_finding() -> None:
    body = ("API_TOKEN=" + "x" * 300_000).encode()
    result = discover.discover_secrets(
        _Client({".env": (200, body)}),
        [_obj(".env", size=len(body))],
        budget=discover.Budget(chunk_size=64 * 1024),
    )
    assert result.coverage_complete is True
    assert result.findings == []


def test_object_size_exact_chunk_multiple_ends_cleanly():
    # body length is an exact multiple of the chunk size: the read at EOF returns
    # 416, which must be treated as end-of-object (not read_failure / not truncated).
    secret = b"AWS_SECRET_ACCESS_KEY=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
    body = secret + b"\n" + b"z" * (128 - len(secret) - 1)  # exactly 128 bytes
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
    res = discover.discover_secrets(client, [_obj("photo.png"), _obj("movie.mp4")])
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
    client = _Client({"a.txt": (200, b"plain"), "b.txt": (200, b"plain")})
    res = discover.discover_secrets(client, [_obj("a.txt"), _obj("b.txt")], budget=discover.Budget(max_objects=100))
    assert res.coverage_complete is True
    assert res.partial_reasons == []


def test_short_plain_object_without_delimiter_is_complete() -> None:
    body = b"ordinary content"
    result = discover.discover_secrets(_Client({"a.env": (206, body)}), [_obj("a.env", size=0)])
    assert result.findings == []
    assert result.coverage_complete is True, result.partial_reasons


def test_neutral_binary_name_is_scanned_for_structured_secret() -> None:
    body = b"DB_PASSWORD=secret-in-neutral-name"
    client = _Client({"opaque.bin": (200, body)})
    result = discover.discover_secrets(client, [_obj("opaque.bin", size=len(body))])
    assert result.coverage_complete is True
    assert result.candidates[0]["reason"] == "content:unclassified"
    assert any(item["value"] == "secret-in-neutral-name" for item in result.findings)


def test_portion_limit_continues_across_objects():
    first = b"password=firstsecret"
    second = b"password=secondsecret"
    client = _Client({"first.env": (200, first), "second.env": (200, second)})
    cap = len(first) + 5
    result = discover.discover_secrets(
        client,
        [_obj("first.env"), _obj("second.env")],
        budget=discover.Budget(max_total_bytes=cap),
    )
    assert result.bytes_read == len(first) + len(second)
    assert result.coverage_complete is True
    assert any(finding["value"] == "firstsecret" for finding in result.findings)
    assert any(finding["value"] == "secondsecret" for finding in result.findings)


def test_failed_object_releases_global_byte_reservation():
    client = _Client({"denied.env": (403, b""), "ok.env": (200, b"password=okaysecret")})
    result = discover.discover_secrets(
        client,
        [_obj("denied.env"), _obj("ok.env")],
        budget=discover.Budget(max_total_bytes=100),
    )
    assert any(finding["value"] == "okaysecret" for finding in result.findings)
    assert result.bytes_read == len(b"password=okaysecret")


def test_parallel_objects_share_one_active_portion_budget():
    client = _Client({f"{index}.env": (200, b"password=sharedsecret") for index in range(12)})
    scheduler = SharedNestedScheduler(max_workers=8)
    try:
        result = discover.discover_secrets(
            client,
            [_obj(f"{index}.env") for index in range(12)],
            budget=discover.Budget(max_total_bytes=37),
            nested_scheduler=scheduler,
            scheduler_key="target",
        )
    finally:
        scheduler.close()
    assert result.bytes_read == 12 * len(b"password=sharedsecret")
    assert result.coverage_complete is True


def test_discover_scans_eight_objects_in_parallel_and_merges_in_input_order():
    class ParallelClient:
        def __init__(self) -> None:
            self.active = 0
            self.peak = 0
            self.lock = threading.Lock()

        def get_object_range(self, bucket, key, *, start=0, length, signed):
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            time.sleep(0.02)
            with self.lock:
                self.active -= 1
            body = f"password=SecretValue-{key}".encode()
            return MinioResponse(http_status=200, headers={}, body=body[start : start + length])

    client = ParallelClient()
    scheduler = SharedNestedScheduler(max_workers=16)
    try:
        objects = [_obj(f"{index:02d}.env") for index in range(12)]
        result = discover.discover_secrets(
            client,
            objects,
            nested_scheduler=scheduler,
            scheduler_key=("minio", "target"),
        )
    finally:
        scheduler.close()

    assert 2 <= client.peak <= 8
    assert [item["key"] for item in result.candidates] == [f"{index:02d}.env" for index in range(12)]
    assert [item["key"] for item in result.findings] == [f"{index:02d}.env" for index in range(12)]


def test_minio_discover_time_includes_detect_and_bucket_listing(monkeypatch) -> None:
    from redposture_core.modules.minio import actions
    from redposture_core.modules.minio import enumerate as minio_enumerate

    monkeypatch.setattr(actions, "_client_for", lambda *_: object())
    monkeypatch.setattr(minio_enumerate, "iter_buckets", lambda *_args, **_kwargs: iter(()))
    monkeypatch.setattr(minio_enumerate, "iter_objects_multi", lambda *_args, **_kwargs: iter(()))
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=9000,
        args=SimpleNamespace(discover=True, discover_time=0.01, discover_max_bytes=1024, output_format="json"),
        credential=None,
        discovery_started_at=time.monotonic() - 1,
    )
    result = actions.data_record(ctx, {"status": "open_no_auth"})
    assert result["discover_coverage"] == "partial"
    assert "timeout" in result["discover_partial_reasons"]
    assert result["discover_coverage_percent"] is None


def test_minio_discover_record_exports_full_discovered_secret(monkeypatch) -> None:
    from redposture_core.modules.minio import actions
    from redposture_core.modules.minio import enumerate as minio_enumerate

    monkeypatch.setattr(
        actions, "_client_for", lambda *_: _Client({".env": (200, b"API_TOKEN=glpat-abcdefghijklmnopqrstuv")})
    )
    monkeypatch.setattr(minio_enumerate, "iter_buckets", lambda *_args, **_kwargs: iter(()))
    monkeypatch.setattr(minio_enumerate, "iter_objects_multi", lambda *_args, **_kwargs: iter((_obj(".env"),)))
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=9000,
        args=SimpleNamespace(discover=True, discover_time=5, discover_max_bytes=1024, output_format="json", bucket="b"),
        credential=None,
    )
    result = actions.data_record(ctx, {"status": "open_no_auth"})
    assert result["discover_coverage"] == "complete"
    assert result["secret_findings"]
    assert any(item["value"] == "glpat-abcdefghijklmnopqrstuv" for item in result["secret_findings"])


def test_minio_live_discovery_streams_full_disk_value(monkeypatch) -> None:
    from redposture_core.modules.minio import actions
    from redposture_core.modules.minio import enumerate as minio_enumerate

    token = "Ab0" * 100_000
    body = f"API_TOKEN={token}\n".encode()
    original_budget = discover.Budget
    monkeypatch.setattr(discover, "Budget", lambda **kwargs: original_budget(chunk_size=64 * 1024, **kwargs))
    monkeypatch.setattr(actions, "_client_for", lambda *_: _Client({".env": (200, body)}))
    monkeypatch.setattr(minio_enumerate, "iter_buckets", lambda *_args, **_kwargs: iter(()))
    monkeypatch.setattr(minio_enumerate, "iter_objects_multi", lambda *_args, **_kwargs: iter((_obj(".env"),)))
    streamed: list[tuple[str, str]] = []
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=9000,
        args=SimpleNamespace(discover=True, discover_time=5, output_format="txt", bucket="b"),
        credential=None,
        live_emit=lambda _lines: None,
        live_discovery_value=lambda module, _host, _port, **kwargs: streamed.append(
            (module, "".join(kwargs["value"].iter_text_chunks()))
        ),
    )
    result = actions.data_record(ctx, {"status": "open_no_auth"})
    assert result["discover_coverage"] == "complete", result["discover_partial_reasons"]
    assert streamed == [("MINIO", token)]
    assert result["_discover_findings_streamed"] is True
    result["secret_findings"][0]["value"].close()


def test_large_bare_jwt_across_ranges_is_complete_and_not_a_prefix() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9." + "YWJj" * 80_000 + ".c2ln"
    body = ("ordinary log\n" + token + "\npassword=qa-later-password\n").encode()
    result = discover.discover_secrets(
        _Client({"auth.log": (200, body)}),
        [_obj("auth.log", size=len(body))],
        budget=discover.Budget(chunk_size=64 * 1024),
    )
    assert result.coverage_complete is True, result.partial_reasons
    tokens = [finding["value"] for finding in result.findings if finding["type"] == "jwt"]
    assert len(tokens) == 1
    assert isinstance(tokens[0], DiskBackedText)
    assert "".join(tokens[0].iter_text_chunks()) == token
    assert any(finding["value"] == "qa-later-password" for finding in result.findings)


def test_interrupted_bare_jwt_does_not_emit_a_valid_looking_prefix() -> None:
    class Interrupted(_Client):
        def get_object_range(self, bucket, key, *, start=0, length, signed):
            if start >= 64 * 1024:
                return MinioResponse(http_status=0, headers={}, body=b"", transport_error="connection closed")
            return super().get_object_range(bucket, key, start=start, length=length, signed=signed)

    token = "eyJhbGciOiJIUzI1NiJ9." + "YWJj" * 80_000 + ".c2ln"
    result = discover.discover_secrets(
        Interrupted({"auth.log": (200, token.encode())}),
        [_obj("auth.log", size=len(token))],
        budget=discover.Budget(chunk_size=64 * 1024),
    )
    assert result.coverage_complete is False and "read_failure" in result.partial_reasons
    assert not result.findings


def test_quoted_password_across_minio_ranges_keeps_exact_value_without_quotes() -> None:
    password = "Ab0λ " * 40000 + "-tail"
    body = ('ordinary status\npassword="' + password + '"\n').encode()
    result = discover.discover_secrets(
        _Client({"app.env": (200, body)}),
        [_obj("app.env", size=len(body))],
        budget=discover.Budget(chunk_size=8191),
    )
    assert result.coverage_complete, result.partial_reasons
    passwords = [finding["value"] for finding in result.findings if finding["type"] == "password"]
    assert len(passwords) == 1 and isinstance(passwords[0], DiskBackedText)
    assert "".join(passwords[0].iter_text_chunks()) == password


def test_unicode_minio_source_growth_keeps_process_rss_bounded() -> None:
    """Large Unicode decoding must not grow RSS with the number of ranges."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    import pytest

    if sys.platform not in {"darwin", "linux"}:
        pytest.skip("per-process RSS probe uses resource on macOS/Linux")
    program = r"""
import hashlib, json, resource, sys, tempfile
from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio.discover import Budget, discover_secrets
from redposture_core.modules.minio.enumerate import ObjectInfo
size=int(sys.argv[1]); expected=hashlib.sha256()
with tempfile.TemporaryFile() as source:
    source.write(b'password="'); remaining=size; unit='Ab0λ '.encode()
    while remaining>=len(unit):
        count=min(remaining//len(unit),10000)
        part=unit*count; source.write(part); expected.update(part); remaining-=len(part)
    part=b'T'*remaining; source.write(part); expected.update(part)
    source.write(b'"\n'); source.flush()
    class Reader:
        def get_object_range(self,bucket,key,*,start,length,signed):
            source.seek(start); data=source.read(length)
            return MinioResponse(206 if data else 416,{},data)
    result=discover_secrets(Reader(),[ObjectInfo('qa','app.env',size+12)],budget=Budget())
    assert result.coverage_complete and len(result.findings)==1,result.partial_reasons
    value=result.findings[0]['value']; assert value.digest==expected.hexdigest()
    value.close()
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps({'rss':rss if sys.platform=='darwin' else rss*1024}))
"""
    peaks = []
    for size in (10_000_000, 100_000_000):
        completed = subprocess.run(
            [sys.executable, "-c", program, str(size)],
            cwd=Path(__file__).resolve().parents[1],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        peaks.append(json.loads(completed.stdout)["rss"])
    assert peaks[1] - peaks[0] <= 32_000_000, peaks
