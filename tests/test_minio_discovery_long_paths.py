"""MinIO retains full JSON locations through live output and dedup spill."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.discovery_paths import concat_discovery_text
from redposture_core.discovery_rendering import iter_disk_discovery_finding_line_chunks
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.minio import actions, discover, render
from redposture_core.modules.minio import enumerate as minio_enumerate
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.secret_detection import fingerprint


def _text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


class _Client:
    def __init__(self, body):
        self.body = body

    def get_object_range(self, _bucket, _key, *, start, length, signed):
        return MinioResponse(
            http_status=206 if start < len(self.body) else 416, headers={}, body=self.body[start : start + length]
        )


def test_completed_json_finding_is_published_before_long_key_is_read():
    key = "catalog_" + "q" * 100_000
    body = ('{"password":"early-secret",' + json.dumps(key) + ':{"password":"known-secret"}}').encode()

    class Reader(_Client):
        reads = 0

        def get_object_range(self, *args, **kwargs):
            self.reads += 1
            return super().get_object_range(*args, **kwargs)

    client = Reader(body)
    emitted = []
    result = discover.discover_secrets(
        client,
        [ObjectInfo("bucket", "config.json", len(body))],
        budget=discover.Budget(chunk_size=127, time_budget=900),
        on_finding=lambda finding: emitted.append((_text(finding["value"]), client.reads)),
    )
    assert result.coverage_complete, result.partial_reasons
    assert [value for value, _reads in emitted] == ["early-secret", "known-secret"]
    assert emitted[0][1] == 1 < emitted[1][1] <= client.reads


def test_direct_minio_formatter_preserves_full_unicode_escaped_disk_place():
    original = "$." + ('ключ/😀"\\\n\x1b[31m' * 1000) + ".password"
    disk = DiskBackedText()
    disk.append_text(original)
    disk.finish()
    finding = {
        "bucket": "bucket",
        "key": "config.json",
        "type": "password",
        "value": "known-secret",
        "object_path": concat_discovery_text(disk),
    }
    line = render.format_finding_line("qa", 9000, finding)
    assert line.endswith(" Place=" + json.dumps("bucket/config.json" + original, ensure_ascii=False))
    assert 'Value="known-secret"' in line
    assert "\x1b" not in line


def test_minio_live_callback_streams_full_disk_place_and_json_without_ansi(monkeypatch):
    key = "catalog_" + ('ключ/😀"\\\n' * 2000)
    body = json.dumps({key: {"password": "known-secret"}}, ensure_ascii=False).encode()
    obj = ObjectInfo(bucket="bucket", key="config.json", size=len(body))
    monkeypatch.setattr(actions, "_client_for", lambda *_: _Client(body))
    monkeypatch.setattr(minio_enumerate, "iter_objects_multi", lambda *_args, **_kwargs: iter((obj,)))
    emitted = []

    def sink(module, host, port, *, finding_type, value, place):
        assert isinstance(place, DiskBackedText)
        emitted.append(
            "".join(
                iter_disk_discovery_finding_line_chunks(
                    module,
                    host,
                    port,
                    finding_type=finding_type,
                    value=value,
                    place=place,
                )
            )
        )

    context = SimpleNamespace(
        host="qa",
        port=9000,
        credential=None,
        args=SimpleNamespace(discover=True, discover_time=900, output_format="txt", bucket="bucket"),
        live_emit=lambda _lines: None,
        live_discovery_value=sink,
    )
    result = actions.data_record(context, {"status": "open_no_auth"})
    assert result["discover_coverage"] == "complete", result["discover_partial_reasons"]
    expected_path = "$." + key + ".password"
    assert len(emitted) == 1
    assert emitted[0].endswith(" Place=" + json.dumps("bucket/config.json" + expected_path, ensure_ascii=False))
    assert "\x1b" not in emitted[0]
    exported = "".join(iter_json_chunks(result["secret_findings"]))
    assert "\x1b" not in exported
    assert json.loads(exported)[0]["object_path"] == expected_path


@pytest.mark.parametrize("seed_equivalent_string_path", [False, True])
def test_minio_spilled_dedup_accepts_disk_path_and_matches_equivalent_string(seed_equivalent_string_path):
    key = "catalog_" + "q" * 100_000
    entry = json.dumps(key) + ':{"password":"known-secret"}'
    body = ("{" + entry + "," + entry + "}").encode()
    obj = ObjectInfo(bucket="bucket", key="config.json", size=len(body))
    seen = {("password", f"prior-{index}", "$.prior", "bucket", "config.json") for index in range(2048)}
    if seed_equivalent_string_path:
        seen.add(("password", fingerprint("known-secret"), "$." + key + ".password", "bucket", "config.json"))
    result = discover.DiscoverResult()
    assert discover._read_and_scan(
        _Client(body),
        obj,
        discover.Budget(chunk_size=65536, time_budget=900),
        result,
        seen,
        None,
    )
    assert result.coverage_complete, result.partial_reasons
    assert len(result.findings) == (0 if seed_equivalent_string_path else 1)
    if result.findings:
        assert _text(result.findings[0]["object_path"]) == "$." + key + ".password"
        assert _text(result.findings[0]["value"]) == "known-secret"


@pytest.mark.parametrize("prefix", ["[INFO] ", "{log text} "])
def test_minio_json_probe_preserves_plain_logs_with_structural_prefix(prefix):
    body = (prefix + "password=known-secret\n").encode()
    result = discover.discover_secrets(
        _Client(body),
        [ObjectInfo("bucket", "ordinary.log", len(body))],
        budget=discover.Budget(chunk_size=3, time_budget=900),
    )
    assert result.coverage_complete, result.partial_reasons
    assert any(_text(f["value"]) == "known-secret" for f in result.findings)


def test_minio_json_probe_keeps_split_whitespace_and_repeated_root_objects():
    key = "catalog_" + "q" * 10_000
    body = ("{ \n\t" + json.dumps(key) + ':{"password":"first-secret"}}\n' + '{"password":"second-secret"}\n').encode()
    result = discover.discover_secrets(
        _Client(body),
        [ObjectInfo("bucket", "untyped-object", len(body))],
        budget=discover.Budget(chunk_size=127, time_budget=900),
    )
    assert result.coverage_complete, result.partial_reasons
    found = {(_text(f["value"]), _text(f["object_path"])) for f in result.findings}
    assert ("first-secret", "$." + key + ".password") in found
    assert ("second-secret", "$.password") in found


def test_minio_live_disk_place_with_small_string_value_uses_streaming_sink(monkeypatch):
    path = DiskBackedText()
    original = "$." + "q" * 100_000 + ".password"
    path.append_text(original)
    path.finish()
    finding = {
        "bucket": "bucket",
        "key": "config.json",
        "type": "password",
        "value": "known-secret",
        "object_path": path,
    }

    def source(_client, _objects, *, budget, on_finding):
        on_finding(finding)
        return discover.DiscoverResult(findings=[finding], objects_scanned=1)

    monkeypatch.setattr(discover, "discover_secrets", source)
    monkeypatch.setattr(actions, "_client_for", lambda *_: object())
    monkeypatch.setattr(minio_enumerate, "iter_objects_multi", lambda *_args, **_kwargs: iter(()))
    emitted = []

    def sink(module, host, port, *, finding_type, value, place):
        assert isinstance(place, DiskBackedText)
        emitted.append(
            "".join(
                iter_disk_discovery_finding_line_chunks(
                    module,
                    host,
                    port,
                    finding_type=finding_type,
                    value=value,
                    place=place,
                )
            )
        )

    context = SimpleNamespace(
        host="qa",
        port=9000,
        credential=None,
        args=SimpleNamespace(discover=True, discover_time=900, output_format="txt", bucket="bucket"),
        live_emit=lambda _lines: None,
        live_discovery_value=sink,
    )
    result = actions.data_record(context, {"status": "open_no_auth"})
    assert result["_discover_findings_streamed"]
    assert len(emitted) == 1
    assert emitted[0].endswith(" Place=" + json.dumps("bucket/config.json" + original))
