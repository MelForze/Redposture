"""Product adapters must not change which explicit values a source contains."""

from __future__ import annotations

import pytest

from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import scan_value_tree

SECRET = "inactive-shared-context-password"


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"name": "password", "value": SECRET}, {SECRET}),
        ({"field": "client_secret", "value": SECRET}, {SECRET}),
        ({"target_field": "password", "value": SECRET}, {SECRET}),
        ({"name": "token_count", "value": "23456789"}, set()),
        ({"name": "public_key", "value": "ordinary-public-material"}, set()),
        ({"api_key": "A" * 300000}, set()),
        ({"api_key": "qR7xN2/pV5tC8+fK3sM9=zD6aL4-" * 10000}, {"qR7xN2/pV5tC8+fK3sM9=zD6aL4-" * 10000}),
    ],
)
@pytest.mark.parametrize("entry", ["common", "elastic"])
def test_explicit_field_context_has_the_same_values_for_each_product(body, expected, entry):
    if entry == "common":
        rows, _, complete = _scan_portioned_value(body, "$", 65536)
        assert complete, getattr(rows, "incomplete_reason", None)
        actual = {plain(row.value) for row in rows if row.confidence != "low"}
    else:
        result = scan_value_tree(body, source_kind="document", object_name="qa/one")
        assert not result.truncated_reasons
        actual = {plain(row.value) for row, _location in result.detections if row.available}
    assert actual == expected


@pytest.mark.parametrize("entry", ["disk-json", "storage-json", "minio-json"])
@pytest.mark.parametrize("value_first", [False, True])
def test_semantic_context_is_preserved_in_streaming_json(entry, value_first):
    import json
    from types import SimpleNamespace

    from redposture_core.clients.minio_api import MinioResponse
    from redposture_core.modules.minio.discover import Budget, discover_secrets
    from redposture_core.modules.minio.enumerate import ObjectInfo
    from redposture_core.storage_discovery import DiscoveryCollector

    password = "inactive-" + "Ab0λ " * 20000
    body = {"value": password, "name": "password"} if value_first else {"name": "password", "value": password}
    raw = json.dumps([body, {"name": "public_key", "value": "ordinary-public-material"}], ensure_ascii=False).encode()
    if entry == "disk-json":
        with DiskBackedText() as disk:
            disk.append_text(raw.decode())
            disk.finish()
            matches, _, complete = _scan_portioned_value(disk, "$", 64)
            assert complete, getattr(matches, "incomplete_reason", None)
            actual = {plain(match.value) for match in matches if match.confidence != "low"}
            assert {plain(match.object_path) for match in matches if match.confidence != "low"} == {"$[0].value"}
    elif entry == "storage-json":
        ctx = SimpleNamespace(host="qa", port=443, args=SimpleNamespace(discover_time=900))
        collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
        assert collector.scan_json_chunks("qa", (raw[i : i + 113] for i in range(0, len(raw), 113)))
        report = collector.result()
        assert report["status"] == "complete", report["partial_reasons"]
        actual = {plain(row["value"]) for row in report["findings"]}
        assert {plain(row["object_path"]) for row in report["findings"]} == {"$.qa[0].value"}
    else:

        class Client:
            def get_object_range(self, _bucket, _key, *, start, length, signed):
                return MinioResponse(http_status=206, headers={}, body=raw[start : start + length])

        minio_report = discover_secrets(
            Client(), [ObjectInfo("qa", "context.json", len(raw))], budget=Budget(chunk_size=113)
        )
        assert minio_report.coverage_complete, minio_report.partial_reasons
        actual = {plain(row["value"]) for row in minio_report.findings}
        assert {plain(row["object_path"]) for row in minio_report.findings} == {"$[0].value"}
    assert actual == {password}


def test_disk_medium_field_uses_the_same_trimmed_entropy_evidence_as_scalar():
    from redposture_core.discovery_confirmation import confirm_disk_field
    from redposture_core.discovery_rules import analyze_value

    core = "qR7xN2/pV5tC8+fK3sM9=zD6aL4-"
    body = " " * 200000 + core + "\n\t" * 200000
    scalar = [row.value for row in analyze_value(body, path="api_key") if row.available]
    with DiskBackedText() as source:
        source.append_text(body)
        source.finish()
        found = confirm_disk_field(source, field_name="api_key")
        actual = [plain(found.value)] if found is not None else []
    assert scalar == actual == [body]


@pytest.mark.parametrize("field", ["password", "api_key"])
def test_materialized_scalar_has_no_hidden_named_value_size_limit(field):
    from redposture_core.discovery_rules import analyze_value

    value = "qR7xN2/pV5tC8+fK3sM9=zD6aL4-" * 10000
    assert {row.value for row in analyze_value(value, path=field) if row.available} == {value}


def test_paired_aws_key_keeps_the_same_secret_without_promoting_identifier():
    import json

    from redposture_core.discovery_rules import analyze_aws_pair

    value = "qaOnly12" * 5
    assert len(value) == 40
    identifier = "AKIA" + "0" * 16
    pair = analyze_aws_pair(identifier, value)
    assert pair is not None and pair.value == value and "aws_credential_pair" in pair.detectors
    assert analyze_aws_pair("not-an-access-key", value) is None
    for body, expected in [
        ({"aws_access_key_id": identifier}, set()),
        (
            {"aws_access_key_id": identifier, "aws_secret_access_key": value},
            {
                json.dumps(
                    {"aws_access_key_id": identifier, "aws_secret_access_key": value},
                    separators=(",", ":"),
                    sort_keys=True,
                )
            },
        ),
    ]:
        common, _, complete = _scan_portioned_value(body, "$", 65536)
        elastic = scan_value_tree(body, source_kind="document", object_name="qa/one")
        assert complete and not elastic.truncated_reasons
        assert {plain(row.value) for row in common if row.confidence != "low"} == expected
        assert {plain(row.value) for row, _ in elastic.detections if row.available} == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"name": "password", "value": SECRET, "field": "public_key"}, set()),
        ({"type": "password", "name": 1, "value": SECRET}, set()),
        ({"name": "password", "field": {}, "value": SECRET}, set()),
    ],
)
def test_streamed_context_honors_label_precedence_and_nonstring_overrides(body, expected):
    import json

    with DiskBackedText() as source:
        source.append_text(json.dumps(body))
        source.finish()
        found, _, complete = _scan_portioned_value(source, "$", 64)
        assert complete
        assert {plain(row.value) for row in found if row.confidence != "low"} == expected
    materialized, _, complete = _scan_portioned_value(body, "$", 65536)
    assert complete
    assert {plain(row.value) for row in materialized if row.confidence != "low"} == expected


def test_corrupt_json_keeps_closed_contextual_value_but_not_an_open_value():
    for ending, expected in [('" , invalid', {SECRET}), ("unfinished", set())]:
        with DiskBackedText() as source:
            source.append_text('{"name":"password","value":"' + (SECRET if expected else "") + ending)
            source.finish()
            found, _, complete = _scan_portioned_value(source, "$", 64)
            assert not complete
            assert {plain(row.value) for row in found if row.confidence != "low"} == expected


@pytest.mark.parametrize("entry", ["storage", "minio"])
def test_read_failure_retains_a_closed_contextual_value(entry):
    from types import SimpleNamespace

    from redposture_core.clients.minio_api import MinioResponse
    from redposture_core.modules.minio.discover import Budget, discover_secrets
    from redposture_core.modules.minio.enumerate import ObjectInfo
    from redposture_core.storage_discovery import DiscoveryCollector

    prefix = ('{"name":"password","value":"' + SECRET + '","notes":"').encode() + b"a" * 200
    if entry == "storage":
        ctx = SimpleNamespace(host="qa", port=443, args=SimpleNamespace(discover_time=900))
        collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})

        def chunks():
            yield prefix
            raise OSError("source disconnected")

        assert not collector.scan_json_chunks("qa", chunks())
        result = collector.result()
        assert result["status"] == "partial"
        values = {plain(row["value"]) for row in result["findings"]}
    else:

        class Client:
            def get_object_range(self, _bucket, _key, *, start, length, signed):
                if start >= len(prefix):
                    return MinioResponse(http_status=0, headers={}, body=b"", transport_error="source disconnected")
                return MinioResponse(http_status=206, headers={}, body=prefix[start : start + length])

        # An exact portion boundary keeps the open source waiting on another read.
        minio_result = discover_secrets(
            Client(), [ObjectInfo("qa", "context.json", len(prefix) + 100)], budget=Budget(chunk_size=len(prefix))
        )
        assert not minio_result.coverage_complete and "read_failure" in minio_result.partial_reasons
        values = {plain(row["value"]) for row in minio_result.findings}
    assert values == {SECRET}
