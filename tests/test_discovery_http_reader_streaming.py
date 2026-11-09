"""HTTP configuration readers publish closed fields before a large body ends."""

import json
import time
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_http_reader import read_json
from redposture_core.storage_discovery import DiscoveryCollector


def run(*, timeout=False, bad_schema=False, grouped=False):
    emitted = []
    ctx = SimpleNamespace(
        host="qa",
        port=80,
        args=SimpleNamespace(discover_time=30),
        live_emit=emitted.extend,
        live_discovery_value=lambda *args, **kwargs: emitted.append("disk-value"),
    )
    collector = DiscoveryCollector("docker", ctx, {"status": "open_no_auth"})

    class Pool:
        def request_stream(self, method, url, *, on_chunk, on_response, **kwargs):
            assert method == "GET"
            on_response(200, {"Content-Type": "application/json"})
            config = (
                {"oauth": {"client_id": "qa", "client_secret": "inactive-client!42"}}
                if grouped
                else {"password": "inactive-early!42"}
            )
            first = json.dumps({"Config": config})[:-1].encode() + b',"padding":"'
            if bad_schema:
                on_chunk(b'{"password":"not-a-config!42"}')
                return HttpResponse(200, b"", {})
            on_chunk(first)
            assert emitted, "completed finding was held until EOF"
            for _ in range(20):
                on_chunk(b"ordinary data " * 8192)
            on_chunk(b'", "pending":"')
            if timeout:
                collector.deadline = time.monotonic() - 1
                return HttpResponse(200, b"", {}, error="read timeout")
            on_chunk(b'end"}')
            return HttpResponse(200, b"", {})

    value = read_json(
        collector,
        Pool(),
        "http://qa/config",
        "config",
        source_class="docker.config",
        headers={},
        timeout=1,
        required_fields=("Config",),
    )
    return collector.result(), value, emitted


def test_completed_prefix_is_emitted_before_eof():
    report, value, _ = run()
    assert value is not None and report["status"] == "complete"
    assert [str(f["value"]) for f in report["findings"]] == ["inactive-early!42"]


def test_timeout_after_large_closed_value_keeps_completed_findings():
    report, _, _ = run(timeout=True)
    assert report["status"] == "partial"
    assert [str(f["value"]) for f in report["findings"]] == ["inactive-early!42"]


def test_missing_required_schema_does_not_emit_error_document_fields():
    report, value, emitted = run(bad_schema=True)
    assert value is None and report["status"] == "partial"
    assert not report["findings"] and not emitted


def test_streaming_keeps_grouped_json_credential_value():
    from redposture_core.discovery_values import CredentialObject

    report, _, _ = run(grouped=True)
    (finding,) = report["findings"]
    assert finding["type"] == "oauth_credentials" and isinstance(finding["value"], CredentialObject)


@pytest.mark.parametrize("failure", ["truncated", "timeout", "read_error"])
def test_interrupted_credential_object_keeps_closed_field_without_inventing_group(failure):
    collector = DiscoveryCollector(
        "docker",
        SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )

    class Pool:
        def request_stream(self, method, url, *, on_chunk, on_response, **kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"Config":{"client_id":"qa","client_secret":"closed-secret-42","password":"unfinished')
            if failure == "read_error":
                raise OSError("source interrupted")
            return HttpResponse(
                200, b"", {}, error="read timeout" if failure == "timeout" else None, truncated=failure == "truncated"
            )

    assert (
        read_json(
            collector,
            Pool(),
            "http://qa/config",
            "config",
            source_class="docker.config",
            headers={},
            timeout=1,
            required_fields=("Config",),
        )
        is None
    )
    report = collector.result()
    assert report["status"] == "partial"
    assert [str(f["value"]) for f in report["findings"]] == ["closed-secret-42"]
    assert all(f["type"] != "oauth_credentials" for f in report["findings"])
