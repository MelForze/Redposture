"""Search filtering and projections must preserve a credential's object context."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from redposture_core.discovery_values import iter_json_chunks
from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverResponse, build_targeted_query
from redposture_core.modules.elastic.search_stream import StreamedSearchPage

AWS = {
    "awsAccessKeyId": "AKIA" + "Q" * 16,
    "awsSecretAccessKey": "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6uV9x",
}


@pytest.mark.parametrize("field,parent", [("payload.awsSecretAccessKey", "payload"), ("oauth.clientSecret", "oauth")])
def test_targeted_source_includes_related_credential_parent(field, parent):
    query = build_targeted_query([field])
    assert parent in query["_source"]["includes"]
    assert query["query"]["bool"]["should"] == [{"exists": {"field": field}}]


def test_targeted_root_credential_requests_full_root_context():
    assert build_targeted_query(["client_secret"])["_source"] is True


@pytest.mark.parametrize("projection", ["fields", "stored_fields"])
@pytest.mark.parametrize("suffix", ["", ".keyword"])
def test_group_component_projection_does_not_create_a_second_finding(projection, suffix):
    engine = DiscoverEngine(lambda _request: pytest.fail("supplied hit"))
    secret = AWS["awsSecretAccessKey"]
    hit = {
        "_index": "logs",
        "_id": "one",
        "_source": {"payload": AWS},
        projection: {"payload.awsSecretAccessKey" + suffix: [secret]},
    }
    engine._process_hit("logs", hit, candidate=True, payload_complete=False)
    engine._process_hit("logs", hit, candidate=False, payload_complete=True)
    found = list(engine.accumulator.findings())
    assert [(item.secret_type, json.loads("".join(iter_json_chunks(item.value)))) for item in found] == [
        ("aws_credentials", AWS)
    ]
    assert [place.path for place in found[0].locations] == ["/payload"]


@pytest.mark.parametrize("source", [{}, {"payload": AWS}])
def test_independent_or_different_projection_is_never_hidden(source):
    engine = DiscoverEngine(lambda _request: pytest.fail("supplied hit"))
    engine._process_hit(
        "logs",
        {
            "_index": "logs",
            "_id": "one",
            "_source": source,
            "fields": {
                "other.awsSecretAccessKey": [AWS["awsSecretAccessKey"]],
                "payload.awsSecretAccessKey.keyword": [AWS["awsSecretAccessKey"][::-1]],
            },
        },
        candidate=False,
        payload_complete=True,
    )
    found = list(engine.accumulator.findings())
    scalar_places = {place.path for item in found if item.secret_type != "aws_credentials" for place in item.locations}
    assert "/fields/other.awsSecretAccessKey/0" in scalar_places
    assert "/fields/payload.awsSecretAccessKey.keyword/0" in scalar_places


@pytest.mark.parametrize("inline", [32, 1024])
def test_single_hit_stream_groups_long_members_before_emitting_components(inline):
    oauth = {
        "client_id": "qa-app",
        "client_secret": "inactive-" + "qλ" * 10000,
        "access_token": "inactive-access-42",
        "refresh_token": "inactive-" + "r" * 12000,
    }
    payload = {"hits": {"total": 1, "hits": [{"_index": "logs", "_id": "one", "_source": {"oauth": oauth}}]}}
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=inline)
    engine = DiscoverEngine(lambda _request: pytest.fail("supplied page"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        stream.summary(),
        candidate=True,
        payload_complete=True,
    )
    found = list(engine.accumulator.findings())
    assert not engine.coverage.truncated_reasons
    assert [(item.secret_type, json.loads("".join(iter_json_chunks(item.value)))) for item in found] == [
        ("oauth_credentials", oauth)
    ]
    assert found[0].locations[0].path == "/oauth"


def test_multi_value_projection_checks_each_source_object_once(monkeypatch):
    import time

    from redposture_core import discovery_groups
    from redposture_core.modules.elastic.discover import _group_component_projection

    source = {"oauth": [{"client_id": f"qa-{i}", "client_secret": f"inactive-secret-{i:04d}"} for i in range(80)]}
    projection = [item["client_secret"] for item in reversed(source["oauth"])]
    calls = 0
    original = discovery_groups.credential_groups

    def counted(value, **kwargs):
        nonlocal calls
        calls += 1
        return original(value, **kwargs)

    monkeypatch.setattr(discovery_groups, "credential_groups", counted)
    assert _group_component_projection(source, "oauth.client_secret", projection, deadline=time.monotonic() + 10)
    assert calls <= 80


def test_many_long_group_members_share_disk_handles():
    fd_directory = Path("/proc/self/fd") if Path("/proc/self/fd").exists() else Path("/dev/fd")
    if not fd_directory.exists():
        pytest.skip("OS does not expose open descriptors")

    source = {
        f"oauth{i}": {"client_id": f"qa-app-{i}", "client_secret": f"inactive-secret-{i:04d}"} for i in range(120)
    }
    payload = {"hits": {"hits": [{"_index": "logs", "_id": "one", "_source": source}]}}
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=8)
    before = len(os.listdir(fd_directory))
    try:
        decoded = stream.compact_source()
        assert len(os.listdir(fd_directory)) - before < 16
        for key, value in decoded.items():
            for name, member in value.items():
                assert json.loads("".join(iter_json_chunks(member))) == source[key][name]
    finally:
        stream.close()
