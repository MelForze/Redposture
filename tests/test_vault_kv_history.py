"""Retained KVv2 versions are independent read-only discovery sources."""

from tests.test_vault_additional_sources import Pool, run


def routes(*, denied_metadata=False, deleted=False):
    return {
        ("LIST", "/v1/secret/metadata/"): (200, {"data": {"keys": ["app"]}}),
        ("GET", "/v1/secret/metadata/app"): (403, {})
        if denied_metadata
        else (
            200,
            {
                "data": {
                    "current_version": 2,
                    "versions": {
                        "1": {"destroyed": deleted, "deletion_time": ""},
                        "2": {"destroyed": False, "deletion_time": ""},
                    },
                }
            },
        ),
        ("GET", "/v1/secret/data/app?version=1"): (
            200,
            {"data": {"data": {"password": "inactive-older!42"}, "metadata": {"version": 1}}},
        ),
        ("GET", "/v1/secret/data/app"): (
            200,
            {"data": {"data": {"password": "inactive-current!42"}, "metadata": {"version": 2}}},
        ),
    }


def pool(**kwargs):
    return Pool({"secret/": {"type": "kv", "options": {"version": "2"}}}, routes(**kwargs))


def test_history_finds_old_value_and_preserves_version_place():
    p = pool()
    report, _ = run(p)
    assert report["status"] == "complete"
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-current!42", "inactive-older!42"}
    old = next(f for f in report["findings"] if str(f["value"]) == "inactive-older!42")
    assert any(place.get("version") == "1" for place in old["locations"])
    assert ("GET", "/v1/secret/data/app?version=2") not in p.calls
    assert all(method in {"GET", "LIST"} for method, path in p.calls)


def test_denied_history_does_not_discard_readable_current_value():
    report, _ = run(pool(denied_metadata=True))
    assert report["status"] == "partial"
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-current!42"}
    assert any(s["denied"] for s in report["sources"] if s["id"].startswith("vault.kv_history"))


def test_destroyed_versions_are_not_restored_or_read_as_complete():
    p = pool(deleted=True)
    report, _ = run(p)
    assert report["status"] == "partial"
    assert ("GET", "/v1/secret/data/app?version=1") not in p.calls
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-current!42"}


def test_completed_history_value_is_emitted_and_retained_before_late_timeout():
    from types import SimpleNamespace

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.token_api import ReadBudget
    from redposture_core.modules.vault.discover import discover_kv_history
    from redposture_core.storage_discovery import DiscoveryCollector

    emitted = []
    args = SimpleNamespace(discover_time=30)
    ctx = SimpleNamespace(host="qa", port=8200, args=args, live_emit=emitted.extend)
    collector = DiscoveryCollector("vault", ctx, {"status": "valid_credentials"})
    original = pool()

    class Stream:
        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            if "?version=1" not in url:
                return original.request_stream(method, url, on_response=on_response, on_chunk=on_chunk, **kwargs)
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"data":{"data":{"password":"inactive-closed-history!42","padding":"')
            assert emitted, "closed history finding held until EOF"
            on_chunk(b"ordinary " * 8192)
            return HttpResponse(200, b"", {}, error="read timeout")

    discover_kv_history(
        SimpleNamespace(pool=Stream()), "http://qa", "secret/", "app", "local-vault-token", ReadBudget(args), collector
    )
    report = collector.result()
    assert report["status"] == "partial"
    assert [str(f["value"]) for f in report["findings"]] == ["inactive-closed-history!42"]
    assert report["findings"][0]["locations"][0]["version"] == "1"
