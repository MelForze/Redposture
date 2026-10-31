"""Classification must suspend for IO without rescoring or rebuilding catalogs."""

import asyncio
from collections import Counter

from redposture_core import async_detection
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.exporters import async_detect, collect, discover, discovery_logic

EXPORTER = {
    "name": "alpha",
    "port": 9104,
    "markers": ["alpha_info"],
    "weak_markers": ["shared_value"],
    "fingerprint_vars": ["alpha-component"],
}


def test_native_fingerprint_resumes_without_repeating_metrics_score(monkeypatch):
    scores, requests = [], []
    original = discover.score_metrics_candidate

    def score(exporter, body):
        scores.append(exporter["name"])
        return original(exporter, body)

    async def wire(self, url, timeout, headers):
        requests.append((url.split(":9104", 1)[1], self.max_bytes))
        return HttpResponse(200, b"shared_value 1\n" if url.endswith("/metrics") else b"alpha-component", {})

    monkeypatch.setattr(discover, "score_metrics_candidate", score)
    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    record, hit = asyncio.run(async_detect.prefetch_discovery("127.0.0.1", 9104, "http", 1, 0, [EXPORTER]))
    assert hit["exporter"] == "alpha" and record["method"] == "fingerprint"
    assert scores == ["alpha"], "metrics classification restarted after each fingerprint read"
    assert requests == [("/metrics", 262144), ("/debug/vars", 131072), ("/debug/pprof/cmdline?debug=1", 131072)]


def test_collect_prepares_catalog_once_for_many_targets(monkeypatch):
    calls = Counter()
    original = discovery_logic.as_token_tuple

    def tokenize(value):
        calls["tokens"] += 1
        return original(value)

    async def wire(self, url, timeout, headers):
        return HttpResponse(200, b"alpha_info 1\n", {})

    monkeypatch.setattr(discovery_logic, "as_token_tuple", tokenize)
    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    result = collect.collect_exporter_debug_data(
        None,
        [],
        1,
        None,
        workers=2,
        retries=0,
        collect_exporters=[EXPORTER],
        discovery_exporters=[EXPORTER],
        collect_debug_endpoints=("/metrics",),
        emit_summary=False,
        emit_line=lambda _: None,
        scan_work_items=((f"127.0.0.{i + 1}", 9104, "http") for i in range(40)),
        scan_work_items_count=40,
    )
    assert result == (40, 40)
    assert calls["tokens"] <= 6, "target-independent marker lists rebuilt for every target"
    assert EXPORTER["markers"] == ["alpha_info"]


def test_prepared_catalog_preserves_scoring_for_seeded_overlapping_markers():
    import random

    rng = random.Random(41031)
    tokens = ["alpha", "a", "aa", "beta", "π", "", " ", None]
    for _ in range(300):
        profile = {
            "name": rng.choice(["alpha", " alpha ", "", None]),
            **{
                key: [rng.choice(tokens) for _ in range(rng.randrange(5))]
                for key in (
                    "markers",
                    "strong_markers",
                    "weak_markers",
                    "negative_markers",
                    "fingerprint_vars",
                    "fingerprint_cmdline",
                )
            },
        }
        body = " ".join(rng.choice(["alpha", "aaa", "beta", "π", "none"]) for _ in range(8))
        prepared = discovery_logic.prepare_exporter_catalog([profile])[0]
        assert prepared == profile
        assert discovery_logic.score_metrics_candidate(prepared, body) == discovery_logic.score_metrics_candidate(
            profile, body
        )
        assert discovery_logic.score_fingerprint_candidate(
            prepared, body, "alpha"
        ) == discovery_logic.score_fingerprint_candidate(profile, body, "alpha")


def test_empty_catalog_does_not_issue_fingerprint_requests(monkeypatch):
    paths = []

    async def wire(self, url, timeout, headers):
        paths.append(url.split(":9104", 1)[1])
        return HttpResponse(200, b"generic_metric 1\n", {})

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    record, hit = asyncio.run(async_detect.prefetch_discovery("127.0.0.1", 9104, "http", 1, 0, []))
    assert hit is None and not record["detected"]
    assert paths == ["/metrics"]
