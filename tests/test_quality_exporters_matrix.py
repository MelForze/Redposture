"""Bounded exporter trigger/collect behavior under profile and transport faults."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.constants import SCAN_EXPORTERS
from redposture_core.exporters import collect
from redposture_core.exporters.trigger import trigger_detected_exporter_task, trigger_query_variants

_TRIGGER_PROFILES = tuple(profile for profile in SCAN_EXPORTERS if profile.get("trigger_path"))


@pytest.mark.parametrize("profile", _TRIGGER_PROFILES, ids=lambda profile: profile["name"])
def test_all_trigger_exporters_stop_after_repeated_server_errors(profile: dict[str, object]) -> None:
    calls: list[str] = []
    delays: list[float] = []

    def request(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        calls.append(url)
        return 503, "upstream unavailable"

    result = trigger_detected_exporter_task(
        None,
        "exporter.local",
        profile,
        ["127.0.0.1"],
        1,
        0,
        request,
        profile_delay=0.01,
        sleep_fn=delays.append,
    )
    assert 1 <= result["attempted"] <= 3
    assert result["success"] == 0
    assert len(calls) == result["attempted"]
    assert len(delays) == max(0, len(calls) - 1)
    assert all(parse_qs(urlsplit(url).query).get("target") for url in calls)


@given(st.sampled_from(_TRIGGER_PROFILES), st.text(alphabet="abc_123-", max_size=15))
def test_trigger_profile_variants_are_bounded_and_do_not_lose_explicit_names(
    profile: dict[str, object], name: str
) -> None:
    query = str(profile.get("trigger_query") or "")
    variants = trigger_query_variants(profile)
    assert len(variants) == len(set(variants)) <= 40
    assert variants[0] == query.lstrip("?")
    if profile.get("explicit_profile"):
        assert len(variants) == 1


@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        ("reset", "connection reset"),
        ("timeout", "timed out"),
        ("truncated", None),
        ("denied", None),
    ],
)
def test_collect_task_retains_fault_and_bounded_body(fault: str, expected: str | None) -> None:
    def get(_url: str, **_kwargs: object):
        if fault == "reset":
            return {
                "status": None,
                "body": "",
                "elapsed_ms": 4,
                "content_type": None,
                "error": "connection reset",
                "truncated": False,
            }
        if fault == "timeout":
            return {
                "status": None,
                "body": "",
                "elapsed_ms": 20,
                "content_type": None,
                "error": "timed out",
                "truncated": False,
            }
        if fault == "denied":
            return {
                "status": 403,
                "body": "forbidden",
                "elapsed_ms": 4,
                "content_type": "text/plain",
                "error": None,
                "truncated": False,
            }
        return {
            "status": 200,
            "body": "abc",
            "elapsed_ms": 4,
            "content_type": "text/plain",
            "error": None,
            "truncated": True,
        }

    record, ok = collect.collect_task("127.0.0.1", "redis_exporter", 9121, "/metrics", 1, 0, http_get_details_fn=get)
    assert record["error"] == expected
    assert record["truncated"] is (fault == "truncated")
    assert ok is (fault == "truncated")


@pytest.mark.parametrize("status", [200, 300, 401, 429, 500])
def test_trigger_acceptance_is_distinct_from_callback_proof(status: int) -> None:
    profile = next(item for item in _TRIGGER_PROFILES if item["name"] == "redis_exporter")
    events: list[dict[str, object]] = []
    result = trigger_detected_exporter_task(
        None,
        "127.0.0.1",
        profile,
        ["127.0.0.1"],
        1,
        0,
        lambda *_args: (status, "probe_success 0\n"),
        emit_trigger_event=events.append,
    )
    assert result["success"] == 0
    assert result["accepted"] == int(200 <= status < 300)
    assert any(item.get("phase") == "callback_result" and item.get("confirmed") is False for item in events)
