"""Default summary counts must not require retaining every project object."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.gitlab import actions


def count(monkeypatch: pytest.MonkeyPatch, replies: list[Any]) -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []
    iterator = iter(replies)

    def request(_host: str, _port: int, path: str, _timeout: float, **kwargs: Any) -> Any:
        calls.append({"query": parse_qs(urlsplit(path).query), **kwargs})
        return next(iterator)

    monkeypatch.setattr(actions, "_api_get_json", request)
    return actions._count_projects("qa", 443, 1, use_https=True, token="identity", public_only=True), calls


def headers(total: str = "250", **overrides: str) -> dict[str, str]:
    return {"x-total": total, "x-total-pages": "3", "x-page": "1", "x-per-page": "100", "x-next-page": "2", **overrides}


def test_exact_server_count_avoids_loading_later_project_pages(monkeypatch):
    (value, error), calls = count(monkeypatch, [(200, [{"id": i} for i in range(100)], headers(), None)])
    assert (value, error) == (250, None)
    assert len(calls) == 1
    assert calls[0]["token"] == "identity" and calls[0]["use_https"] is True
    assert calls[0]["query"]["visibility"] == ["public"]


@pytest.mark.parametrize(
    "bad",
    [
        {},
        headers("bad"),
        headers("-1"),
        headers("9"),
        headers("9" * 5000),
        headers(**{"x-page": "2"}),
        headers(**{"x-per-page": "0"}),
        headers(**{"x-total-pages": "90"}),
        headers(**{"x-next-page": "3"}),
    ],
)
def test_missing_or_inconsistent_totals_fall_back_without_losing_pages(monkeypatch, bad):
    first = [{"id": i} for i in range(100)]
    # Preserve the original continuation when the count headers are rejected.
    bad = {**bad, "x-next-page": bad.get("x-next-page", "2")}
    (value, error), calls = count(monkeypatch, [(200, first, bad, None), (200, [{"id": 200}], {}, None)])
    assert (value, error) == (101, None)
    assert len(calls) == 2
    assert calls[1]["query"]["page"] == [bad["x-next-page"]]


@pytest.mark.parametrize(
    "reply", [(0, None, {}, "reset"), (403, {}, {}, None), (503, {}, {}, None), (200, {}, {}, None)]
)
def test_later_failure_keeps_completed_count_and_partial_reason(monkeypatch, reply):
    (value, error), calls = count(monkeypatch, [(200, [{"id": 1}], {"x-next-page": "2"}, None), reply])
    assert value == 1 and error.startswith("partial:") and len(calls) == 2


def test_empty_catalogue_and_rejected_initial_request_remain_distinct(monkeypatch):
    assert count(monkeypatch, [(200, [], {}, None)])[0] == (0, None)
    assert count(monkeypatch, [(401, {}, {}, None)])[0] == (None, "authentication required")


def test_inventory_still_fetches_every_project_even_with_exact_total(monkeypatch):
    replies = iter(
        [
            (200, [{"id": 1}], headers("2", **{"x-per-page": "1", "x-total-pages": "2"}), None),
            (200, [{"id": 2}], {}, None),
        ]
    )
    monkeypatch.setattr(actions, "_api_get_json", lambda *a, **kw: next(replies))
    assert actions._paginate_projects("qa", 443, 1, use_https=True, token="identity", public_only=False) == (
        [{"id": 1}, {"id": 2}],
        None,
    )


def test_count_fallback_does_not_retain_completed_page_objects(monkeypatch):
    import weakref

    alive = []
    page = 0

    class Project(dict):
        pass

    def request(*args, **kwargs):
        nonlocal page
        page += 1
        assert sum(ref() is not None for ref in alive) <= 2
        item = Project(id=page)
        alive.append(weakref.ref(item))
        return 200, [item], {"x-next-page": str(page + 1) if page < 50 else ""}, None

    monkeypatch.setattr(actions, "_api_get_json", request)
    assert actions._count_projects("qa", 443, 1, use_https=True, token=None, public_only=False) == (50, None)
    assert not any(ref() is not None for ref in alive)


def test_summary_collector_uses_separate_public_and_verified_token_counts(monkeypatch):
    state = actions.GitLabLifecycleState(token_valid=True)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        host="qa",
        port=443,
        args=SimpleNamespace(timeout=1),
        credential=SimpleNamespace(token="verified"),
    )
    calls = []

    def counts(*a, **kw):
        calls.append(kw)
        return (7 if kw["token"] is None else 250), None

    monkeypatch.setattr(actions, "_count_projects", counts)
    monkeypatch.setattr(actions, "_paginate_projects", lambda *a, **kw: pytest.fail("summary loaded catalogue"))
    result = actions.collect_gitlab_data(
        ctx, {"https": True}, {"count_only": True, "project_filters": [], "clone": False, "clone_dir": "/unused"}
    )
    assert result["public_projects"] is None and result["token_projects"] is None
    assert result["public_projects_count"] == 7 and result["token_projects_count"] == 250
    assert [c["token"] for c in calls] == [None, "verified"]


@pytest.mark.parametrize(
    "flags,summary",
    [
        ([], True),
        (["--project", "platform/reporting"], False),
        (["--images"], False),
        (["--clone"], False),
        (["--discover"], False),
    ],
)
def test_public_spec_only_requests_counts_when_project_objects_are_unused(monkeypatch, flags, summary):
    from redposture_core.audit_models import AuditRecord
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.gitlab import stage
    from redposture_core.modules.registry.actions import RegistryLifecycleState

    args = parse_args(["gitlab", "-t", "http://qa", "--token", "verified", *flags])
    state = stage.GitLabCombinedState(actions.GitLabLifecycleState(), RegistryLifecycleState())
    ctx = SimpleNamespace(
        args=args,
        lifecycle_state=state,
        host="qa",
        port=80,
        target=SimpleNamespace(scheme="http", path=""),
        credential=SimpleNamespace(source="web_token", token="verified", username=None),
    )
    seen = []

    def collect(ctx, record, options):
        seen.append(options["count_only"])
        return {
            **record.to_dict(),
            "public_projects": None,
            "token_projects": None,
            "public_projects_count": 7,
            "token_projects_count": 250,
        }

    monkeypatch.setattr(actions, "collect_gitlab_data", collect)
    monkeypatch.setattr(stage, "discover_gitlab_sources", lambda *a: None)
    spec = stage.build_gitlab_spec(args)
    assert spec.data is not None
    result = spec.data(
        ctx, AuditRecord.from_mapping({"gitlab_surface": "web"}, module="gitlab", service="gitlab")
    ).to_dict()
    if "--discover" in flags:
        assert seen == []  # Dedicated discovery reader owns the full traversal.
    else:
        assert seen == [summary]
        if summary:
            assert result["public_projects_count"] == 7 and result["token_projects_count"] == 250


@pytest.mark.parametrize(
    "key,value", [("project_filters", ["group/selected"]), ("show_repositories", True), ("clone", True)]
)
def test_collector_defensively_refuses_count_only_when_objects_are_needed(monkeypatch, key, value):
    state = actions.GitLabLifecycleState(token_valid=True)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        host="qa",
        port=443,
        args=SimpleNamespace(timeout=1, workers=1),
        credential=SimpleNamespace(token="verified"),
        nested_scheduler=None,
    )
    monkeypatch.setattr(actions, "_count_projects", lambda *a, **k: pytest.fail("discarded selected project objects"))
    monkeypatch.setattr(actions, "_paginate_projects", lambda *a, **k: ([], None))
    monkeypatch.setattr(actions, "_fetch_project_by_ref", lambda *a, **k: (None, "not found"))
    options = {
        "count_only": True,
        "project_filters": [],
        "show_repositories": False,
        "clone": False,
        "clone_dir": "/unused",
        key: value,
    }
    result = actions.collect_gitlab_data(ctx, {"https": True}, options)
    assert result["public_projects"] == [] and result["token_projects"] == []


def test_total_is_not_accepted_for_malformed_page_items(monkeypatch):
    replies = [
        (200, [{"id": 1}, "not a project"], headers("3", **{"x-per-page": "2", "x-total-pages": "2"}), None),
        (200, [{"id": 2}], {}, None),
    ]
    (value, error), calls = count(monkeypatch, replies)
    assert value == 2 and error is None and len(calls) == 2
