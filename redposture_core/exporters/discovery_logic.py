"""Pure scoring helpers for exporter discovery."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..scheduler import BoundedScheduler
from .http_client import build_http_url

HttpGetDetails = Callable[..., dict[str, Any]]


def as_token_tuple(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        value = raw.strip()
        return (value,) if value else ()
    if not isinstance(raw, (list, tuple)):
        return ()
    result: list[str] = []
    for item in raw:
        token = str(item or "").strip()
        if not token or token in result:
            continue
        result.append(token)
    return tuple(result)


def score_metrics_candidate(exporter: dict[str, Any], body: str) -> dict[str, Any] | None:
    exporter_name = str(exporter.get("name") or "").strip()
    if not exporter_name:
        return None

    strong_markers = as_token_tuple(exporter.get("strong_markers")) or as_token_tuple(exporter.get("markers"))
    weak_markers = tuple(
        marker for marker in as_token_tuple(exporter.get("weak_markers")) if marker not in strong_markers
    )
    negative_markers = as_token_tuple(exporter.get("negative_markers"))

    strong_hits = [marker for marker in strong_markers if marker in body]
    weak_hits = [marker for marker in weak_markers if marker in body]
    negative_hits = [marker for marker in negative_markers if marker in body]

    score = (len(strong_hits) * 100) + (len(weak_hits) * 25) - (len(negative_hits) * 80)
    if score <= 0:
        return None

    marker_hit = strong_hits[0] if strong_hits else (weak_hits[0] if weak_hits else None)
    return {
        "name": exporter_name,
        "score": score,
        "strong_count": len(strong_hits),
        "weak_count": len(weak_hits),
        "negative_count": len(negative_hits),
        "marker_hit": marker_hit,
    }


def needs_fingerprint_tiebreak(candidates: list[dict[str, Any]], *, weak_confidence_score: int = 50) -> bool:
    if not candidates:
        return False

    top = candidates[0]
    top_score = int(top.get("score") or 0)
    top_strong = int(top.get("strong_count") or 0)

    if top_strong <= 0:
        if len(candidates) <= 1:
            return top_score < weak_confidence_score
        return True
    if len(candidates) <= 1:
        return False

    second = candidates[1]
    second_score = int(second.get("score") or 0)
    second_strong = int(second.get("strong_count") or 0)
    if top_strong > second_strong and top_score > second_score:
        return False
    if top_score == second_score:
        return True
    if (top_score - second_score) < 35:
        return True
    return False


def select_fingerprint_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not candidates:
        return []
    top_score = int(candidates[0].get("score") or 0)
    return [item for item in candidates if (top_score - int(item.get("score") or 0)) < 35]


def fetch_fingerprint_bodies(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    scheme: str = "http",
    http_get_details_fn: HttpGetDetails,
    max_bytes: int,
) -> tuple[str, str]:
    vars_url = build_http_url(host, port, "/debug/vars", scheme=scheme)
    cmdline_url = build_http_url(host, port, "/debug/pprof/cmdline?debug=1", scheme=scheme)

    scheduler: BoundedScheduler[tuple[str, str], dict[str, Any]] = BoundedScheduler(max_workers=2, max_inflight=2)
    results: dict[str, dict[str, Any]] = {}
    for (name, _url), result in scheduler.iter_completed(
        [("vars", vars_url), ("cmdline", cmdline_url)],
        lambda item: http_get_details_fn(
            item[1],
            timeout,
            retries,
            max_bytes=max_bytes,
        ),
    ):
        results[name] = result

    vars_result = results.get("vars", {})
    cmdline_result = results.get("cmdline", {})
    vars_body = str(vars_result.get("body") or "") if (vars_result.get("status") or 0) < 400 else ""
    cmdline_body = str(cmdline_result.get("body") or "") if (cmdline_result.get("status") or 0) < 400 else ""
    return vars_body, cmdline_body


def score_fingerprint_candidate(exporter: dict[str, Any], vars_body: str, cmdline_body: str) -> tuple[int, int]:
    vars_tokens = as_token_tuple(exporter.get("fingerprint_vars"))
    cmdline_tokens = as_token_tuple(exporter.get("fingerprint_cmdline"))

    vars_hits = sum(1 for token in vars_tokens if token in vars_body)
    cmdline_hits = sum(1 for token in cmdline_tokens if token in cmdline_body)
    score = (vars_hits * 20) + (cmdline_hits * 25)
    return score, vars_hits + cmdline_hits


def resolve_best_exporter_candidate(
    *,
    host: str,
    port: int,
    candidates: list[dict[str, Any]],
    exporters_by_name: dict[str, dict[str, Any]],
    timeout: float,
    retries: int,
    fetch_fingerprint_bodies_fn: Callable[[str, int, float, int], tuple[str, str]],
    weak_confidence_score: int = 50,
) -> tuple[dict[str, Any] | None, str, str]:
    if not candidates:
        return None, "none", "no_markers"

    if not needs_fingerprint_tiebreak(candidates, weak_confidence_score=weak_confidence_score):
        return candidates[0], "marker", "marker_unique"

    shortlist = select_fingerprint_candidates(candidates)
    if not shortlist:
        return None, "ambiguous", "ambiguous_empty_shortlist"

    vars_body, cmdline_body = fetch_fingerprint_bodies_fn(host, port, timeout, retries)

    ranked: list[tuple[int, int, int, dict[str, Any]]] = []
    for candidate in shortlist:
        exporter_name = str(candidate.get("name") or "")
        exporter = exporters_by_name.get(exporter_name)
        if exporter is None:
            continue
        fp_score, fp_hits = score_fingerprint_candidate(exporter, vars_body, cmdline_body)
        ranked.append((fp_score, fp_hits, int(candidate.get("score") or 0), candidate))

    if not ranked:
        return None, "ambiguous", "ambiguous_no_ranked_candidates"

    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    top_fp, _top_hits, _top_metric, top_candidate = ranked[0]
    second_fp = ranked[1][0] if len(ranked) > 1 else -1
    runner_up = candidates[1] if len(candidates) > 1 else None
    top_metric_score = int(top_candidate.get("score") or 0)
    top_metric_strong = int(top_candidate.get("strong_count") or 0)
    second_metric_score = int(runner_up.get("score") or 0) if runner_up is not None else -1
    second_metric_strong = int(runner_up.get("strong_count") or 0) if runner_up is not None else -1

    if top_fp <= 0:
        if top_metric_strong > second_metric_strong and top_metric_score > second_metric_score:
            return top_candidate, "marker", "marker_fallback_no_fingerprint"
        # Precision-first: unresolved conflict stays unknown.
        return None, "ambiguous", "ambiguous_no_fingerprint_hits"
    if top_fp == second_fp:
        if top_metric_strong > second_metric_strong and top_metric_score > second_metric_score:
            return top_candidate, "marker", "marker_fallback_fp_tie"
        return None, "ambiguous", "ambiguous_fingerprint_tie"

    return top_candidate, "fingerprint", "fingerprint_unique"


def resolve_fingerprint_only_candidate(
    *,
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
    fetch_fingerprint_bodies_fn: Callable[[str, int, float, int], tuple[str, str]],
) -> tuple[dict[str, Any] | None, str, str]:
    if not exporters:
        return None, "none", "no_exporters"

    vars_body, cmdline_body = fetch_fingerprint_bodies_fn(host, port, timeout, retries)
    ranked: list[tuple[int, int, str]] = []
    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "").strip()
        if not exporter_name:
            continue
        fp_score, fp_hits = score_fingerprint_candidate(exporter, vars_body, cmdline_body)
        if fp_score <= 0:
            continue
        ranked.append((fp_score, fp_hits, exporter_name))

    if not ranked:
        return None, "none", "no_fingerprint_hits"

    ranked.sort(reverse=True)
    top_score, top_hits, top_name = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None
    if second is not None and (top_score, top_hits) == second[:2]:
        return None, "ambiguous", "ambiguous_fingerprint_only_tie"

    return (
        {
            "name": top_name,
            "score": 0,
            "strong_count": 0,
            "weak_count": 0,
            "negative_count": 0,
            "marker_hit": None,
        },
        "fingerprint",
        "fingerprint_only",
    )


def resolve_prometheus_port_fallback(exporters: list[dict[str, Any]]) -> dict[str, Any] | None:
    unique_names: list[str] = []
    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "").strip()
        if not exporter_name or exporter_name in unique_names:
            continue
        unique_names.append(exporter_name)
    if len(unique_names) != 1:
        return None
    return {
        "name": unique_names[0],
        "score": 0,
        "strong_count": 0,
        "weak_count": 0,
        "negative_count": 0,
        "marker_hit": None,
    }


__all__ = [
    "as_token_tuple",
    "fetch_fingerprint_bodies",
    "needs_fingerprint_tiebreak",
    "resolve_best_exporter_candidate",
    "resolve_fingerprint_only_candidate",
    "resolve_prometheus_port_fallback",
    "score_fingerprint_candidate",
    "score_metrics_candidate",
    "select_fingerprint_candidates",
]
