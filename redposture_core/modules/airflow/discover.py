"""Read-only secret discovery in Airflow task-instance logs."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from ...clients.airflow_api import AirflowClient
from ...secret_detection import fingerprint, mask_secret, scan_value


@dataclass(frozen=True)
class DiscoverConfig:
    max_dags: int | None = None
    max_runs: int | None = None
    max_tasks: int | None = None
    max_logs: int | None = None
    max_log_bytes: int = 50 * 1024 * 1024
    max_bytes: int = 50 * 1024 * 1024
    max_seconds: float | None = None
    max_findings: int | None = None


@dataclass(frozen=True)
class _Collection:
    items: tuple[dict[str, Any], ...]
    complete: bool
    error: str | None = None


def _component(value: str) -> str:
    return quote(value, safe="")


def _collection(
    client: AirflowClient,
    path: str,
    key: str,
    limit: int | None,
    deadline: float | None,
    *,
    order_by: str | None = None,
    start_offset: int = 0,
) -> _Collection:
    items: list[dict[str, Any]] = []
    seen_pages: set[tuple[str, str, int]] = set()
    selected_order = order_by
    while limit is None or len(items) < limit:
        if deadline is not None and time.monotonic() >= deadline:
            return _Collection(tuple(items), False, "discover_time")
        page_size = min(100, limit - len(items)) if limit is not None else 100
        query_args: dict[str, int | str] = {"limit": page_size, "offset": start_offset + len(items)}
        if selected_order is not None:
            query_args["order_by"] = selected_order
        query = urlencode(query_args)
        response = client.get(f"{path}?{query}")
        if response.transport_error:
            return _Collection(tuple(items), False, "transport_error")
        if response.http_status in {400, 422} and selected_order is not None and not items:
            selected_order = None
            continue
        if response.http_status != 200:
            return _Collection(tuple(items), False, f"http_{response.http_status}")
        if response.truncated:
            return _Collection(tuple(items), False, "response_truncated")
        payload = response.json()
        if not isinstance(payload, dict):
            return _Collection(tuple(items), False, "invalid_collection")
        page = payload.get(key)
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            return _Collection(tuple(items), False, "invalid_collection")
        raw_total = payload.get("total_entries")
        total: int | None = (
            raw_total if isinstance(raw_total, int) and not isinstance(raw_total, bool) and raw_total >= 0 else None
        )
        if not page:
            stalled = total is not None and start_offset + len(items) < total
            return _Collection(
                tuple(items),
                not stalled,
                "pagination_stalled" if stalled else None,
            )
        signature = (repr(page[0])[:256], repr(page[-1])[:256], len(page))
        if signature in seen_pages:
            return _Collection(tuple(items), False, "pagination_stalled")
        seen_pages.add(signature)
        items.extend(page[:page_size])
        if total is not None and start_offset + len(items) >= total:
            return _Collection(tuple(items), True)
        if total is None and len(page) < page_size:
            return _Collection(tuple(items), True)
    return _Collection(tuple(items), False)


def _log_content(response_body: bytes, payload: Any) -> tuple[str, str | None]:
    if not isinstance(payload, dict) or "content" not in payload:
        return response_body.decode("utf-8", errors="replace"), None
    content = payload["content"]
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(str(item.get("event") or "") if isinstance(item, dict) else str(item) for item in content)
    else:
        text = ""
    token = payload.get("continuation_token")
    return text, str(token) if isinstance(token, str) and token else None


def _read_log(
    client: AirflowClient,
    path: str,
    *,
    max_log_bytes: int,
    max_total_bytes: int,
    deadline: float | None,
) -> tuple[str, int, str | None]:
    parts: list[str] = []
    used = 0
    token: str | None = None
    seen_tokens: set[str] = set()
    for _page in range(64):
        if deadline is not None and time.monotonic() >= deadline:
            return "".join(parts), used, "discover_time"
        remaining = min(max_log_bytes - used, max_total_bytes - used)
        if remaining <= 0:
            return "".join(parts), used, "max_log_bytes" if used >= max_log_bytes else "max_bytes"
        query = f"&token={quote(token, safe='')}" if token is not None else ""
        separator = "&" if "?" in path else "?"
        page_path = f"{path}{separator}full_content=false{query}"
        response = client.get(
            page_path,
            extra_headers={"Accept": "application/json"},
            response_size_cap=min(2 * 1024 * 1024, remaining + 64 * 1024),
        )
        if response.transport_error:
            return "".join(parts), used, "transport_error"
        if response.http_status != 200:
            return "".join(parts), used, f"http_{response.http_status}"
        text, next_token = _log_content(response.body, response.json())
        encoded = text.encode("utf-8", errors="replace")
        accepted = encoded[:remaining]
        parts.append(accepted.decode("utf-8", errors="replace"))
        used += len(accepted)
        if response.truncated:
            return "".join(parts), used, "response_truncated"
        if len(encoded) > remaining:
            return "".join(parts), used, "max_log_bytes" if used >= max_log_bytes else "max_bytes"
        if next_token is None:
            return "".join(parts), used, None
        if next_token in seen_tokens:
            return "".join(parts), used, "continuation_loop"
        seen_tokens.add(next_token)
        token = next_token
    return "".join(parts), used, "max_log_pages"


def discover_task_logs(client: AirflowClient, generation: str, config: DiscoverConfig) -> dict[str, Any]:
    """Read DAG task logs in stable order and retain only secret findings."""
    started = time.monotonic()
    deadline = started + config.max_seconds if config.max_seconds is not None else None
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    reasons: list[str] = []
    errors: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str, str, str, int, int]] = set()
    dags_scanned = runs_scanned = tasks_seen = logs_scanned = bytes_scanned = 0

    def partial(reason: str, path: str | None = None) -> None:
        if reason not in reasons:
            reasons.append(reason)
        if path is not None:
            errors.append({"path": path, "reason": reason})

    def iter_collection(
        path: str,
        key: str,
        limit: int | None,
        *,
        error_prefix: str,
        max_reason: str,
        order_by: str | None = None,
    ):
        offset = 0
        seen_pages: set[tuple[str, str, int]] = set()
        while True:
            page_limit = min(100, limit - offset) if limit is not None else 100
            if page_limit <= 0:
                partial(max_reason)
                return
            page = _collection(client, path, key, page_limit, deadline, order_by=order_by, start_offset=offset)
            if page.items:
                signature = (repr(page.items[0])[:256], repr(page.items[-1])[:256], len(page.items))
                if signature in seen_pages:
                    partial(f"{error_prefix}:pagination_stalled", path)
                    return
                seen_pages.add(signature)
            yield from page.items
            offset += len(page.items)
            if page.error:
                partial(f"{error_prefix}:{page.error}", path)
                return
            if page.complete:
                return
            if not page.items:
                partial(f"{error_prefix}:pagination_stalled", path)
                return

    stopped = False
    for dag in iter_collection(f"{prefix}/dags", "dags", config.max_dags, error_prefix="dags", max_reason="max_dags"):
        dag_id = dag.get("dag_id")
        if not isinstance(dag_id, str) or not dag_id:
            continue
        if deadline is not None and time.monotonic() >= deadline:
            partial("discover_time")
            break
        dags_scanned += 1
        runs_path = f"{prefix}/dags/{_component(dag_id)}/dagRuns"
        runs = iter_collection(
            runs_path,
            "dag_runs",
            config.max_runs,
            error_prefix="dag_runs",
            max_reason="max_runs",
            order_by="-start_date" if generation == "v2" else "-execution_date",
        )
        for run in runs:
            run_id = run.get("dag_run_id")
            if not isinstance(run_id, str) or not run_id:
                continue
            runs_scanned += 1
            tasks_path = f"{runs_path}/{_component(run_id)}/taskInstances"
            remaining_tasks = config.max_tasks - tasks_seen if config.max_tasks is not None else None
            if remaining_tasks is not None and remaining_tasks <= 0:
                partial("max_tasks")
                stopped = True
                break
            tasks = iter_collection(
                tasks_path,
                "task_instances",
                remaining_tasks,
                error_prefix="task_instances",
                max_reason="max_tasks",
            )
            for task in tasks:
                task_id = task.get("task_id")
                if not isinstance(task_id, str) or not task_id:
                    continue
                tasks_seen += 1
                try_number = task.get("try_number")
                if not isinstance(try_number, int) or isinstance(try_number, bool) or try_number < 1:
                    continue
                map_index = task.get("map_index", -1)
                if not isinstance(map_index, int) or isinstance(map_index, bool):
                    map_index = -1
                for attempt in range(1, try_number + 1):
                    if deadline is not None and time.monotonic() >= deadline:
                        partial("discover_time")
                        stopped = True
                        break
                    if config.max_logs is not None and logs_scanned >= config.max_logs:
                        partial("max_logs")
                        stopped = True
                        break
                    if bytes_scanned >= config.max_bytes:
                        partial("max_bytes")
                        stopped = True
                        break
                    if config.max_findings is not None and len(findings) >= config.max_findings:
                        partial("max_findings")
                        stopped = True
                        break
                    log_path = f"{tasks_path}/{_component(task_id)}/logs/{attempt}"
                    if map_index >= 0:
                        log_path += f"?map_index={map_index}"
                    text, used, error = _read_log(
                        client,
                        log_path,
                        max_log_bytes=config.max_log_bytes,
                        max_total_bytes=config.max_bytes - bytes_scanned,
                        deadline=deadline,
                    )
                    logs_scanned += 1
                    bytes_scanned += used
                    if error:
                        partial(f"logs:{error}", log_path)
                    for match in scan_value(text):
                        key = (
                            match.detector,
                            fingerprint(match.value),
                            dag_id,
                            run_id,
                            task_id,
                            attempt,
                            map_index,
                        )
                        if key in seen_findings:
                            continue
                        seen_findings.add(key)
                        findings.append(
                            {
                                "type": match.detector,
                                "confidence": match.confidence,
                                "value": match.value,
                                "masked_value": mask_secret(match.value),
                                "fingerprint": key[1],
                                "dag_id": dag_id,
                                "dag_run_id": run_id,
                                "task_id": task_id,
                                "try_number": attempt,
                                "map_index": map_index,
                                "object_path": match.object_path,
                            }
                        )
                        if config.max_findings is not None and len(findings) >= config.max_findings:
                            partial("max_findings")
                            stopped = True
                            break
                    if stopped:
                        break
                if stopped:
                    break
            if stopped:
                break
        if stopped:
            break

    return {
        "status": "partial" if reasons else "complete",
        "api_generation": generation,
        "dags_scanned": dags_scanned,
        "runs_scanned": runs_scanned,
        "task_instances_seen": tasks_seen,
        "logs_scanned": logs_scanned,
        "bytes_scanned": bytes_scanned,
        "finding_count": len(findings),
        "findings": findings,
        "partial_reasons": reasons,
        "errors": errors,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


__all__ = ["DiscoverConfig", "discover_task_logs"]
