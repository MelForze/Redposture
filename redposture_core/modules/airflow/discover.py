"""Read-only secret discovery in Airflow DAG sources, configuration and logs."""

from __future__ import annotations

import ast
import base64
import json
import time
from collections.abc import Callable
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
    include_dag_sources: bool = False
    include_variables: bool = False
    include_connections: bool = False


@dataclass(frozen=True)
class _Collection:
    items: tuple[dict[str, Any], ...]
    complete: bool
    error: str | None = None
    total: int | None = None


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
    latest_total: int | None = None
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
        latest_total = total
        if not page:
            stalled = total is not None and start_offset + len(items) < total
            return _Collection(
                tuple(items),
                not stalled,
                "pagination_stalled" if stalled else None,
                total,
            )
        signature = (repr(page[0])[:256], repr(page[-1])[:256], len(page))
        if signature in seen_pages:
            return _Collection(tuple(items), False, "pagination_stalled", total)
        seen_pages.add(signature)
        items.extend(page[:page_size])
        if total is not None and start_offset + len(items) >= total:
            return _Collection(tuple(items), True, total=total)
        if total is None and len(page) < page_size:
            return _Collection(tuple(items), True, total=total)
    return _Collection(tuple(items), False, total=latest_total)


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
    # Airflow 2.x can serialize multi-host task logs as the repr of
    # ``[(hostname, content), ...]``. Unwrap that transport envelope so host
    # names and the generated local-file preamble are not scanned as secrets.
    unwrapped = False
    if text.startswith("[("):
        try:
            wrapped = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            wrapped = None
        if isinstance(wrapped, list) and all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], str) for item in wrapped
        ):
            text = "\n".join(item[1] for item in wrapped)
            unwrapped = True
    if unwrapped:
        text = "\n".join(
            line
            for line in text.splitlines()
            if line.strip() != "*** Found local files:" and not line.strip().startswith("***   * ")
        )
    token = payload.get("continuation_token")
    return text, str(token) if isinstance(token, str) and token else None


def _continuation_at_end(token: str) -> bool:
    """Recognize Airflow's signed continuation payload without trusting it."""
    try:
        encoded = token.split(".", 1)[0]
        encoded += "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("end_of_log") is True


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
        if _continuation_at_end(next_token):
            return "".join(parts), used, None
        if next_token in seen_tokens:
            return "".join(parts), used, "continuation_loop"
        seen_tokens.add(next_token)
        token = next_token
    return "".join(parts), used, "max_log_pages"


def list_variable_keys(client: AirflowClient, generation: str, *, limit: int | None = None) -> dict[str, Any]:
    """Return Variable names only; values are never copied into this result."""
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    result = _collection(client, f"{prefix}/variables", "variables", limit, None)
    keys = [
        str(item["key"]) for item in result.items if isinstance(item.get("key"), str) and str(item.get("key") or "")
    ]
    total = result.total if result.total is not None else len(keys)
    return {
        "keys": keys,
        "count": len(keys),
        "total": total,
        "truncated": total > len(keys),
        "error": result.error,
    }


def list_connections(client: AirflowClient, generation: str, *, limit: int | None = None) -> dict[str, Any]:
    """Return the complete read-only Connection objects exposed by Airflow."""

    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    result = _collection(client, f"{prefix}/connections", "connections", limit, None)
    connections = [dict(item) for item in result.items]
    total = result.total if result.total is not None else len(connections)
    return {
        "connections": connections,
        "count": len(connections),
        "total": total,
        "truncated": total > len(connections),
        "error": result.error,
    }


def discover_task_logs(
    client: AirflowClient,
    generation: str,
    config: DiscoverConfig,
    on_finding: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Read DAG task logs in stable order and retain only secret findings."""
    started = time.monotonic()
    deadline = started + config.max_seconds if config.max_seconds is not None else None
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    reasons: list[str] = []
    errors: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    dags_scanned = runs_scanned = tasks_seen = logs_scanned = bytes_scanned = 0
    dag_sources_scanned = variables_scanned = connections_scanned = 0
    dag_source_bytes_scanned = variable_bytes_scanned = connection_bytes_scanned = log_bytes_scanned = 0
    variable_keys: list[str] = []
    variables_error: str | None = None

    def partial(reason: str, path: str | None = None) -> None:
        if reason not in reasons:
            reasons.append(reason)
        if path is not None:
            errors.append({"path": path, "reason": reason})

    def add_matches(value: Any, *, source_kind: str, place: str, context: dict[str, Any] | None = None) -> bool:
        """Append and stream stable, de-duplicated findings. Return False at the finding limit."""
        matches = scan_value(value)
        for match in matches:
            # A vendor-specific detector and the generic api-key detector can
            # identify the exact same value. Likewise, the entropy fallback can
            # encompass an already classified assignment. Keep the specific
            # finding so live output contains one useful line per secret/place.
            if match.detector == "high_entropy" and any(
                other.detector != "high_entropy" and other.value in match.value for other in matches
            ):
                continue
            location = f"{place}{match.object_path}"
            key = (fingerprint(match.value), location)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            finding: dict[str, Any] = {
                "type": match.detector,
                "confidence": match.confidence,
                "value": match.value,
                "masked_value": mask_secret(match.value),
                "fingerprint": key[0],
                "source_kind": source_kind,
                "place": location,
                "object_path": match.object_path,
            }
            if context:
                finding.update(context)
            findings.append(finding)
            if on_finding is not None:
                on_finding(dict(finding))
            if config.max_findings is not None and len(findings) >= config.max_findings:
                partial("max_findings")
                return False
        return True

    def consume_value(value: Any) -> tuple[Any, int, bool]:
        """Apply the shared byte budget to a JSON-compatible value."""
        nonlocal bytes_scanned
        raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
        encoded = raw.encode("utf-8", errors="replace")
        remaining = max(0, config.max_bytes - bytes_scanned)
        accepted = encoded[:remaining]
        bytes_scanned += len(accepted)
        text = accepted.decode("utf-8", errors="replace")
        if len(encoded) > remaining:
            partial("max_bytes")
            return text, len(accepted), False
        return value, len(accepted), True

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

    # Variables and Connections are global configuration surfaces. Inspect them
    # before potentially large task-log walks so a busy deployment cannot starve
    # the small, high-value collections of their shared time/byte budget.
    if config.include_variables:
        variables_path = f"{prefix}/variables"
        for variable in iter_collection(
            variables_path,
            "variables",
            None,
            error_prefix="variables",
            max_reason="max_variables",
        ):
            if deadline is not None and time.monotonic() >= deadline:
                partial("discover_time")
                stopped = True
                break
            key_value = variable.get("key")
            key_name = str(key_value) if isinstance(key_value, str) and key_value else "?"
            if key_name != "?":
                variable_keys.append(key_name)
            scanned, used, complete = consume_value(variable)
            variables_scanned += 1
            variable_bytes_scanned += used
            scan_target: Any = scanned
            if complete and key_name != "?" and "value" in variable:
                # Airflow's collection schema uses the generic field name
                # ``value``. Re-key it with the Variable name so semantic
                # detectors can classify names such as ``db_password``.
                scan_target = {key_name: variable.get("value")}
            if not add_matches(scan_target, source_kind="variable", place=f"variable:{key_name}"):
                stopped = True
                break
            if not complete:
                stopped = True
                break
        variables_error = next(
            (reason.split(":", 1)[1] for reason in reasons if reason.startswith("variables:")),
            None,
        )

    if config.include_connections and not stopped:
        connections_path = f"{prefix}/connections"
        for connection in iter_collection(
            connections_path,
            "connections",
            None,
            error_prefix="connections",
            max_reason="max_connections",
        ):
            if deadline is not None and time.monotonic() >= deadline:
                partial("discover_time")
                stopped = True
                break
            connection_id = connection.get("connection_id") or connection.get("conn_id") or "?"
            scanned, used, complete = consume_value(connection)
            connections_scanned += 1
            connection_bytes_scanned += used
            if not add_matches(
                scanned,
                source_kind="connection",
                place=f"connection:{connection_id}",
            ):
                stopped = True
                break
            if not complete:
                stopped = True
                break

    dag_items = (
        ()
        if stopped
        else iter_collection(f"{prefix}/dags", "dags", config.max_dags, error_prefix="dags", max_reason="max_dags")
    )
    for dag in dag_items:
        if stopped:
            break
        dag_id = dag.get("dag_id")
        if not isinstance(dag_id, str) or not dag_id:
            continue
        if deadline is not None and time.monotonic() >= deadline:
            partial("discover_time")
            break
        dags_scanned += 1

        if config.include_dag_sources:
            source_id = dag_id if generation == "v2" else dag.get("file_token")
            if not isinstance(source_id, str) or not source_id:
                partial("dag_sources:missing_file_token", f"{prefix}/dags/{_component(dag_id)}")
            else:
                source_path = f"{prefix}/dagSources/{_component(source_id)}"
                remaining = config.max_bytes - bytes_scanned
                if remaining <= 0:
                    partial("max_bytes")
                    stopped = True
                    break
                # Airflow 2.x exposes DAG source as ``text/plain`` and returns
                # HTTP 406 when the shared HTTP client advertises JSON only.
                # Airflow 3.x may return the JSON ``{"content": ...}`` shape;
                # accepting both representations keeps the read-only probe
                # compatible with both API generations.
                source_response = client.get(
                    source_path,
                    extra_headers={"Accept": "text/plain, application/json"},
                    response_size_cap=min(remaining + 64 * 1024, 2 * 1024 * 1024),
                )
                if source_response.transport_error:
                    partial("dag_sources:transport_error", source_path)
                elif source_response.http_status != 200:
                    partial(f"dag_sources:http_{source_response.http_status}", source_path)
                else:
                    payload = source_response.json()
                    source_value: Any = (
                        payload.get("content")
                        if isinstance(payload, dict) and isinstance(payload.get("content"), str)
                        else source_response.body.decode("utf-8", errors="replace")
                    )
                    scanned, used, complete = consume_value(source_value)
                    dag_sources_scanned += 1
                    dag_source_bytes_scanned += used
                    if source_response.truncated:
                        partial("dag_sources:response_truncated", source_path)
                    if not add_matches(
                        scanned,
                        source_kind="dag_source",
                        place=f"dag_source:{dag_id}",
                        context={"dag_id": dag_id},
                    ):
                        stopped = True
                        break
                    if not complete:
                        stopped = True
                        break
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
                    log_bytes_scanned += used
                    if error:
                        partial(f"logs:{error}", log_path)
                    log_place = f"log:{dag_id}/{run_id}/{task_id}/try:{attempt}/map:{map_index}"
                    if not add_matches(
                        text,
                        source_kind="task_log",
                        place=log_place,
                        context={
                            "dag_id": dag_id,
                            "dag_run_id": run_id,
                            "task_id": task_id,
                            "try_number": attempt,
                            "map_index": map_index,
                        },
                    ):
                        stopped = True
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
        "dag_sources_scanned": dag_sources_scanned,
        "variables_scanned": variables_scanned,
        "connections_scanned": connections_scanned,
        "bytes_scanned": bytes_scanned,
        "log_bytes_scanned": log_bytes_scanned,
        "dag_source_bytes_scanned": dag_source_bytes_scanned,
        "variable_bytes_scanned": variable_bytes_scanned,
        "connection_bytes_scanned": connection_bytes_scanned,
        "variable_keys": variable_keys,
        "variables_error": variables_error,
        "finding_count": len(findings),
        "findings": findings,
        "partial_reasons": reasons,
        "errors": errors,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


__all__ = ["DiscoverConfig", "discover_task_logs", "list_connections", "list_variable_keys"]
