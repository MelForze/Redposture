"""Explicit ClickHouse user-management tasks through a confirmed Keeper queue."""

from __future__ import annotations

import ast
import hashlib
import re
import time
import uuid
from typing import Any

from ...clients.zookeeper import _ZK_ERR_NONODE, _ZK_ERR_OK, _zk_error_name

_QUEUE = "/clickhouse/task_queue/ddl"
_USERNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CLUSTER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_HOST_ID = re.compile(r"[A-Za-z0-9_.%-]{1,253}:[0-9]{1,5}\Z")
_TASK_NAME = re.compile(r"query-[0-9]{10,}\Z")
_MAX_ENTRY_BYTES = 64 * 1024


def _valid_hosts(raw: str) -> list[str] | None:
    if len(raw) > 16_384:
        return None
    try:
        value = ast.literal_eval(raw)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        return None
    hosts = [
        item
        for item in value
        if isinstance(item, str) and _HOST_ID.fullmatch(item) and 1 <= int(item.rsplit(":", 1)[1]) <= 65535
    ]
    return hosts if len(hosts) == len(value) and len(set(hosts)) == len(hosts) else None


def _parse_template(data: bytes) -> tuple[str, list[str], str] | None:
    if len(data) > _MAX_ENTRY_BYTES:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    version_match = re.match(r"version: ([5-8])\n", text)
    if version_match is None:
        return None
    query_match = re.search(r"(?m)^query: ([^\n]+)$", text)
    hosts_match = re.search(r"(?m)^hosts: (\[[^\n]+\])$", text)
    id_match = re.search(r"(?m)^initial_query_id: [0-9a-fA-F-]{36}$", text)
    if not query_match or not hosts_match or not id_match:
        return None
    cluster_match = re.search(
        r"\bON CLUSTER\s+(?:'([A-Za-z_][A-Za-z0-9_]*)'|([A-Za-z_][A-Za-z0-9_]*))",
        query_match.group(1),
        re.I,
    )
    hosts = _valid_hosts(hosts_match.group(1))
    if cluster_match is None or hosts is None:
        return None
    return text, hosts, cluster_match.group(1) or cluster_match.group(2)


def _scan_templates(client: Any) -> tuple[dict[str, tuple[str, list[str]]], str | None]:
    children, error, _stat = client.get_children2(_QUEUE)
    if error == _ZK_ERR_NONODE:
        return {}, "DDL queue does not exist"
    if error != _ZK_ERR_OK or children is None:
        return {}, f"DDL queue read: {_zk_error_name(error)}"
    task_names = sorted((name for name in children if _TASK_NAME.fullmatch(name)), reverse=True)[:512]
    by_cluster: dict[str, tuple[str, list[str]]] = {}
    for name in task_names:
        raw, read_error, _stat = client.get_data(f"{_QUEUE}/{name}")
        if read_error != _ZK_ERR_OK or raw is None:
            continue
        parsed = _parse_template(raw)
        if parsed is None:
            continue
        text, hosts, cluster = parsed
        if cluster not in by_cluster:
            by_cluster[cluster] = text, hosts
        else:
            template, known_hosts = by_cluster[cluster]
            by_cluster[cluster] = template, list(dict.fromkeys([*known_hosts, *hosts]))
    return by_cluster, None


def read_ddl_topology(client: Any) -> dict[str, Any]:
    """Read DDL worker IDs; replica names are not guaranteed host IDs."""

    try:
        by_cluster, reason = _scan_templates(client)
    except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
        return {"status": "unavailable", "clusters": {}, "reason": exc.__class__.__name__}
    if reason:
        return {"status": "unavailable", "clusters": {}, "reason": reason}
    return {
        "status": "ok",
        "clusters": {cluster: sorted(hosts) for cluster, (_template, hosts) in sorted(by_cluster.items())},
        "reason": None,
        "source": _QUEUE,
    }


def _select_template(
    client: Any, preferred_cluster: str | None
) -> tuple[str | None, list[str] | None, str | None, str | None]:
    by_cluster, reason = _scan_templates(client)
    if reason:
        return None, None, None, reason
    if preferred_cluster:
        selected = by_cluster.get(preferred_cluster)
        return (
            (selected[0], selected[1], preferred_cluster, None)
            if selected is not None
            else (None, None, preferred_cluster, None)
        )
    if len(by_cluster) > 1:
        return None, None, None, "multiple ClickHouse clusters in DDL queue; specify --clickhouse-cluster"
    if by_cluster:
        cluster, (template, hosts) = next(iter(by_cluster.items()))
        return template, hosts, cluster, None
    return None, None, None, None


def _build_entry(query: str, hosts: list[str]) -> bytes:
    if "\n" in query or "\r" in query or ";" in query:
        raise ValueError("DDL task must contain exactly one statement")
    task_id = str(uuid.uuid4())
    # Emit a minimal v5 entry rather than copying settings, backup flags or
    # initiator identity/roles from an unrelated task (v6-v8 may contain them).
    text = (
        "version: 5\n"
        f"query: {query}\n"
        f"hosts: {hosts!r}\n"
        f"initiator: {hosts[0]}\n"
        "tracing: 00000000-0000-0000-0000-000000000000\n"
        "0\n\n0\n"
        f"initial_query_id: {task_id}\n"
    )
    return text.encode("utf-8")


def _wait_for_hosts(client: Any, path: str, hosts: list[str], timeout: float) -> tuple[str, dict[str, str]]:
    deadline = time.monotonic() + max(0.1, timeout)
    results: dict[str, str] = {}
    while time.monotonic() < deadline:
        children, error, _stat = client.get_children2(f"{path}/finished")
        if error not in {_ZK_ERR_OK, _ZK_ERR_NONODE}:
            return "unverified", results
        for host in set(children or []).intersection(hosts) - results.keys():
            data, read_error, _stat = client.get_data(f"{path}/finished/{host}")
            if read_error != _ZK_ERR_OK or data is None:
                continue
            code = data.split(b"\n", 1)[0].strip()
            results[host] = "ok" if code == b"0" else "failed"
        if len(results) == len(hosts):
            break
        time.sleep(0.1)
    successes = sum(value == "ok" for value in results.values())
    if successes == len(hosts):
        return "created", results
    if successes:
        return "partial", results
    if len(results) == len(hosts):
        return "failed", results
    return "unverified", results


def create_user_via_ddl(
    client: Any,
    username: str,
    password: str,
    *,
    access: str,
    grant_admin: bool,
    clickhouse_host: str | None,
    clickhouse_port: int | None,
    clickhouse_cluster: str | None = None,
    timeout: float,
) -> dict[str, Any]:
    """Enqueue one user task and an optional grant, reporting worker evidence."""

    result: dict[str, Any] = {
        "username": username,
        "status": "unavailable",
        "admin_status": "not_attempted" if grant_admin else "not_requested",
        "hosts": [],
        "task_path": None,
        "grant_task_path": None,
        "results": {},
        "reason": None,
    }
    if access != "Write":
        result["reason"] = f"DDL access is {access}"
        return result
    if not _USERNAME.fullmatch(username) or not password:
        result["reason"] = "invalid user name or empty password"
        return result
    if clickhouse_host is not None:
        port = clickhouse_port or 9000
        host_id = f"{clickhouse_host}:{port}"
        if not _HOST_ID.fullmatch(host_id) or not 1 <= port <= 65535:
            result["reason"] = "invalid ClickHouse host or port"
            return result
    try:
        _template, discovered_hosts, discovered_cluster, reason = _select_template(client, clickhouse_cluster)
        if reason:
            result["reason"] = reason
            return result
        hosts = [f"{clickhouse_host}:{clickhouse_port or 9000}"] if clickhouse_host else discovered_hosts
        cluster = clickhouse_cluster or discovered_cluster
        if not hosts or not cluster or not _CLUSTER.fullmatch(cluster):
            result["reason"] = "ClickHouse host and cluster are required when the queue has no usable task"
            return result
        result["hosts"] = hosts
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        query = f"CREATE USER {username} ON CLUSTER {cluster} IDENTIFIED WITH sha256_hash BY '{password_hash}'"
        path, create_error = client.create_sequential(f"{_QUEUE}/query-", _build_entry(query, hosts))
        if create_error != _ZK_ERR_OK or not path:
            result["status"] = "failed"
            result["reason"] = f"enqueue: {_zk_error_name(create_error)}"
            return result
        result["task_path"] = path
        status, host_results = _wait_for_hosts(client, path, hosts, timeout)
        result["status"] = status
        result["results"] = host_results
        if status != "created" or not grant_admin:
            return result
        grant_query = f"GRANT ON CLUSTER {cluster} ALL ON *.* TO {username} WITH GRANT OPTION"
        grant_path, grant_error = client.create_sequential(f"{_QUEUE}/query-", _build_entry(grant_query, hosts))
        if grant_error != _ZK_ERR_OK or not grant_path:
            result["admin_status"] = "failed"
            result["reason"] = f"grant enqueue: {_zk_error_name(grant_error)}"
            return result
        result["grant_task_path"] = grant_path
        grant_status, grant_results = _wait_for_hosts(client, grant_path, hosts, timeout)
        result["admin_status"] = "granted" if grant_status == "created" else grant_status
        result["grant_results"] = grant_results
        return result
    except (TimeoutError, ConnectionError, OSError, ValueError, TypeError, AttributeError) as exc:
        result["status"] = "unverified" if result["task_path"] else "unavailable"
        result["reason"] = exc.__class__.__name__
        return result
