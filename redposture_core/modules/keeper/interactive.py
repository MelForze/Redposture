"""Operator decisions for Keeper DDL account changes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TextIO

from . import ddl


def _write(stream: TextIO, message: str) -> None:
    stream.write(message)
    stream.flush()


def _answer(input_stream: TextIO, output_stream: TextIO, prompt: str) -> str | None:
    _write(output_stream, prompt)
    try:
        answer = input_stream.readline()
    except KeyboardInterrupt:
        _write(output_stream, "\n")
        return None
    return answer.strip() if answer else None


def _choose(
    title: str,
    values: list[str],
    descriptions: list[str],
    input_stream: TextIO,
    output_stream: TextIO,
) -> list[str] | None:
    _write(output_stream, f"{title}:\n")
    for index, description in enumerate(descriptions, 1):
        _write(output_stream, f"  {index}) {description}\n")
    _write(output_stream, "  a) all\n  q) cancel\n")
    while True:
        answer = _answer(input_stream, output_stream, "Choose (number(s), a or q): ")
        if answer is None or answer.lower() in {"", "q", "quit"}:
            return None
        if answer.lower() in {"a", "all"}:
            return values
        try:
            numbers = [int(part.strip()) for part in answer.split(",")]
        except ValueError:
            numbers = []
        if numbers and all(1 <= number <= len(values) for number in numbers):
            return list(dict.fromkeys(values[number - 1] for number in numbers))
        _write(output_stream, "Choose listed numbers, a, or q.\n")


def _confirm(input_stream: TextIO, output_stream: TextIO, prompt: str) -> bool:
    while True:
        answer = _answer(input_stream, output_stream, prompt)
        if answer is None or answer.lower() in {"", "n", "no"}:
            return False
        if answer.lower() in {"y", "yes"}:
            return True
        _write(output_stream, "Answer y or n.\n")


def _summarize(values: list[str]) -> str:
    return ", ".join(values)


def run_user_creation(
    client: Any,
    username: str,
    password: str,
    *,
    access: str,
    grant_admin: bool,
    clickhouse_host: str | None,
    clickhouse_port: int | None,
    clickhouse_cluster: str | None,
    timeout: float,
    input_stream: TextIO,
    output_stream: TextIO,
    refresh_session: Callable[[], tuple[bool, str | None]] | None = None,
) -> dict[str, Any]:
    """Choose topology and require two distinct approvals before DDL writes."""

    result: dict[str, Any] = {
        "username": username,
        "status": "unavailable",
        "admin_status": "not_attempted" if grant_admin else "not_requested",
        "clusters": [],
        "reason": None,
    }
    if access != "Write":
        result["reason"] = f"DDL access is {access}"
        return result
    topology = ddl.read_ddl_topology(client)
    discovered = topology.get("clusters") if topology.get("status") == "ok" else None
    clusters = discovered if isinstance(discovered, dict) else {}
    selected_clusters: list[str] | None
    if clickhouse_cluster:
        selected_clusters = [clickhouse_cluster]
    elif clusters:
        names = sorted(clusters)
        selected_clusters = _choose(
            "ClickHouse clusters",
            names,
            [
                f"{name} ({len(clusters[name])} {'worker' if len(clusters[name]) == 1 else 'workers'}: "
                f"{_summarize(clusters[name])})"
                for name in names
            ],
            input_stream,
            output_stream,
        )
    else:
        selected_clusters = None
        result["reason"] = "--clickhouse-host and --clickhouse-cluster are required without usable DDL tasks"
        return result
    if not selected_clusters:
        result["status"] = "declined"
        return result
    if clickhouse_host and len(selected_clusters) > 1:
        result["reason"] = "one explicit ClickHouse host cannot select multiple clusters"
        return result

    plans: list[tuple[str, list[str]]] = []
    for cluster in selected_clusters:
        if clickhouse_host:
            hosts = [f"{clickhouse_host}:{clickhouse_port or 9000}"]
        elif cluster in clusters and clusters[cluster]:
            available = list(clusters[cluster])
            chosen_hosts = _choose(f"DDL workers for {cluster}", available, available, input_stream, output_stream)
            if chosen_hosts is None:
                result["status"] = "declined"
                return result
            hosts = chosen_hosts
            if len(hosts) < len(available):
                _write(output_stream, "Warning: user will exist only on selected workers.\n")
        else:
            result["reason"] = f"no DDL workers for {cluster}; specify --clickhouse-host"
            return result
        plans.append((cluster, hosts))

    _write(output_stream, f"\nPlan: CREATE USER {username} (password hidden; DDL stores a SHA-256 hash)\n")
    for cluster, hosts in plans:
        _write(output_stream, f"  Cluster: {cluster}; workers ({len(hosts)}): {_summarize(hosts)}\n")
    if not _confirm(input_stream, output_stream, "Create user? [y/N]: "):
        result["status"] = "declined"
        return result

    for cluster, hosts in plans:
        if refresh_session is not None:
            ready, reason = refresh_session()
            if not ready:
                creation = {
                    "username": username,
                    "cluster": cluster,
                    "hosts": hosts,
                    "status": "unavailable",
                    "admin_status": "not_attempted" if grant_admin else "not_requested",
                    "reason": reason or "DDL session could not be refreshed",
                }
                result["clusters"].append(creation)
                continue
        creation = ddl.create_user_via_ddl(
            client,
            username,
            password,
            access=access,
            grant_admin=False,
            clickhouse_host=None,
            clickhouse_port=None,
            clickhouse_cluster=cluster,
            selected_hosts=hosts,
            timeout=timeout,
        )
        creation["cluster"] = cluster
        creation["admin_status"] = "not_attempted" if grant_admin else "not_requested"
        result["clusters"].append(creation)

    successful = [item for item in result["clusters"] if item["status"] == "created"]
    result["status"] = "created" if len(successful) == len(plans) else "partial" if successful else "failed"
    if grant_admin:
        for item in successful:
            cluster = str(item["cluster"])
            hosts = list(item["hosts"])
            _write(
                output_stream,
                f"\nPlan: GRANT ALL ON *.* TO {username} WITH GRANT OPTION\n"
                f"  Cluster: {cluster}; workers ({len(hosts)}): {_summarize(hosts)}\n",
            )
            if not _confirm(input_stream, output_stream, "Grant admin rights? [y/N]: "):
                item["admin_status"] = "declined"
                continue
            if refresh_session is not None:
                ready, reason = refresh_session()
                if not ready:
                    item["admin_status"] = "unavailable"
                    item["reason"] = reason or "DDL session could not be refreshed"
                    continue
            grant = ddl.grant_admin_via_ddl(client, username, cluster, hosts, timeout)
            item.update(grant)
        statuses = [item["admin_status"] for item in result["clusters"]]
        result["admin_status"] = statuses[0] if len(set(statuses)) == 1 else "partial"
    return result
