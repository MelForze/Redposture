#!/usr/bin/env python3
"""Native data-adapter cost with authored socket/SDK peers, not server throughput.

Runs production read/format helpers for Redis/PostgreSQL/ClickHouse/Oracle/
MongoDB and the shared ZooKeeper/Keeper tree reader. Network, authentication,
TLS, driver internals behind an SDK boundary and hypervisor work are excluded.
The short wire profiles cover detection/auth separately; full CI/QA remains.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.performance_container import container_sample  # noqa: E402
from scripts.profile_module_performance import (  # noqa: E402
    activate_source,
    environment_evidence,
    fd_count,
    source_hash,
)

MODULES = ("redis", "postgres", "clickhouse", "oracle", "mongodb", "zookeeper", "keeper")


def document(i: int) -> dict[str, Any]:
    return {"id": i, "password": f"inactive-row-{i:06d}!42", "name": "данные"}


def text(i: int) -> str:
    return json.dumps(document(i), ensure_ascii=False, separators=(",", ":"))


class Socket:
    def __init__(self, response: bytes) -> None:
        self.data = response
        self.offset = 0
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        value = self.data[self.offset : self.offset + size]
        self.offset += len(value)
        return value

    def gettimeout(self) -> None:
        return None

    def settimeout(self, value: Any) -> None:
        pass


def native_data(module: str, count: int) -> tuple[Any, Any, str]:
    """Expected data is authored here, never derived from returned records."""
    actual: Any
    expected: Any
    if module == "redis":
        from redposture_core.modules.redis import actions as redis_actions

        actual = []
        for i in range(count):
            raw = text(i).encode()
            sock = Socket(b"$6\r\nstring\r\n$" + str(len(raw)).encode() + b"\r\n" + raw + b"\r\n")
            value, error = redis_actions._dump_redis_key_value(cast(Any, sock), f"key{i:06d}")
            assert error is None and len(sock.sent) == 2 and sock.offset == len(sock.data)
            actual.append(value)
        return (
            actual,
            [text(i) for i in range(count)],
            "production RESP read/format; byte-socket peer, excludes network",
        )
    if module == "postgres":
        from redposture_core.modules.postgres import actions as postgres_actions

        messages = []
        for i in range(count):
            raw = text(i).encode()
            payload = struct.pack("!hi", 1, len(raw)) + raw
            messages.append(b"D" + struct.pack("!i", len(payload) + 4) + payload)
        sock = Socket(b"".join(messages) + b"Z\x00\x00\x00\x05I")
        name, rows, error = postgres_actions._pg_query_table_rows(cast(Any, sock), "qa.items", max_rows=count)
        assert error is None and name == "qa.items" and len(sock.sent) == 1 and sock.offset == len(sock.data)
        return (
            rows,
            [text(i) for i in range(count)],
            "production query/row decoding; byte-socket peer, excludes startup/auth/network",
        )
    if module == "clickhouse":
        from redposture_core.modules.clickhouse import actions as clickhouse_actions

        class ClickHousePeer:
            def execute(self, sql, **kwargs):
                assert sql == f"SELECT * FROM `qa`.`items` LIMIT {count}"
                return [(i, text(i)) for i in range(count)]

        rows, error = clickhouse_actions._query_table_rows(
            clickhouse_actions._ChSession(
                protocol="native", client=ClickHousePeer(), username="qa", password="fixture", database="qa"
            ),
            "qa",
            "items",
            max_rows=count,
        )
        assert error is None
        return (
            rows,
            [json.dumps([i, text(i)], ensure_ascii=False) for i in range(count)],
            "production query/row adapter; execute-result SDK peer, excludes driver/network",
        )
    if module == "mongodb":
        from redposture_core.modules.mongodb import actions as mongodb_actions

        class MongoPeer:
            def list_collection_names(self, db):
                assert db == "qa"
                return ["items"]

            def count_documents(self, db, collection):
                assert (db, collection) == ("qa", "items")
                return count

            def find_documents(self, db, collection, **kwargs):
                assert (db, collection) == ("qa", "items") and kwargs["limit"] == count
                return [document(i) for i in range(count)]

        data = mongodb_actions._collect_mongodb_data(
            cast(Any, MongoPeer()),
            database_names=["qa"],
            selected_database="qa",
            collection_targets=[],
            collection_targets_by_database={},
            show_databases=True,
            show_collections=True,
            show_indexes=False,
            dump_documents=True,
            dump_limit=count,
            query_filter=None,
            projection=None,
        )
        expected = [{"database": "qa", "collection": "items", "document": document(i)} for i in range(count)]
        return (
            data["documents"],
            expected,
            "production catalog/document adapter; MongoAuditClient peer, excludes PyMongo/TLS/DNS/network",
        )
    if module == "oracle":
        from redposture_core.modules.oracle import actions as oracle_actions

        class OraclePeer:
            def current_context(self):
                return {"session_user": "QA", "con_name": "FREEPDB1"}

            def server_banner(self):
                return {"version": "23.0.0"}

            def list_tables(self, schema):
                assert schema == "QA"
                return [{"owner": "QA", "table_name": "ITEMS"}]

            def dump_table(self, owner, table, *, limit):
                assert (owner, table, limit) == ("QA", "ITEMS", count)
                return [document(i) for i in range(count)]

        flags: Any = dict.fromkeys(
            "show_pdbs show_users show_roles show_privs show_schemas show_tables privesc_check privesc_chain wallet_search hashes sensitive_scan dblink_check".split(),
            False,
        )
        data = oracle_actions._collect_oracle_data(
            cast(Any, OraclePeer()),
            host="qa.invalid",
            port=1521,
            protocol="tcp",
            insecure=False,
            schema="QA",
            table="ITEMS",
            dump_rows=True,
            dump_limit=count,
            query=None,
            exec_cmd=None,
            exec_method="scheduler",
            reverse_shell=None,
            reverse_shell_type="bash",
            os_read=None,
            os_write=None,
            download=None,
            delete=None,
            **flags,
        )
        assert not data.get("error"), data.get("error")
        return (
            data["rows"],
            [{"schema": "QA", "table": "ITEMS", "row": document(i)} for i in range(count)],
            "production selected table adapter; OracleAuditClient peer, excludes oracledb/TNS/network",
        )
    if module in {"zookeeper", "keeper"}:
        from redposture_core.clients.zookeeper import _enumerate_znodes, _format_znode_data

        class ZkPeer:
            def get_children2(self, path):
                return ([f"item{i:06d}" for i in range(count)] if path == "/" else []), 0, None

            def get_data(self, path):
                return (b"" if path == "/" else text(int(path.removeprefix("/item"))).encode()), 0, None

        client = ZkPeer()
        paths, total, truncated, _, error = _enumerate_znodes(
            cast(Any, client), count + 1, collect_paths=True, enum_workers=1
        )
        assert error is None and not truncated and total == count
        actual = [{"path": path, "value": _format_znode_data(client.get_data(path)[0])} for path in paths]
        expected = [{"path": f"/item{i:06d}", "value": text(i)} for i in range(count)]
        return (
            actual,
            expected,
            "production shared ZooKeeper/Keeper tree/data adapter; _ZkClient peer, excludes network/session/ACL/DDL",
        )
    raise ValueError("unsupported module")


def measure(args: Any) -> dict[str, Any]:
    activate_source(args.source)
    source = source_hash(args.source)
    fd = fd_count()
    stopped = threading.Event()
    peak = [fd]
    errors: list[str] = []

    def sample() -> None:
        while not stopped.wait(0.005):
            try:
                peak[0] = max(peak[0], fd_count())
            except OSError as exc:
                errors.append(str(exc))
                return

    sampler = threading.Thread(target=sample, name="native-data-resource-sampler")
    sampler.start()
    start = time.monotonic()
    cpu = time.process_time()
    try:
        actual, expected, scope = native_data(args.module, args.rows)
        first = time.monotonic() - start
        encoded = json.dumps(actual, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        wanted = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        wall, cpu = time.monotonic() - start, time.process_time() - cpu
    finally:
        stopped.set()
        sampler.join(2)
    cleanup = fd_count() == fd
    after_source = source_hash(args.source)
    return {
        "module": args.module,
        "mode": "data-adapter",
        "scope": scope,
        "rows": args.rows,
        "quality": "PASS"
        if encoded == wanted
        and cleanup
        and not sampler.is_alive()
        and not errors
        and source == after_source
        and b"\x1b" not in encoded
        else "FAIL",
        "result_sha256": hashlib.sha256(encoded).hexdigest(),
        "expected_sha256": hashlib.sha256(wanted).hexdigest(),
        "missing": [] if encoded == wanted else ["exact data mismatch"],
        "extra": [],
        "duplicates": 0,
        "wall_seconds": wall,
        "cpu_seconds": cpu,
        "first_finding_seconds": first,
        "first_finding_note": "upper bound: first complete selected data batch available, not a secret scan",
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "fd_peak": max(peak[0], fd_count()),
        "fd_before": fd,
        "fd_after": fd_count(),
        "cleanup": "PASS" if cleanup else "FAIL",
        "fd_measurement": "5 ms sampled; transient shorter spikes may be missed",
        "resource_errors": errors,
        "source_sha256": source,
        "profile_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "environment": environment_evidence(),
        "input_sha256": hashlib.sha256(wanted).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module", choices=MODULES, required=True)
    parser.add_argument("--rows", type=int, default=128)
    parser.add_argument("--container-image")
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.rows <= 10000:
        parser.error("new output and 1..10000 rows required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.container_image:
        return container_sample(
            ROOT,
            Path(__file__).resolve(),
            args.source,
            args.output,
            args.container_image,
            ["--module", args.module, "--rows", str(args.rows)],
        )
    if sys.platform != "linux":
        parser.error("use isolated Linux container for comparable resources")
    result = measure(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return int(result["quality"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
