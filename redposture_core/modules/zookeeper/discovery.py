"""Disk-backed, unbounded-by-size ZooKeeper discovery traversal."""

from __future__ import annotations

import base64
import json
import tempfile
import time
from collections.abc import Mapping
from typing import Any

from ...clients.zookeeper import _ZK_ERR_NOAUTH, _ZK_ERR_NONODE, _ZK_ERR_OK, _join_znode_path
from ...discovery_bytes import SpoolBytes
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_spool import SpoolingRecords, SpoolingStrings
from ...discovery_values import DiskBackedText, iter_json_chunks
from ...storage_discovery import DiscoveryCollector


def discover_znodes(ctx: Any, prior: Mapping[str, Any], client: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    """Read each reachable node once and scan completed values before moving on."""
    payload = dict(prior)
    collector = DiscoveryCollector(str(payload.get("module") or "zookeeper"), ctx, payload)
    # Discovery has a target-wide time limit; byte limits are not a stop rule.
    collector.remaining = 2**63 - 1
    selected = str(options.get("query_znode") or "").strip()
    visited_count = 0
    show = bool(options.get("show_znodes"))
    explicit_dump = bool(options.get("dump")) and not bool(getattr(ctx.args, "_discover_implicit_dump", False))
    names = SpoolingStrings() if show else None
    dump_rows = SpoolingRecords() if explicit_dump else None
    with DiscoveryFrontier() as frontier:
        frontier.enqueue(selected or "/")
        while (path := frontier.pop()) is not None:
            if not collector.allowed():
                break
            if path != "/":
                visited_count += 1
                if names is not None:
                    names.append(path)
            source = f"znode.{path}"
            try:
                data, error, _stat = client.get_data_discovery(path, deadline=collector.deadline)
                if error == _ZK_ERR_OK:
                    collector.mark_accessible_source()
                    decoded: str | DiskBackedText | None = None
                    if data:
                        collector.bytes_read += len(data)
                        try:
                            if isinstance(data, SpoolBytes):
                                decoded = data.decode("utf-8")
                            else:
                                decoded = data.decode("utf-8")
                        except UnicodeDecodeError:
                            # Binary znodes remain readable but are not secret
                            # text. Explicit dump renders them as base64.
                            decoded = None
                        if isinstance(decoded, DiskBackedText):
                            collector.scan_disk_text(source, decoded, key=path.rsplit("/", 1)[-1])
                        elif isinstance(decoded, str):
                            collector.add(source, {path.rsplit("/", 1)[-1]: decoded}, charge=False)
                    if dump_rows is not None:
                        if data is None:
                            shown: str | DiskBackedText = "<nil>"
                        elif not data:
                            shown = "<empty>"
                        elif decoded is not None:
                            shown = decoded
                        elif isinstance(data, SpoolBytes):
                            encoded = data.base64_text()
                            shown = DiskBackedText()
                            shown.append_text("<")
                            try:
                                for chunk in encoded.iter_text_chunks():
                                    shown.append_text(chunk)
                            finally:
                                encoded.close()
                            shown.append_text(">")
                            shown.finish()
                        else:
                            shown = f"<base64:{base64.b64encode(data).decode('ascii')}>"
                        dump_rows.append({"path": path, "value": shown})
                elif error == _ZK_ERR_NOAUTH:
                    collector.partial(source, "access_denied")
                    if dump_rows is not None:
                        dump_rows.append({"path": path, "value": "<Access Denied>"})
                elif error != _ZK_ERR_NONODE:
                    collector.partial(source, f"getData:{error}")
            except (TimeoutError, ConnectionError, OSError, RuntimeError, ValueError) as exc:
                collector.partial(source, str(exc))
                if time.monotonic() >= collector.deadline or getattr(client, "sock", object()) is None:
                    break

            if selected:
                continue
            try:

                def enqueue(name: str) -> None:
                    frontier.enqueue(_join_znode_path(path, name))

                error, _stat = client.read_children_discovery(path, enqueue, deadline=collector.deadline)
                if error == _ZK_ERR_OK:
                    collector.mark_accessible_source()
                elif error == _ZK_ERR_NOAUTH:
                    collector.partial(source, "access_denied")
                elif error != _ZK_ERR_NONODE:
                    collector.partial(source, f"getChildren:{error}")
            except (TimeoutError, ConnectionError, OSError, RuntimeError, ValueError) as exc:
                collector.partial(source, str(exc))
                if time.monotonic() >= collector.deadline or getattr(client, "sock", object()) is None:
                    break

    discovery = collector.result()
    if names is not None:
        names.finish()
    if dump_rows is not None:
        dump_rows.finish()
    payload.update(
        {
            "content_discovery": discovery,
            "znode_count": visited_count if not selected else None,
            "znode_count_partial": discovery["status"] != "complete",
            "znode_count_unknown": discovery["status"] != "complete",
            "znodes_truncated": discovery["status"] != "complete",
            "znode_truncated_reason": (
                "; ".join(discovery["partial_reasons"]) if discovery["partial_reasons"] else None
            ),
            "max_znodes": None,
            "dump": bool(options.get("dump")),
            "show_znodes": bool(options.get("show_znodes")),
            "query_znode": selected or None,
        }
    )
    if names is not None or dump_rows is not None:
        payload["_stream_lines_file"] = _write_explicit_output(ctx, payload, names, dump_rows)
        payload["_zookeeper_discovery_streamed"] = True
    return payload


def _iter_display(path: str, value: object):
    yield path + ":"
    if isinstance(value, DiskBackedText):
        yield from value.iter_text_chunks()
    else:
        yield str(value)


def _write_explicit_output(
    ctx: Any,
    payload: Mapping[str, Any],
    names: SpoolingStrings | None,
    dump_rows: SpoolingRecords | None,
) -> str:
    module = str(payload.get("module") or "zookeeper")
    output_format = str(getattr(ctx.args, "output_format", "txt") or "txt")
    prefix = f"{module.upper():<12}\t{ctx.host}\t{ctx.port}\t"
    selected = str(payload.get("query_znode") or "")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", prefix="redposture-zk-discover-", suffix=".txt", delete=False
    ) as output:
        if output_format == "json":
            common = {
                "timestamp": payload.get("timestamp"),
                "service": payload.get("service") or module,
                "host": ctx.host,
                "port": ctx.port,
            }
            if names is not None:
                descriptor = {**common, "type": "znodes_list", "znode_count": payload.get("znode_count")}
                output.write(json.dumps(descriptor, ensure_ascii=False)[:-1] + ',"znodes":')
                for chunk in iter_json_chunks(names):
                    output.write(chunk)
                output.write("}\n")
            if dump_rows is not None:
                descriptor = {**common, "type": "znodes_dump", "znode_count": payload.get("znode_count")}
                output.write(json.dumps(descriptor, ensure_ascii=False)[:-1] + ',"znode_values":[')
                for ordinal, row in enumerate(dump_rows):
                    if ordinal:
                        output.write(",")
                    value = row.get("value")
                    path = str(row.get("path") or "")
                    joined = DiskBackedText()
                    for chunk in _iter_display(path, value):
                        joined.append_text(chunk)
                    joined.finish()
                    try:
                        for chunk in iter_json_chunks(joined):
                            output.write(chunk)
                    finally:
                        joined.close()
                output.write("]}\n")
        else:
            if names is not None:
                output.write(f"{prefix} [*] Znodes Enumeration (Count:{len(names)})\n")
                for path in names:
                    output.write(f"{prefix} {path}\n")
            if dump_rows is not None:
                output.write(f"{prefix} [*] {'Dump Znode ' + selected if selected else 'Dump Znodes'}\n")
                for row in dump_rows:
                    output.write(prefix + " ")
                    for chunk in _iter_display(str(row.get("path") or ""), row.get("value")):
                        output.write(chunk.replace("\n", "\\n"))
                    output.write("\n")
        return output.name
