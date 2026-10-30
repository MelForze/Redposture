"""Bounded secret inspection of data already read by audit modules."""

from __future__ import annotations

import codecs
import json
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .discovery_containers import DiskContainer
from .discovery_encoded import (
    compressed_text_prefix,
    decode_disk_structured_blob,
    encoded_text_prefix,
    mime_text_prefix,
)
from .discovery_keys import disk_key_hint
from .discovery_matches import SpoolingSecretMatches
from .discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from .discovery_paths import Text, concat_discovery_text, json_discovery_path, path_suffix
from .discovery_rendering import format_discovery_finding_line
from .discovery_spool import FINDING_SPOOL_MAX_CHARS, SpoolingFindings
from .discovery_text import DiscoveryTextStream, _Value
from .discovery_values import DiskBackedText
from .json_stream import JSONPath, JSONScalarStream
from .secret_detection import (
    SecretMatch,
    _key_detector,
    fingerprint,
    is_secret_field_name,
    scan_disk_atomic_token,
    scan_value,
)

FINDING_SPOOL_THRESHOLD = 4096

DISCOVERY_MODULES = frozenset(
    {
        "kafka",
        "redis",
        "etcd",
        "consul",
        "mongodb",
        "postgres",
        "zookeeper",
        "keeper",
        "qdrant",
        "oracle",
        "kubeapi",
        "jenkins",
        "vault",
        "nomad",
        "jupyter",
        "spark",
        "yarn",
        "portainer",
        "gitlab",
        "harbor",
        "nexus",
        "docker-registry",
    }
)
_FIELDS: dict[str, tuple[str, ...]] = {
    "kafka": ("dump_results", "ui_dump_records"),
    "redis": ("key_value_entries", "query_key_entry"),
    "etcd": ("key_value_entries", "query_key_entry"),
    "consul": ("kv_dump_items",),
    "mongodb": ("documents", "query_documents"),
    "postgres": ("table_dumps",),
    "zookeeper": ("znode_values", "query_znode_dump"),
    "keeper": ("znode_values", "query_znode_dump"),
    "qdrant": ("payload_discovery_items",),
    "oracle": ("rows", "query_rows"),
    "kubeapi": ("secrets", "configmaps"),
    "jenkins": ("build_logs", "job_configs", "build_envs"),
    "vault": ("kv_dump_items",),
    "nomad": ("job_specs",),
    "jupyter": ("notebook_contents",),
    "spark": ("spark_metadata",),
    "yarn": ("app_specs",),
    "portainer": ("portainer_metadata",),
}
_INCOMPLETE_SOURCE_FIELDS: dict[str, tuple[str, ...]] = {
    "kafka": (
        "dump_partial",
        "dump_error",
        "dump_errors",
        "topic_read_error",
        "ui_dump_partial",
        "ui_dump_limit_reduced",
        "ui_discovery_budget_reason",
    ),
    "redis": ("dump_partial", "dump_error", "keys_truncated"),
    "etcd": ("dump_partial", "dump_error", "keys_truncated"),
    "consul": ("kv_dump_error",),
    "mongodb": ("dump_partial", "dump_error", "dump_errors", "collections_truncated"),
    "postgres": ("dump_partial", "dump_error", "dump_errors", "tables_truncated"),
    "zookeeper": ("dump_partial", "dump_error", "znodes_truncated", "query_znode_dump_error"),
    "keeper": ("dump_partial", "dump_error", "znodes_truncated", "query_znode_dump_error"),
    "qdrant": ("payload_discovery_partial", "payload_discovery_errors", "collection_dump_error"),
    "oracle": ("dump_partial", "dump_error", "tables_truncated", "discover_partial"),
    "kubeapi": ("secrets_partial", "secrets_error", "configmaps_partial", "configmaps_error"),
    "jenkins": ("job_discovery_partial",),
    "vault": ("kv_discovery_partial",),
    "nomad": ("job_discovery_partial",),
    "jupyter": ("content_discovery_partial", "contents_partial", "contents_error"),
    "spark": ("content_discovery_partial",),
    "yarn": ("app_discovery_partial",),
    "portainer": ("content_discovery_partial",),
}
_MAX_BYTES = UNLIMITED_DISCOVER_BYTES
_MAX_SECONDS = DEFAULT_DISCOVER_TIME


def discovery_fields(module: str) -> tuple[str, ...]:
    return _FIELDS.get(module, ())


def prepare_discovery_request(args: Any) -> None:
    """Ask existing read-only inventory paths for content when discovery is set."""
    if not bool(getattr(args, "discover", False)):
        return
    module = str(getattr(args, "command", "") or "")
    if module not in DISCOVERY_MODULES:
        return
    args._discover_implicit_dump = False
    args._discover_implicit_secrets = False
    args._discover_implicit_builds = False
    args._discover_implicit_show_keys = False
    if module in {"kafka", "redis", "etcd", "consul", "mongodb", "postgres", "zookeeper", "keeper", "qdrant", "oracle"}:
        if not getattr(args, "dump", False) and not (module == "etcd" and getattr(args, "key", None)):
            args._discover_implicit_dump = True
            args.dump = 200 if module == "oracle" else True
            if module == "consul" and not bool(getattr(args, "show_keys", False)):
                # Consul's unscoped --dump also reads services, agents, checks
                # and nodes. Scope an implicit discovery dump to KV only.
                args.show_keys = True
                args._discover_implicit_show_keys = True
    if module == "kubeapi":
        args._discover_implicit_secrets = not bool(getattr(args, "secrets", False))
        args.secrets = True
    elif module == "jenkins":
        args._discover_implicit_builds = not bool(getattr(args, "show_builds", False))
        args.show_builds = getattr(args, "show_builds", None) or 10


_IMPLICIT_DUMP_FIELDS: dict[str, tuple[str, ...]] = {
    "kafka": (
        "dump_results",
        "dump_topics",
        "dump_errors",
        "dump_error",
        "dump_coverage",
        "ui_dump_records",
        "ui_dump_skipped_topics",
        "ui_dump_limit_reduced",
    ),
    "redis": ("key_value_entries", "key_values"),
    "etcd": ("key_value_entries", "key_value_entries_by_api", "key_values"),
    "consul": ("kv_dump_items", "kv_dump_error"),
    "mongodb": ("documents", "dump_safety_limit"),
    "postgres": ("table_dumps", "dump_row_limit"),
    "zookeeper": ("znode_values", "znode_dump_items", "dump_error", "dump_ms"),
    "keeper": ("znode_values", "znode_dump_items", "dump_error", "dump_ms"),
    "qdrant": ("collection_dump_items", "collection_dump_error", "payload_discovery_items"),
    "oracle": ("rows",),
}


def project_discovery_output(args: Any, record: Mapping[str, Any]) -> dict[str, Any]:
    """Hide inventory requested only as input to a bare ``--discover`` scan.

    The scanner inspects the full record first. This projection is used both by
    live TXT phases and by final TXT/JSON output; explicitly requested inventory
    and targeted queries remain visible.
    """
    payload = dict(record)
    module = str(getattr(args, "command", "") or "")
    if module not in DISCOVERY_MODULES or not bool(getattr(args, "discover", False)):
        return payload
    if (
        module == "consul"
        and bool(getattr(args, "dump", False))
        and not any(
            (
                getattr(args, "show_keys", False),
                getattr(args, "kv_key", None),
                getattr(args, "dump_all_requested", False),
            )
        )
    ):
        # A service/agent-specific --dump still lets --discover read KV, but
        # that additional source was not requested as raw inventory output.
        payload.pop("kv_dump_items", None)
        payload.pop("kv_dump_error", None)
    for field in {
        "vault": ("kv_dump_items",),
        "nomad": ("job_specs",),
        "jupyter": ("notebook_contents",),
        "spark": ("spark_metadata",),
        "yarn": ("app_specs",),
        "portainer": ("portainer_metadata",),
    }.get(module, ()):
        payload.pop(field, None)

    if bool(getattr(args, "_discover_implicit_dump", False)):
        if (
            module == "consul"
            and bool(getattr(args, "show_keys", False))
            and not bool(getattr(args, "_discover_implicit_show_keys", False))
        ):
            # Explicit --keys should still render its key list even though the
            # implicit dump path fetched values instead of a separate list.
            values = payload.get("kv_dump_items")
            if payload.get("kv_keys_list") is None and isinstance(values, list):
                payload["kv_keys_list"] = [
                    str(item["key"]) for item in values if isinstance(item, Mapping) and item.get("key")
                ]
        for field in _IMPLICIT_DUMP_FIELDS.get(module, ()):
            payload.pop(field, None)
        for flag in ("dump", "dump_keys", "dump_documents", "dump_requested", "table_dump_enabled"):
            if flag in payload:
                payload[flag] = False
        if module == "consul":
            payload["dump_all_requested"] = False
            if bool(getattr(args, "_discover_implicit_show_keys", False)):
                payload["keys_requested"] = False
        if module == "kafka" and not bool(getattr(args, "show_topics", False)):
            payload.pop("topics", None)
            payload.pop("ui_topics", None)
        if module in {"redis", "etcd"} and not bool(getattr(args, "show_keys", False)):
            payload.pop("keys", None)
        if module == "consul" and not bool(getattr(args, "show_keys", False)):
            payload.pop("kv_keys_list", None)
        if module in {"zookeeper", "keeper"} and not bool(getattr(args, "show_znodes", False)):
            payload.pop("znodes", None)
            payload.pop("znode_details", None)
        if module == "qdrant" and not bool(getattr(args, "show_collections", False)):
            payload.pop("collections", None)
        if module == "mongodb" and not any(
            (getattr(args, "show_collections", False), getattr(args, "collections", None))
        ):
            payload.pop("collections", None)
        if module == "postgres":
            if not bool(getattr(args, "show_tables", False)):
                payload.pop("table_names", None)
            if not any(
                (getattr(args, "show_tables", False), getattr(args, "rows", False), getattr(args, "tables", None))
            ):
                # The implicit dump walks tables and also computes row counts;
                # the latter have their own formatter and would leak a raw
                # "Table Rows" section even after table_dumps is removed.
                payload.pop("table_row_counts", None)
                payload.pop("table_targets", None)
                payload["show_row_counts"] = False
        if module == "oracle" and not bool(getattr(args, "show_tables", False)):
            payload.pop("tables", None)

    if bool(getattr(args, "_discover_implicit_secrets", False)):
        payload.pop("secrets", None)
        payload["show_secrets"] = False
    # ConfigMaps, job configs, logs and injected env are read for the secret
    # scanner only; none has an independent raw-output CLI switch.
    for field in ("configmaps", "payload_discovery_items", "job_configs", "build_logs", "build_envs"):
        payload.pop(field, None)
    if bool(getattr(args, "_discover_implicit_builds", False)):
        payload.pop("builds", None)
        payload["builds_requested"] = False
        if not bool(getattr(args, "show_jobs", False)):
            payload.pop("jobs", None)
            payload["jobs_requested"] = False
    return payload


def _items(module: str, record: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    for field in _FIELDS.get(module, ()):
        value = record.get(field)
        if value is None:
            continue
        if field in {"key_value_entries", "kv_dump_items"} and isinstance(value, list):
            for entry in value:
                if isinstance(entry, Mapping):
                    if entry.get("error"):
                        continue
                    key = str(entry.get("key") or "?")
                    yield f"{field}.{key}", {key.rsplit("/", 1)[-1]: entry.get("value")}
            continue
        if field == "query_key_entry" and isinstance(value, Mapping):
            if value.get("error"):
                continue
            key = str(value.get("key") or "?")
            yield f"query_key.{key}", {key.rsplit("/", 1)[-1]: value.get("value")}
            continue
        if field == "table_dumps" and isinstance(value, list):
            for table in value:
                if isinstance(table, Mapping):
                    yield f"table.{table.get('database')}.{table.get('table')}", table.get("rows")
            continue
        if field in {"documents", "query_documents"} and isinstance(value, list):
            for doc in value:
                if isinstance(doc, Mapping):
                    yield f"{doc.get('database')}.{doc.get('collection')}", doc.get("document")
            continue
        if field in {"secrets", "configmaps"} and isinstance(value, list):
            for secret in value:
                if isinstance(secret, Mapping):
                    data = secret.get("data")
                    if field == "configmaps" and secret.get("name") == "kube-root-ca.crt" and isinstance(data, Mapping):
                        # Kubernetes injects this public CA bundle into each
                        # namespace. It is not a secret; retain other keys if
                        # somebody added data to the same ConfigMap.
                        data = {key: item for key, item in data.items() if key != "ca.crt"}
                    if data:
                        yield f"{field}.{secret.get('namespace')}.{secret.get('name')}", data
            continue
        if field == "payload_discovery_items" and isinstance(value, list):
            for collection in value:
                if isinstance(collection, Mapping):
                    yield f"collection.{collection.get('collection')}", collection.get("points")
            continue
        if field == "dump_results" and isinstance(value, Mapping):
            for topic, messages in value.items():
                yield f"topic.{topic}", messages
            continue
        if field == "ui_dump_records" and isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    yield f"cluster.{item.get('cluster')}.topic.{item.get('topic')}", item.get("messages")
            continue
        if module == "oracle" and field == "rows" and isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    yield f"table.{item.get('schema')}.{item.get('table')}", item.get("row")
            continue
        if module == "jenkins" and field in {"build_logs", "job_configs", "build_envs"} and isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    job = str(item.get("job") or "?")
                    build = item.get("build")
                    path = f"job.{job}" + (f".build.{build}" if build is not None else "")
                    source_key = {"build_logs": "log", "job_configs": "config", "build_envs": "env"}[field]
                    yield f"{path}.{source_key}", item.get(source_key)
            continue
        if field == "znode_values" and isinstance(value, list):
            structured = record.get("znode_dump_items")
            if isinstance(structured, list):
                for item in structured:
                    if isinstance(item, Mapping) and isinstance(item.get("path"), str) and not item.get("error"):
                        path = item["path"]
                        yield f"znode.{path}", {path.rsplit("/", 1)[-1]: item.get("value")}
                continue
            for item in value:
                if isinstance(item, str) and ":" in item:
                    path, content = item.split(":", 1)
                    if content.startswith(("<error:", "<not found>", "<Access Denied>", "<NoAuth>")):
                        continue
                    yield f"znode.{path}", {path.rsplit("/", 1)[-1]: content}
            continue
        if field == "query_znode_dump" and isinstance(value, str):
            if record.get("query_znode_dump_error"):
                continue
            path = str(record.get("query_znode") or "?")
            yield f"znode.{path}", {path.rsplit("/", 1)[-1]: value}
            continue
        yield field, value


def _minimum_json_size(value: Any, limit: int) -> int:
    """Cheap lower bound that rejects large strings before JSON copies them."""
    pending = [value]
    visited: set[int] = set()
    size = 0
    while pending and size <= limit:
        item = pending.pop()
        if isinstance(item, (str, bytes)):
            size += len(item) + 2
        elif isinstance(item, (DiskBackedText, DiskContainer)):
            return limit + 1
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in visited:
                continue
            visited.add(id(item))
            size += 2
            if isinstance(item, dict):
                for key, child in item.items():
                    if isinstance(key, DiskBackedText):
                        return limit + 1
                    size += len(key) + 3 if isinstance(key, str) else 1
                    pending.append(child)
                    if size > limit:
                        return size
            else:
                # Do not duplicate a huge container merely to reject it.
                size += max(0, len(item) - 1)
                if size > limit:
                    return size
                pending.extend(item)
        else:
            size += 1
    return size


def _bounded_json_size(value: Any, limit: int) -> int | None:
    if _minimum_json_size(value, limit) > limit:
        return None
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, default=str).iterencode(value):
        if len(chunk) > limit - size:
            return None
        size += len(chunk.encode("utf-8"))
        if size > limit:
            return None
    return size


def _text_prefix(value: str | bytes) -> str:
    for position in range(0, len(value), 65_536):
        part = value[position : position + 65_536].lstrip()
        if part:
            prefix = part[:4096]
            return prefix.decode("utf-8", errors="replace") if isinstance(prefix, bytes) else prefix
    return ""


def _json_container_prefix(value: str | bytes) -> bool:
    """Distinguish a possible JSON container from plain labels such as [INFO]."""
    prefix = _text_prefix(value)
    if not prefix or prefix[0] not in "{[":
        return False
    tail = prefix[1:].lstrip()
    if not tail:
        return True  # Keep genuinely incomplete JSON subject to validation.
    if prefix[0] == "{":
        return tail[0] in '"}'
    if tail[0] in '"]{[':
        return True
    if tail[0] in "-0123456789":
        number = re.match(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", tail)
        if number is None:
            return tail == "-"  # A split negative JSON number is still possible.
        remainder = tail[number.end() :].lstrip()
        return not remainder or remainder[0] in ",]" or remainder in {".", "e", "E", "e+", "e-", "E+", "E-"}
    for literal in ("true", "false", "null"):
        if literal.startswith(tail):
            return True
        if tail.startswith(literal) and (len(tail) == len(literal) or tail[len(literal)] in " \t\r\n,]"):
            return True
    return False


def _scan_disk_json(
    value: DiskBackedText, path: str, portion_bytes: int, decode_depth: int, deadline: float | None = None
) -> tuple[list[Any], bool]:
    matches = SpoolingSecretMatches()
    covered = True
    scalar: _Value | None = None

    def visit(parts: JSONPath, value: Any) -> None:
        nonlocal covered
        named = bool(parts) and isinstance(parts[-1], (str, DiskBackedText))
        parent = parts[:-1] if named else parts
        location = json_discovery_path(parent, path)
        found, _size, complete = _scan_portioned_value(
            {parts[-1]: value} if named else value,
            location,
            portion_bytes,
            _decode_depth=decode_depth,
            _deadline=deadline,
        )
        matches.extend(found)
        covered &= complete
        if reason := getattr(found, "incomplete_reason", None):
            matches.incomplete_reason = reason

    def text(parts: JSONPath, chunk: str, final: bool) -> None:
        nonlocal scalar
        if scalar is None:
            scalar = _Value(portion_bytes)
        scalar.append(chunk)
        if final:
            completed = scalar.finish()
            scalar = None
            visit(parts, completed)

    decoder = JSONScalarStream(text, on_primitive=lambda item: visit(*item), deadline=deadline)
    try:
        for chunk in value.iter_text_chunks():
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("discover_time")
            decoder.feed(chunk.encode("utf-8"))
        decoder.finish()
    except TimeoutError:
        matches.incomplete_reason = "discover_time"
        covered = False
    except OSError:
        matches.incomplete_reason = "storage_failure"
        covered = False
    except (ValueError, UnicodeError):
        matches.incomplete_reason = "invalid_json"
        covered = False
    finally:
        decoder.close()
        if scalar is not None:
            scalar.close()
    return matches, covered


def _small_encoded_blob(value: Any) -> bool:
    if isinstance(value, (str, bytes)):
        return compressed_text_prefix(value) or mime_text_prefix(value) or _json_container_prefix(value)
    if isinstance(value, Mapping):
        return any(_small_encoded_blob(child) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_small_encoded_blob(child) for child in value)
    return False


def _scan_decoded_text(
    value: DiskBackedText, path: str, portion_bytes: int, decode_depth: int, deadline: float | None = None
) -> tuple[list[Any], bool]:
    for chunk in value.iter_text_chunks(max_chars=4096):
        prefix = chunk.lstrip()
        if prefix:
            if prefix.startswith(("{", "[")):
                return _scan_disk_json(value, path, portion_bytes, decode_depth, deadline)
            break
    return _scan_text_chunks(value.iter_text_chunks(), path, portion_bytes, decode_depth, deadline)


def _scan_text_chunks(
    chunks: Iterable[str], path: str, portion_bytes: int, decode_depth: int = 0, deadline: float | None = None
) -> tuple[list[Any], bool]:
    matches = SpoolingSecretMatches()
    covered = True

    def incomplete(_reason: str) -> None:
        nonlocal covered
        covered = False

    def emit(item: Any) -> None:
        nonlocal covered
        if isinstance(item, SecretMatch):
            matches.append(SecretMatch(item.detector, item.confidence, path, item.value))
        elif isinstance(item, DiskBackedText):
            if item.obvious_placeholder or (
                item.uniform and next(item.iter_text_chunks(max_chars=1), "") not in {"{", "["}
            ):
                return
            found = scan_disk_atomic_token(item, object_path=path)
            # A completed disk-backed neutral scalar is fully inspected even
            # when it is neither a token nor a structured encoding.
            complete = True
            if not found:
                decoded = decode_disk_structured_blob(item, layers=max(0, 2 - decode_depth), deadline=deadline)
                if decoded is not None:
                    try:
                        found, complete = _scan_decoded_text(
                            decoded.text, path, portion_bytes, decode_depth + decoded.layers, deadline
                        )
                    finally:
                        decoded.text.close()
            matches.extend(found)
            covered &= complete
        elif isinstance(item, Mapping) and any(isinstance(child, DiskBackedText) for child in item.values()):
            found, _size, complete = _scan_portioned_value(
                item, path, portion_bytes, _decode_depth=decode_depth, _deadline=deadline
            )
            matches.extend(found)
            covered &= complete
        else:
            matches.extend(scan_value(item, object_path=path))

    scanner = DiscoveryTextStream(emit, incomplete, portion=portion_bytes)
    try:
        for chunk in chunks:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("discover_time")
            scanner.feed(chunk)
        scanner.finish()
    except OSError:
        matches.incomplete_reason = "storage_failure"
        covered = False
    except TimeoutError:
        covered = False
    finally:
        scanner.close()
    return matches, covered


def _scan_disk_mapping_key(
    key: DiskBackedText,
    child: Any,
    path: str,
    portion: int,
    decode_depth: int,
    deadline: float | None,
) -> tuple[list[Any], int, bool]:
    matches = SpoolingSecretMatches()
    inspected = key.byte_length
    try:
        hint = disk_key_hint(key, deadline)
        nested, size, covered = _scan_portioned_value(
            {hint: child}, "$", portion, _decode_depth=decode_depth, _deadline=deadline
        )
        inspected += size
        for match in nested:
            full_path = concat_discovery_text(path, ".", key, path_suffix(match.object_path, f"$.{hint}"))
            value = match.value
            if not isinstance(value, DiskBackedText):
                disk = DiskBackedText()
                try:
                    for offset in range(0, len(value), 65536):
                        disk.append_text(value[offset : offset + 65536])
                    disk.finish()
                except BaseException:
                    disk.close()
                    raise
                value = disk
            matches.append(SecretMatch(match.detector, match.confidence, full_path, value))
        if reason := getattr(nested, "incomplete_reason", None):
            matches.incomplete_reason = reason
        return matches, inspected, covered
    except TimeoutError:
        matches.incomplete_reason = "discover_time"
    except OSError:
        matches.incomplete_reason = "storage_failure"
    return matches, inspected, False


def _scan_portioned_value(
    value: Any, path: Text, portion_bytes: int, *, _decode_depth: int = 0, _deadline: float | None = None
) -> tuple[list[Any], int, bool]:
    """Scan a materialized record without treating its size as a total quota.

    Source readers still own network bounds. Here each bounded part is scanned
    and released before visiting the next part of a large record. Recognized
    continuous tokens and secret fields use disk-backed validation; unknown
    long grammars remain incomplete instead of being guessed from their size.
    """
    # This bounds local regex/JSON allocations, not how much source data is
    # inspected. Larger values continue through the streaming text reader.
    portion_bytes = max(1, min(portion_bytes, 65_536))
    if isinstance(path, DiskBackedText):
        nested, size, covered = _scan_portioned_value(
            value, "$", portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
        )
        matches = SpoolingSecretMatches()
        for match in nested:
            retained = match.value
            if not isinstance(retained, DiskBackedText):
                retained = DiskBackedText()
                try:
                    retained.append_text(match.value)
                    retained.finish()
                except BaseException:
                    retained.close()
                    raise
            matches.append(
                SecretMatch(
                    match.detector,
                    match.confidence,
                    concat_discovery_text(path, path_suffix(match.object_path, "$")),
                    retained,
                )
            )
        matches.incomplete_reason = getattr(nested, "incomplete_reason", None)
        return matches, size, covered
    if isinstance(value, SecretMatch):
        size = value.value.byte_length if isinstance(value.value, DiskBackedText) else len(value.value.encode("utf-8"))
        return [SecretMatch(value.detector, value.confidence, path, value.value)], size, True
    if _deadline is not None and time.monotonic() >= _deadline:
        # A small plain prefix may have arrived in the response that reported
        # the timeout. Keep its finished findings, but do not start expansion
        # or a new large scan after the target deadline.
        try:
            received_size = _bounded_json_size(value, portion_bytes)
        except (TypeError, ValueError):
            received_size = None
        if received_size is not None and not _small_encoded_blob(value):
            return scan_value(value, object_path=path), received_size, False
        return [], 0, False
    if isinstance(value, DiskBackedText):
        key = path.rsplit(".", 1)[-1]
        if value.obvious_placeholder:
            return [], value.byte_length, True
        prefix = next(value.iter_text_chunks(max_chars=4096), "").lstrip()
        if _json_container_prefix(prefix):
            json_matches, covered = _scan_disk_json(value, path, portion_bytes, _decode_depth, _deadline)
            return json_matches, value.byte_length, covered
        try:
            decoded = decode_disk_structured_blob(value, layers=max(0, 2 - _decode_depth), deadline=_deadline)
        except TimeoutError:
            return [], value.byte_length, False
        if decoded is not None and not decoded.structured and is_secret_field_name(key):
            # An opaque password can happen to be printable base64. Keep its
            # actual stored value unless the decoded payload has structure.
            decoded.text.close()
            decoded = None
        if decoded is not None:
            try:
                decoded_matches, covered = _scan_decoded_text(
                    decoded.text, path, portion_bytes, _decode_depth + decoded.layers, _deadline
                )
                return decoded_matches, value.byte_length, covered
            finally:
                decoded.text.close()
        if compressed_text_prefix(prefix):
            return [], value.byte_length, False
        if is_secret_field_name(key) and value.byte_length >= 4:
            return [SecretMatch(_key_detector(key), "high", path, value)], value.byte_length, True
        if value.uniform and next(value.iter_text_chunks(max_chars=1), "") not in {"{", "["}:
            return [], value.byte_length, True
        atomic_matches = scan_disk_atomic_token(value, object_path=path)
        if atomic_matches:
            return atomic_matches, value.byte_length, True
        text_matches, covered = _scan_text_chunks(
            value.iter_text_chunks(), path, portion_bytes, _decode_depth, _deadline
        )
        return text_matches, value.byte_length, covered
    try:
        small_size = _bounded_json_size(value, portion_bytes)
    except (TypeError, ValueError):
        return [], 0, False
    compressed = _small_encoded_blob(value) if small_size is not None else False
    if small_size is not None and not compressed:
        return scan_value(value, object_path=path), small_size, True
    if isinstance(value, Mapping):
        matches = SpoolingSecretMatches()
        total = 0
        complete = True
        try:
            for raw_key, child in value.items():
                if _deadline is not None and time.monotonic() >= _deadline:
                    complete = False
                    break
                if isinstance(raw_key, DiskBackedText):
                    nested, size, covered = _scan_disk_mapping_key(
                        raw_key, child, path, portion_bytes, _decode_depth, _deadline
                    )
                    matches.extend(nested)
                    total += size
                    complete &= covered
                    if reason := getattr(nested, "incomplete_reason", None):
                        matches.incomplete_reason = reason
                    continue
                key = str(raw_key)
                # A small key/value pair needs the parent's key context for the
                # detector that recognizes secrets by field name.
                pair = {key: child}
                try:
                    pair_size = _bounded_json_size(pair, portion_bytes)
                except (TypeError, ValueError):
                    pair_size = None
                child_size = _bounded_json_size(child, portion_bytes) if isinstance(child, (str, bytes)) else None
                if (pair_size is not None or child_size is not None) and not _small_encoded_blob(child):
                    matches.extend(scan_value(pair, object_path=path))
                    total += pair_size if pair_size is not None else int(child_size or 0)
                else:
                    nested, size, covered = _scan_portioned_value(
                        child, f"{path}.{key}", portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
                    )
                    matches.extend(nested)
                    total += size
                    complete &= covered
                    if reason := getattr(nested, "incomplete_reason", None):
                        matches.incomplete_reason = reason
        except TimeoutError:
            matches.incomplete_reason = "discover_time"
            complete = False
        except OSError:
            matches.incomplete_reason = "storage_failure"
            complete = False
        return matches, total, complete
    if isinstance(value, (list, tuple, set)):
        matches = SpoolingSecretMatches()
        total = 0
        complete = True
        try:
            for index, child in enumerate(value):
                if _deadline is not None and time.monotonic() >= _deadline:
                    complete = False
                    break
                nested, size, covered = _scan_portioned_value(
                    child, f"{path}[{index}]", portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
                )
                matches.extend(nested)
                total += size
                complete &= covered
                if reason := getattr(nested, "incomplete_reason", None):
                    matches.incomplete_reason = reason
        except OSError:
            matches.incomplete_reason = "storage_failure"
            complete = False
        return matches, total, complete
    if not isinstance(value, (str, bytes)):
        return [], len(str(value).encode("utf-8", errors="replace")), True

    def text_chunks() -> Iterable[str]:
        if isinstance(value, bytes):
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            for position in range(0, len(value), 65_536):
                yield decoder.decode(value[position : position + 65_536])
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail
        else:
            for position in range(0, len(value), 65_536):
                yield value[position : position + 65_536]

    key = path.rsplit(".", 1)[-1]
    if compressed or encoded_text_prefix(value) or _json_container_prefix(value) or is_secret_field_name(key):
        disk_value = DiskBackedText()
        for chunk in text_chunks():
            if _deadline is not None and time.monotonic() >= _deadline:
                disk_value.close()
                return [], 0, False
            disk_value.append_text(chunk)
        disk_value.finish()
        found, size, covered = _scan_portioned_value(
            disk_value, path, portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
        )
        if not found:
            disk_value.close()
        return found, size, covered
    inspected = 0

    def measured_chunks() -> Iterable[str]:
        nonlocal inspected
        for chunk in text_chunks():
            inspected += len(chunk.encode("utf-8"))
            yield chunk

    text_matches, covered = _scan_text_chunks(measured_chunks(), path, portion_bytes, _decode_depth, _deadline)
    return text_matches, inspected, covered


def inspect_record(
    module: str,
    record: Mapping[str, Any],
    *,
    max_bytes: int = _MAX_BYTES,
    max_seconds: float = _MAX_SECONDS,
    started_at: float | None = None,
) -> dict[str, Any]:
    """Return full findings without re-reading the network or auth material."""
    now = time.monotonic()
    source_timed_out = started_at is not None and now - started_at >= max_seconds
    # A collector may have already returned partial data after its deadline.
    # Preserve findings from that data instead of discarding the first item.
    started = now if source_timed_out else (now if started_at is None else started_at)
    consumed = 0
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    source_present = any(record.get(field) is not None for field in _FIELDS.get(module, ()))
    partial_reasons = [key for key in _INCOMPLETE_SOURCE_FIELDS.get(module, ()) if record.get(key)]
    budget_reason = record.get("discovery_budget_reason")
    source_budget_exhausted = source_timed_out or budget_reason in {"byte_budget", "time_budget", "request_limit"}
    if source_budget_exhausted and isinstance(budget_reason, str):
        partial_reasons.append(budget_reason)
    for field in _INCOMPLETE_SOURCE_FIELDS.get(module, ()):
        error = record.get(field)
        if not isinstance(error, str):
            continue
        for segment in error.split(";"):
            reason = segment.rsplit(":", 1)[-1].strip()
            if reason in {"byte_budget", "time_budget"}:
                partial_reasons.append(reason)
                source_budget_exhausted = True
            elif module in {"zookeeper", "keeper"} and (
                reason == "discover_max_bytes" or "discovery byte budget" in reason.lower()
            ):
                partial_reasons.append("byte_budget")
                source_budget_exhausted = True
    if source_timed_out:
        partial_reasons.append("time_budget")
    if module in {"redis", "etcd"}:
        entries = record.get("key_value_entries")
        budget_reasons = {"byte_budget", "time_budget"}
        if isinstance(entries, list) and any(
            isinstance(entry, Mapping) and bool(entry.get("error")) and str(entry.get("error")) not in budget_reasons
            for entry in entries
        ):
            partial_reasons.append("key_read_error")
        query_entry = record.get("query_key_entry")
        if isinstance(query_entry, Mapping) and query_entry.get("error"):
            partial_reasons.append("key_read_error")
        if record.get("query_key") and record.get("error") and record.get("query_key_entry") is None:
            partial_reasons.append("key_read_error")
    if module == "kafka":
        ui_budget_reason = record.get("ui_discovery_budget_reason")
        if ui_budget_reason in {"byte_budget", "discover_time"}:
            partial_reasons.append("time_budget" if ui_budget_reason == "discover_time" else ui_budget_reason)
            source_budget_exhausted = True
        dump_errors = record.get("dump_errors")
        if isinstance(dump_errors, Mapping):
            for error in dump_errors.values():
                if not isinstance(error, str):
                    continue
                for reason in ("byte_budget", "discover_time"):
                    if reason in error:
                        partial_reasons.append("time_budget" if reason == "discover_time" else reason)
                        source_budget_exhausted = True
        message_cap = record.get("max_messages")
        results = record.get("dump_results")
        if (
            isinstance(message_cap, int)
            and not isinstance(message_cap, bool)
            and message_cap > 0
            and isinstance(results, Mapping)
            and any(isinstance(messages, list) and len(messages) >= message_cap for messages in results.values())
        ):
            # Reaching a client-side cap does not prove that the topic's high
            # watermark was reached; the coverage object only counts topics.
            partial_reasons.append("message_limit_reached")
    elif module == "mongodb":
        document_cap = record.get("dump_limit") or record.get("dump_safety_limit")
        documents = record.get("documents")
        if (
            isinstance(document_cap, int)
            and not isinstance(document_cap, bool)
            and document_cap > 0
            and isinstance(documents, list)
        ):
            counts = Counter(
                (doc.get("database"), doc.get("collection")) for doc in documents if isinstance(doc, Mapping)
            )
            if any(count >= document_cap for count in counts.values()):
                partial_reasons.append("document_limit_reached")
    elif module == "postgres":
        row_cap = record.get("dump_row_limit")
        tables = record.get("table_dumps")
        if (
            isinstance(row_cap, int)
            and not isinstance(row_cap, bool)
            and row_cap > 0
            and isinstance(tables, list)
            and any(
                isinstance(table, Mapping) and isinstance(table.get("rows"), list) and len(table["rows"]) >= row_cap
                for table in tables
            )
        ):
            partial_reasons.append("row_limit_reached")
    status = "partial" if partial_reasons else "complete"
    source = (
        "anonymous"
        if record.get("status") == "open_no_auth" or record.get("anonymous_access") is True
        else "authenticated"
        if record.get("provided_credentials_ok") is True
        or record.get("status") in {"valid_credentials", "weak_default_creds", "auth_valid", "open_auth"}
        else "access_unverified"
    )
    retained_value_chars = 0
    for path, value in _items(module, record):
        if time.monotonic() - started >= max_seconds:
            status = "partial"
            partial_reasons.append("time_budget")
            break
        matches, size, covered = _scan_portioned_value(value, f"$.{path}", max_bytes, _deadline=started + max_seconds)
        if not covered:
            status = "partial"
            partial_reasons.append("time_budget" if time.monotonic() - started >= max_seconds else "byte_budget")
        consumed += size
        for match in matches:
            identity = (match.detector, fingerprint(match.value))
            if not isinstance(findings, SpoolingFindings) and identity in seen:
                continue
            finding = {
                "type": match.detector,
                "confidence": match.confidence,
                "value": match.value,
                "fingerprint": identity[1],
                "object_path": match.object_path,
                "source": source,
            }
            if not isinstance(findings, SpoolingFindings) and (
                isinstance(match.value, DiskBackedText)
                or len(findings) >= FINDING_SPOOL_THRESHOLD
                or retained_value_chars + len(match.value) > FINDING_SPOOL_MAX_CHARS
            ):
                spool = SpoolingFindings()
                for previous in findings:
                    spool.add(previous)
                findings = spool
                seen.clear()
            if isinstance(findings, SpoolingFindings):
                findings.add(finding)
            else:
                seen.add(identity)
                findings.append(finding)
                retained_value_chars += len(match.value)
    if not source_present:
        if source_budget_exhausted:
            status = "partial"
        else:
            status = "unavailable"
            partial_reasons.append("no_readable_source")
    elif module == "oracle" and record.get("discover_unavailable") and status == "complete":
        status = "unavailable"
        partial_reasons.append("no_readable_table")
    elif module == "kubeapi" and status == "partial":
        # The API client returns an empty list alongside an error for a denied
        # resource. That list does not prove that the resource was read.
        requested = [field for field in _FIELDS["kubeapi"] if record.get(field) is not None]
        source_budget_error = any(
            str(record.get(f"{field}_error") or "").rsplit(":", 1)[-1].strip() in {"byte_budget", "time_budget"}
            for field in requested
        )
        if (
            requested
            and not source_budget_error
            and all(not record.get(field) and record.get(f"{field}_error") for field in requested)
        ):
            status = "unavailable"
    return {
        "status": status,
        "bytes_inspected": consumed,
        "source": source,
        "findings": findings,
        "partial_reasons": list(dict.fromkeys(partial_reasons)),
    }


def iter_discovery_finding_lines(module: str, record: Mapping[str, Any]) -> Iterable[str]:
    data = record.get("content_discovery")
    if not isinstance(data, Mapping):
        return
    findings = data.get("findings")
    if not isinstance(findings, list):
        return
    pending: Iterable[Any]
    from .discovery_spool import SpoolingFindings

    emitted_fingerprints = data.get("emitted_fingerprints")
    if isinstance(findings, SpoolingFindings):
        pending = findings.iter_unemitted()
    elif isinstance(emitted_fingerprints, list):
        emitted = {str(value) for value in emitted_fingerprints}
        pending = (
            finding
            for finding in findings
            if isinstance(finding, Mapping) and str(finding.get("fingerprint")) not in emitted
        )
    else:
        pending = () if data.get("live_emitted") else findings
    for finding in pending:
        if isinstance(finding, Mapping):
            yield format_discovery_finding_line(
                module.upper(),
                record.get("host"),
                record.get("port"),
                severity=finding.get("confidence"),
                finding_type=finding.get("type"),
                value=finding.get("value"),
                place=finding.get("object_path"),
            )


def render_discovery(module: str, record: Mapping[str, Any], *, include_findings: bool = True) -> list[str]:
    data = record.get("content_discovery")
    if not isinstance(data, Mapping):
        return []
    findings = data.get("findings")
    if not isinstance(findings, list):
        return []
    lines = list(iter_discovery_finding_lines(module, record)) if include_findings else []
    reasons = data.get("partial_reasons")
    reason_text = (
        " (reason:" + "; ".join(str(reason) for reason in reasons[:3]) + ")"
        if isinstance(reasons, list) and reasons
        else ""
    )
    lines.append(
        f"{module.upper()}\t{record.get('host') or '?'}\t{record.get('port') or 0}\t [*] Discover Secrets (status:{data.get('status')}) (findings:{len(findings)}) (source:{data.get('source')}){reason_text}"
    )
    return lines
