"""Bounded secret inspection of data already read by audit modules."""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .discovery_rendering import format_discovery_finding_line
from .secret_detection import fingerprint, mask_secret, scan_value

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
_MAX_BYTES = 50 * 1024 * 1024
_MAX_SECONDS = 300.0


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
        if not getattr(args, "dump", False):
            args._discover_implicit_dump = True
            args.dump = {"kafka": 100, "mongodb": 100, "postgres": 100, "qdrant": 20, "oracle": 200}.get(module, 1000)
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
                    key = str(entry.get("key") or "?")
                    yield f"{field}.{key}", {key.rsplit("/", 1)[-1]: entry.get("value")}
            continue
        if field == "query_key_entry" and isinstance(value, Mapping):
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
                    yield f"{field}.{secret.get('namespace')}.{secret.get('name')}", secret.get("data")
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
        if isinstance(item, str):
            size += len(item) + 2
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in visited:
                continue
            visited.add(id(item))
            size += 2
            if isinstance(item, dict):
                for key, child in item.items():
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


def inspect_record(
    module: str, record: Mapping[str, Any], *, max_bytes: int = _MAX_BYTES, max_seconds: float = _MAX_SECONDS
) -> dict[str, Any]:
    """Return masked findings without re-reading the network or auth material."""
    started = time.monotonic()
    consumed = 0
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    source_present = any(record.get(field) is not None for field in _FIELDS.get(module, ()))
    partial_reasons = [key for key in _INCOMPLETE_SOURCE_FIELDS.get(module, ()) if record.get(key)]
    if module == "kafka":
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
    for path, value in _items(module, record):
        if time.monotonic() - started >= max_seconds:
            status = "partial"
            partial_reasons.append("time_budget")
            break
        try:
            size = _bounded_json_size(value, max_bytes - consumed)
        except (TypeError, ValueError):
            status = "partial"
            partial_reasons.append("invalid_source")
            continue
        if size is None:
            status = "partial"
            partial_reasons.append("byte_budget")
            break
        consumed += size
        for match in scan_value(value, object_path=f"$.{path}"):
            identity = (match.detector, fingerprint(match.value))
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(
                {
                    "type": match.detector,
                    "confidence": match.confidence,
                    "value": mask_secret(match.value),
                    "fingerprint": identity[1],
                    "object_path": match.object_path,
                    "source": source,
                }
            )
    if not source_present:
        status = "unavailable"
        partial_reasons.append("no_readable_source")
    elif module == "kubeapi" and status == "partial":
        # The API client returns an empty list alongside an error for a denied
        # resource. That list does not prove that the resource was read.
        requested = [field for field in _FIELDS["kubeapi"] if record.get(field) is not None]
        if requested and all(not record.get(field) and record.get(f"{field}_error") for field in requested):
            status = "unavailable"
    return {
        "status": status,
        "bytes_inspected": consumed,
        "source": source,
        "findings": findings,
        "partial_reasons": list(dict.fromkeys(partial_reasons)),
    }


def render_discovery(module: str, record: Mapping[str, Any]) -> list[str]:
    data = record.get("content_discovery")
    if not isinstance(data, Mapping):
        return []
    findings = data.get("findings")
    if not isinstance(findings, list):
        return []
    lines: list[str] = []
    pending: Iterable[Any]
    emitted_fingerprints = data.get("emitted_fingerprints")
    if isinstance(emitted_fingerprints, list):
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
            lines.append(
                format_discovery_finding_line(
                    module.upper(),
                    record.get("host"),
                    record.get("port"),
                    severity=finding.get("confidence"),
                    finding_type=finding.get("type"),
                    value=finding.get("value"),
                    place=finding.get("object_path"),
                )
            )
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
