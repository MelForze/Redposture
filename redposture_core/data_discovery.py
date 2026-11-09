"""Bounded secret inspection of data already read by audit modules."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .discovery_engine import (
    _bounded_json_size as _bounded_json_size,
)
from .discovery_engine import (
    _json_container_prefix as _json_container_prefix,
)
from .discovery_engine import (
    _minimum_json_size as _minimum_json_size,
)
from .discovery_engine import (
    _scan_decoded_text as _scan_decoded_text,
)
from .discovery_engine import (
    _scan_disk_json as _scan_disk_json,
)
from .discovery_engine import (
    _scan_disk_mapping_key as _scan_disk_mapping_key,
)
from .discovery_engine import (
    _scan_portioned_value as _scan_portioned_value,
)
from .discovery_engine import (
    _scan_small_value as _scan_small_value,
)
from .discovery_engine import (
    _scan_text_chunks as _scan_text_chunks,
)
from .discovery_engine import (
    _small_encoded_blob as _small_encoded_blob,
)
from .discovery_engine import (
    _text_prefix as _text_prefix,
)
from .discovery_occurrences import OccurrenceRegistry
from .discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from .discovery_rendering import format_discovery_finding_line
from .discovery_values import DiskBackedText
from .secret_detection import (
    fingerprint,
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
        "docker",
        "rabbitmq",
        "grafana",
        "keycloak",
    }
)
_FIELDS: dict[str, tuple[str, ...]] = {
    "docker": ("docker_metadata",),
    "rabbitmq": ("rabbitmq_metadata",),
    "grafana": ("grafana_metadata",),
    "keycloak": ("keycloak_metadata",),
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


def _source_items(module: str, record: Mapping[str, Any]) -> Iterable[tuple[str, Any, dict[str, Any]]]:
    """Attach real IDs or explicit read-order locators without guessing keys."""
    if module == "mongodb":
        for field in _FIELDS[module]:
            documents = record.get(field)
            if not isinstance(documents, list):
                continue
            for ordinal, item in enumerate(documents):
                if not isinstance(item, Mapping):
                    continue
                document = item.get("document")
                context = {
                    "source_kind": "document",
                    "object": f"{item.get('database')}.{item.get('collection')}",
                    "database": item.get("database"),
                    "collection": item.get("collection"),
                }
                if isinstance(document, Mapping) and "_id" in document:
                    identifier = document["_id"]
                    context.update(
                        id=identifier
                        if identifier is None
                        or isinstance(identifier, (str, int, float, bool, list, Mapping, DiskBackedText))
                        else str(identifier),
                        locator_kind="document_id",
                    )
                else:
                    context.update(row_ordinal=ordinal, locator_kind="read_order")
                yield str(context["object"]), document, context
        return
    if module == "postgres":
        for table in record.get("table_dumps") or ():
            if not isinstance(table, Mapping):
                continue
            rows = table.get("rows")
            if not isinstance(rows, list):
                continue
            path = f"table.{table.get('database')}.{table.get('table')}"
            keys = table.get("primary_key_columns")
            for ordinal, row in enumerate(rows):
                context = {
                    "source_kind": "table_row",
                    "object": path,
                    "database": table.get("database"),
                    "table": table.get("table"),
                    "row_ordinal": ordinal,
                    "locator_kind": "read_order",
                }
                if (
                    isinstance(keys, (list, tuple))
                    and keys
                    and isinstance(row, Mapping)
                    and all(k in row for k in keys)
                ):
                    context.update(selector={key: row[key] for key in keys}, locator_kind="primary_key")
                yield f"{path}[{ordinal}]", row, context
        return
    for path, value in _items(module, record):
        yield path, value, {"source_kind": "content", "object": path}


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
    registry: OccurrenceRegistry | None = None
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

    storage_failed = False
    for path, value, location in _source_items(module, record):
        if time.monotonic() - started >= max_seconds:
            status = "partial"
            partial_reasons.append("time_budget")
            break
        matches, size, covered = _scan_portioned_value(value, f"$.{path}", max_bytes, _deadline=started + max_seconds)
        if not covered:
            status = "partial"
            partial_reasons.append(
                "time_budget"
                if time.monotonic() - started >= max_seconds
                else getattr(matches, "incomplete_reason", None) or "byte_budget"
            )
        consumed += size
        for match in matches:
            identity = (match.detector, fingerprint(match.value))
            finding = {
                "type": match.detector,
                "confidence": match.confidence,
                "detectors": list(match.rule_ids),
                "value": match.value,
                "fingerprint": identity[1],
                "object_path": match.object_path,
                "source": source,
            }
            try:
                if registry is None:
                    # Matches are already completed and retained by the scan.
                    # Deadline expiry must stop new inspection, not discard
                    # its finished prefix during final result publication.
                    registry = OccurrenceRegistry()
                    findings = registry
                registry.add(
                    finding,
                    location={**location, "source": source, "object_path": match.object_path},
                    identity=("value", identity[1]),
                )
            except TimeoutError:
                storage_failed = True
                status = "partial"
                partial_reasons.append("time_budget")
                break
            except OSError:
                storage_failed = True
                status = "partial"
                partial_reasons.append("storage_failure")
                break
        if storage_failed:
            break
    if registry is not None:
        registry.finish()
        findings = registry.bounded_inline_view(max_findings=FINDING_SPOOL_THRESHOLD)
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
