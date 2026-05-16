"""MongoDB audit stage."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from typing import Any

from .clients.mongodb import (
    MongoAuditClient,
    close_quietly,
    is_auth_error,
    json_safe,
    non_system_databases,
    normalize_mongodb_error,
    open_mongodb_client,
)
from .console import Console
from .logger import AttemptLogger
from .rendering import CountColorRule, render_colored_marker_line
from .stage_runtime import (
    StageTelemetryBuilder,
    TwoPassAuditRunner,
    merge_stage_records,
    progress_total_from_groups,
    should_use_global_progress,
    start_audit_progress,
    start_command_progress,
)
from .utils import (
    collect_scan_ports,
    collect_scan_targets,
    filter_open_tcp_hosts_for_credential_file,
    parse_username_password_credential_file,
    utc_now_iso,
)

_MONGODB_TAG = "MONGODB"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_MONGODB_DEEP_STATUSES = {"open_no_auth", "valid_credentials", "weak_default_creds"}
_MONGODB_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("root", "root"),
    ("admin", "admin"),
    ("root", "password"),
    ("mongo", "mongo"),
    ("mongodb", "mongodb"),
)
_MONGODB_DUMP_SAFETY_LIMIT = 1000


def _clip(text: str, width: int = 96) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _is_timeout_error(value: Any) -> bool:
    text = str(value or "").lower()
    return "timeout" in text or "timed out" in text


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").lower()
    return "connection refused" in text


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and (
        _is_timeout_error(record.get("error")) or _is_connection_refused_error(record.get("error"))
    )


def _credential_runs(
    username: str | None,
    password: str | None,
    *,
    defcreds: bool,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()
    if username is not None or password is not None:
        pair = (username, password)
        runs.append({"username": username, "password": password, "default": False})
        seen.add(pair)
    if defcreds:
        for user, secret in _MONGODB_DEFAULT_CREDS:
            pair = (user, secret)
            if pair in seen:
                continue
            runs.append({"username": user, "password": secret, "default": True})
            seen.add(pair)
    return runs


def _parse_json_object(raw: str | None, *, field_name: str) -> tuple[dict[str, Any] | None, str | None]:
    if raw is None:
        return None, None
    text = str(raw).strip()
    if not text:
        return {}, None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"{field_name} must be valid JSON object: {exc.msg}"
    if not isinstance(value, dict):
        return None, f"{field_name} must be a JSON object"
    return value, None


def _parse_document_selector(raw: str | None) -> tuple[Any | None, Any | None, str | None]:
    if raw is None:
        return None, None, None
    text = str(raw).strip()
    if not text:
        return None, None, "--document must not be empty"
    if len(text) == 24 and all(char in "0123456789abcdefABCDEF" for char in text):
        try:
            from bson import ObjectId  # type: ignore[import-not-found]

            value = ObjectId(text)
            return value, json_safe(value), None
        except Exception:
            return text, text, None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text, text, None
    if isinstance(value, (dict, list)):
        return None, None, "--document must be a scalar _id value"
    return value, json_safe(value), None


def _split_csv_values(raw_values: list[str] | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values or []:
        for part in str(raw_value).split(","):
            item = part.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            result.append(item)
    return result


def _group_collection_targets(
    raw_targets: list[str],
    selected_database: str | None,
) -> tuple[list[str], dict[str | None, list[str]], str | None]:
    grouped: dict[str | None, list[str]] = {}
    normalized: list[str] = []
    for raw in raw_targets:
        value = str(raw or "").strip()
        if not value:
            continue
        if "." in value:
            database, collection = value.split(".", 1)
            database = database.strip()
            collection = collection.strip()
            if not database or not collection:
                return [], {}, f"invalid --collection target: {value}"
            grouped.setdefault(database, []).append(collection)
            normalized.append(value)
        else:
            grouped.setdefault(selected_database, []).append(value)
            normalized.append(value)
    return normalized, grouped, None


def _open_client(
    host: str,
    port: int,
    timeout: float,
    *,
    username: str | None,
    password: str | None,
    auth_db: str,
) -> MongoAuditClient:
    raw_client = open_mongodb_client(
        host,
        port,
        username=username,
        password=password,
        auth_db=auth_db,
        timeout=timeout,
    )
    return MongoAuditClient(raw_client)


def _try_list_databases(client: MongoAuditClient) -> tuple[list[str] | None, str | None]:
    try:
        return client.list_database_names(), None
    except Exception as exc:
        if is_auth_error(exc):
            return None, "authentication required"
        return None, normalize_mongodb_error(exc)


def _try_credentials(
    host: str,
    port: int,
    timeout: float,
    *,
    auth_db: str,
    credential_candidates: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for candidate in credential_candidates:
        username = candidate.get("username")
        password = candidate.get("password")
        raw_client: Any = None
        try:
            mongo = _open_client(
                host,
                port,
                timeout,
                username=str(username or ""),
                password=None if password is None else str(password),
                auth_db=auth_db,
            )
            raw_client = mongo.client
            mongo.hello()
            mongo.list_database_names()
            attempt = {
                "username": username,
                "password": password,
                "ok": True,
                "default": bool(candidate.get("default")),
                "error": None,
            }
            attempts.append(attempt)
            return attempt, attempts
        except Exception as exc:
            attempts.append(
                {
                    "username": username,
                    "password": password,
                    "ok": False,
                    "default": bool(candidate.get("default")),
                    "error": normalize_mongodb_error(exc),
                }
            )
        finally:
            close_quietly(raw_client)
    return None, attempts


def _selected_databases(
    database_names: list[str] | None,
    selected_database: str | None,
    needs_collection_walk: bool,
) -> list[str]:
    if selected_database:
        return [selected_database]
    if needs_collection_walk and database_names:
        return non_system_databases(database_names) or list(database_names)
    return []


def _collect_mongodb_data(
    client: MongoAuditClient,
    *,
    database_names: list[str] | None,
    selected_database: str | None,
    collection_targets: list[str],
    collection_targets_by_database: dict[str | None, list[str]],
    show_databases: bool,
    show_collections: bool,
    show_indexes: bool,
    dump_documents: bool,
    dump_limit: int | None,
    query_filter: dict[str, Any] | None,
    projection: dict[str, Any] | None,
    index_filter: str | None = None,
    nosql_command: dict[str, Any] | None = None,
) -> dict[str, Any]:
    query_requested = query_filter is not None
    command_database = selected_database or "admin"
    needs_collection_walk = bool(show_collections or show_indexes or index_filter or dump_documents or query_requested)
    databases_for_walk = _selected_databases(database_names, selected_database, needs_collection_walk)
    collection_rows: list[dict[str, Any]] = []
    index_rows: list[dict[str, Any]] = []
    document_rows: list[dict[str, Any]] = []
    query_rows: list[dict[str, Any]] = []
    query_error: str | None = None
    nosql_command_result: dict[str, Any] | None = None
    nosql_command_error: str | None = None
    capabilities: dict[str, bool | None] = {
        "can_list_databases": database_names is not None,
        "can_list_collections": None,
        "can_read_documents": None,
        "can_list_indexes": None,
        "can_run_command": None,
    }

    target_map: dict[str, list[str] | None] = {}
    if collection_targets_by_database:
        for db_name, values in collection_targets_by_database.items():
            effective_db = db_name or selected_database
            if effective_db:
                target_map.setdefault(effective_db, [])
                for value in values:
                    if value not in target_map[effective_db]:  # type: ignore[operator]
                        target_map[effective_db].append(value)  # type: ignore[union-attr]
        if None in collection_targets_by_database and not selected_database:
            for db_name in databases_for_walk:
                target_map.setdefault(db_name, [])
                for value in collection_targets_by_database.get(None, []):
                    if value not in target_map[db_name]:  # type: ignore[operator]
                        target_map[db_name].append(value)  # type: ignore[union-attr]
    elif databases_for_walk:
        for db_name in databases_for_walk:
            target_map[db_name] = None

    for db_name, explicit_collections in target_map.items():
        try:
            collections = (
                list(explicit_collections)
                if explicit_collections is not None
                else client.list_collection_names(db_name)
            )
            capabilities["can_list_collections"] = True
        except Exception as exc:
            capabilities["can_list_collections"] = False
            query_error = query_error or normalize_mongodb_error(exc)
            continue

        for collection_name in collections:
            count = client.count_documents(db_name, collection_name)
            collection_rows.append({"database": db_name, "collection": collection_name, "documents": count})
            if count is not None:
                capabilities["can_read_documents"] = True

            if show_indexes or index_filter:
                try:
                    indexes = client.list_indexes(db_name, collection_name)
                    capabilities["can_list_indexes"] = True
                    for item in indexes:
                        if index_filter and str(item.get("name") or "") != index_filter:
                            continue
                        index_rows.append({"database": db_name, "collection": collection_name, "index": item})
                except Exception as exc:
                    capabilities["can_list_indexes"] = False
                    query_error = query_error or normalize_mongodb_error(exc)

            if dump_documents or query_requested:
                limit = dump_limit if dump_limit is not None else _MONGODB_DUMP_SAFETY_LIMIT
                try:
                    docs = client.find_documents(
                        db_name,
                        collection_name,
                        query=query_filter or {},
                        projection=projection,
                        limit=limit,
                    )
                    capabilities["can_read_documents"] = True
                    target = query_rows if query_requested else document_rows
                    for doc in docs:
                        target.append({"database": db_name, "collection": collection_name, "document": doc})
                except Exception as exc:
                    capabilities["can_read_documents"] = False
                    query_error = query_error or normalize_mongodb_error(exc)

    if nosql_command is not None:
        try:
            nosql_command_result = client.run_command(command_database, nosql_command)
            capabilities["can_run_command"] = True
        except Exception as exc:
            capabilities["can_run_command"] = False
            nosql_command_error = normalize_mongodb_error(exc)

    return {
        "database_names": database_names if show_databases else None,
        "database_count": len(database_names) if isinstance(database_names, list) else None,
        "collections": collection_rows
        if (show_collections or collection_targets or dump_documents or query_requested)
        else [],
        "indexes": index_rows if (show_indexes or index_filter) else [],
        "documents": document_rows if dump_documents else [],
        "query_documents": query_rows if query_requested else [],
        "query_error": query_error,
        "index_filter": index_filter,
        "nosql_command": json_safe(nosql_command) if nosql_command is not None else None,
        "nosql_command_database": command_database if nosql_command is not None else None,
        "nosql_command_result": nosql_command_result,
        "nosql_command_error": nosql_command_error,
        "capabilities": capabilities,
    }


def _base_record(
    *,
    host: str,
    port: int,
    auth_db: str,
    database: str | None,
    collection_targets: list[str],
    show_databases: bool,
    show_collections: bool,
    show_indexes: bool,
    dump_documents: bool,
    dump_limit: int | None,
    query_filter: dict[str, Any] | None,
    projection: dict[str, Any] | None,
    document_selector: Any | None = None,
    index_filter: str | None = None,
    nosql_command: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": int(port),
        "service": "mongodb",
        "auth_db": auth_db,
        "database": database,
        "is_mongodb": False,
        "status": "fail",
        "auth_required": None,
        "provided_credentials": False,
        "provided_username": None,
        "provided_password": None,
        "defcreds_enabled": False,
        "effective_username": None,
        "credential_attempts": [],
        "server_version": None,
        "hello": None,
        "show_databases": show_databases,
        "show_collections": show_collections,
        "show_indexes": show_indexes,
        "collection_targets": collection_targets,
        "dump_documents": dump_documents,
        "dump_limit": dump_limit,
        "dump_safety_limit": _MONGODB_DUMP_SAFETY_LIMIT if dump_documents and dump_limit is None else None,
        "document_selector": document_selector,
        "index_filter": index_filter,
        "query_filter": json_safe(query_filter) if query_filter is not None else None,
        "projection": json_safe(projection) if projection is not None else None,
        "nosql_command": json_safe(nosql_command) if nosql_command is not None else None,
        "nosql_command_database": None,
        "nosql_command_result": None,
        "nosql_command_error": None,
        "database_names": None,
        "database_count": None,
        "collections": [],
        "indexes": [],
        "documents": [],
        "query_documents": [],
        "query_error": None,
        "capabilities": {},
        "elapsed_ms": None,
        "error": None,
    }


def _audit_mongodb_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    credential_candidates: list[dict[str, Any]],
    auth_db: str,
    database: str | None,
    show_databases: bool,
    show_collections: bool,
    show_indexes: bool,
    collection_targets: list[str],
    collection_targets_by_database: dict[str | None, list[str]],
    dump_documents: bool,
    dump_limit: int | None,
    query_filter: dict[str, Any] | None,
    projection: dict[str, Any] | None,
    document_selector: Any | None = None,
    index_filter: str | None = None,
    nosql_command: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attempts = max(1, int(retries) + 1)
    last_error: str | None = None
    selected_database = str(database or "").strip() or None
    auth_database = str(auth_db or "admin").strip() or "admin"
    record_template = _base_record(
        host=host,
        port=port,
        auth_db=auth_database,
        database=selected_database,
        collection_targets=collection_targets,
        show_databases=show_databases,
        show_collections=show_collections,
        show_indexes=show_indexes,
        dump_documents=dump_documents,
        dump_limit=dump_limit,
        query_filter=query_filter,
        projection=projection,
        document_selector=document_selector,
        index_filter=index_filter,
        nosql_command=nosql_command,
    )

    for attempt in range(attempts):
        started = time.monotonic()
        client: MongoAuditClient | None = None
        try:
            client = _open_client(host, port, timeout, username=None, password=None, auth_db=auth_database)
            hello = client.hello()
            version = None
            try:
                info = client.server_info()
                version = str(info.get("version") or "").strip() or None
            except Exception:
                version = str(hello.get("version") or "").strip() or None

            anon_databases, anon_error = _try_list_databases(client)
            auth_required = anon_databases is None and anon_error == "authentication required"
            credential_attempts: list[dict[str, Any]] = []
            selected_credential: dict[str, Any] | None = None
            active_client = client
            active_client_owned = False

            if credential_candidates:
                selected_credential, credential_attempts = _try_credentials(
                    host,
                    port,
                    timeout,
                    auth_db=auth_database,
                    credential_candidates=credential_candidates,
                )
                if selected_credential is not None:
                    active_client = _open_client(
                        host,
                        port,
                        timeout,
                        username=str(selected_credential.get("username") or ""),
                        password=None
                        if selected_credential.get("password") is None
                        else str(selected_credential.get("password")),
                        auth_db=auth_database,
                    )
                    active_client_owned = True
                    database_names, database_error = _try_list_databases(active_client)
                    status = "weak_default_creds" if selected_credential.get("default") else "valid_credentials"
                    effective_username = selected_credential.get("username")
                    effective_password = selected_credential.get("password")
                    auth_required = True if auth_required else False
                elif anon_databases is not None:
                    database_names = anon_databases
                    database_error = None
                    status = "invalid_credentials_anonymous"
                    effective_username = credential_candidates[0].get("username")
                    effective_password = credential_candidates[0].get("password")
                    auth_required = False
                else:
                    database_names = None
                    database_error = anon_error or "authentication required"
                    status = "auth_required"
                    effective_username = credential_candidates[0].get("username")
                    effective_password = credential_candidates[0].get("password")
                    auth_required = True
            elif anon_databases is not None:
                database_names = anon_databases
                database_error = None
                status = "open_no_auth"
                effective_username = None
                effective_password = None
                auth_required = False
            else:
                database_names = None
                database_error = anon_error or "authentication required"
                status = "auth_required" if auth_required else "fail"
                effective_username = None
                effective_password = None

            allow_data_actions = status in _MONGODB_DEEP_STATUSES
            data = _collect_mongodb_data(
                active_client,
                database_names=database_names,
                selected_database=selected_database,
                collection_targets=collection_targets if allow_data_actions else [],
                collection_targets_by_database=collection_targets_by_database if allow_data_actions else {},
                show_databases=show_databases if allow_data_actions else False,
                show_collections=show_collections if allow_data_actions else False,
                show_indexes=show_indexes if allow_data_actions else False,
                dump_documents=dump_documents if allow_data_actions else False,
                dump_limit=dump_limit if allow_data_actions else None,
                query_filter=query_filter if allow_data_actions else None,
                projection=projection if allow_data_actions else None,
                index_filter=index_filter if allow_data_actions else None,
                nosql_command=nosql_command if allow_data_actions else None,
            )
            if active_client_owned:
                active_client.close()

            record = dict(record_template)
            record.update(data)
            record.update(
                {
                    "timestamp": utc_now_iso(),
                    "is_mongodb": True,
                    "status": status,
                    "auth_required": auth_required,
                    "provided_credentials": bool(credential_candidates),
                    "provided_username": effective_username if credential_candidates else None,
                    "provided_password": effective_password if credential_candidates else None,
                    "defcreds_enabled": any(bool(item.get("default")) for item in credential_candidates),
                    "effective_username": effective_username,
                    "credential_attempts": credential_attempts,
                    "server_version": version,
                    "hello": hello,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": data.get("query_error") or data.get("nosql_command_error") or database_error,
                }
            )
            return record
        except Exception as exc:
            last_error = normalize_mongodb_error(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
        finally:
            if client is not None:
                client.close()

    record = dict(record_template)
    record.update(
        {
            "timestamp": utc_now_iso(),
            "status": "fail",
            "is_mongodb": False,
            "error": last_error or "connection failed",
        }
    )
    return record


def _audit_mongodb_host_stage(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    credential_candidates: list[dict[str, Any]],
    auth_db: str,
    database: str | None,
    show_databases: bool,
    show_collections: bool,
    show_indexes: bool,
    collection_targets: list[str],
    collection_targets_by_database: dict[str | None, list[str]],
    dump_documents: bool,
    dump_limit: int | None,
    query_filter: dict[str, Any] | None,
    projection: dict[str, Any] | None,
    document_selector: Any | None = None,
    index_filter: str | None = None,
    nosql_command: dict[str, Any] | None = None,
    *,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_mongodb_host(
        host,
        port,
        timeout,
        retries,
        credential_candidates,
        auth_db,
        database,
        show_databases if run_deep_checks else False,
        show_collections if run_deep_checks else False,
        show_indexes if run_deep_checks else False,
        collection_targets if run_deep_checks else [],
        collection_targets_by_database if run_deep_checks else {},
        dump_documents if run_deep_checks else False,
        dump_limit if run_deep_checks else None,
        query_filter if run_deep_checks else None,
        projection if run_deep_checks else None,
        document_selector if run_deep_checks else None,
        index_filter if run_deep_checks else None,
        nosql_command if run_deep_checks else None,
    )
    result = dict(record)
    status = str(result.get("status") or "fail")
    is_mongodb = bool(result.get("is_mongodb"))
    attempts = max(1, int(retries) + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)

    detect_result = "ok" if is_mongodb else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)
    auth_result = "ok" if is_mongodb and status in _MONGODB_DEEP_STATUSES.union({"auth_required"}) else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)
    if run_deep_checks and status in _MONGODB_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_error = str(result.get("query_error") or result.get("nosql_command_error") or "") or None
        telemetry.stage(_STAGE_DATA, "error" if data_error else "ok", data_error, elapsed_ms)
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    durations = {str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages}
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={durations.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={durations.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={durations.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={durations.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )
    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_MONGODB_TAG:<8}\t{host}\t{port}\t"


def _caps_suffix(record: dict[str, Any]) -> str:
    database_count = record.get("database_count")
    collections = record.get("collections")
    collection_count = len(collections) if isinstance(collections, list) else 0
    db_text = str(database_count) if isinstance(database_count, int) else "-"
    return f"(DBs:{db_text}) (collections:{collection_count})"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required = record.get("auth_required")
    auth_required_text = "True" if auth_required is True else "False" if auth_required is False else "unknown"
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "service": "mongodb",
                "host": record.get("host"),
                "port": record.get("port"),
                "detected": bool(record.get("is_mongodb")),
                "auth_required": auth_required,
                "server_version": record.get("server_version"),
            },
            ensure_ascii=False,
        )
    version = str(record.get("server_version") or "-")
    return f"{_nxc_prefix(record)} [*] MongoDB Service (auth required:{auth_required_text}) (version:{version})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)
    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access {_caps_suffix(record)}"
    if status == "weak_default_creds":
        username = str(record.get("effective_username") or "-")
        password = str(record.get("provided_password") or "")
        return f"{prefix} [+] {username}:{password} {_caps_suffix(record)}"
    if status == "valid_credentials":
        username = str(record.get("effective_username") or record.get("provided_username") or "-")
        password = record.get("provided_password")
        password_text = "<empty>" if password == "" else str(password or "")
        return f"{prefix} [+] {username}:{password_text} {_caps_suffix(record)}"
    if status == "invalid_credentials_anonymous":
        username = str(record.get("provided_username") or "-")
        password = record.get("provided_password")
        password_text = "<empty>" if password == "" else str(password or "")
        return f"{prefix} [!] invalid credentials {username}:{password_text}; anonymous access still available {_caps_suffix(record)}"
    if status == "auth_required":
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "-")
            password = record.get("provided_password")
            password_text = "<empty>" if password == "" else str(password or "")
            return f"{prefix} [-] {username}:{password_text}"
        return f"{prefix} [-] authentication required"
    err = _clip(str(record.get("error") or "connection failed"), 96)
    return f"{prefix} [!] connection failed err={err}"


def _format_databases_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    names = record.get("database_names")
    if not isinstance(names, list):
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "databases",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "databases": names,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    return [f"{prefix} [*] Databases"] + [f"{prefix} {name}" for name in names]


def _format_collections_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("collections")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "collections",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "collections": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Collections"]
    for row in rows:
        count = row.get("documents") if isinstance(row, dict) else None
        count_text = str(count) if isinstance(count, int) else "unknown"
        lines.append(f"{prefix} {row.get('database')}.{row.get('collection')} (documents:{count_text})")
    return lines


def _format_indexes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("indexes")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "indexes",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "indexes": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Indexes"]
    for row in rows:
        index = row.get("index") if isinstance(row, dict) else {}
        index_name = index.get("name") if isinstance(index, dict) else "-"
        lines.append(f"{prefix} {row.get('database')}.{row.get('collection')} index={index_name}")
    return lines


def _format_documents_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("documents")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "documents_dump",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "documents": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Dump Documents"]
    for row in rows:
        payload = json.dumps(row.get("document"), ensure_ascii=False, separators=(",", ":"))
        lines.append(f"{prefix} {row.get('database')}.{row.get('collection')}:{_clip(payload, 240)}")
    return lines


def _format_query_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("query_documents")
    error = record.get("query_error")
    if not rows and not error:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "query",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "query": record.get("query_filter"),
                    "documents": rows or [],
                    "error": error,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Query"]
    if error:
        lines.append(f"{prefix} [!] query failed err={_clip(str(error), 120)}")
    for row in rows or []:
        payload = json.dumps(row.get("document"), ensure_ascii=False, separators=(",", ":"))
        lines.append(f"{prefix} {row.get('database')}.{row.get('collection')}:{_clip(payload, 240)}")
    return lines


def _format_nosql_command_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    command = record.get("nosql_command")
    result = record.get("nosql_command_result")
    error = record.get("nosql_command_error")
    if command is None and result is None and not error:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "mongo_command",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("nosql_command_database"),
                    "command": command,
                    "result": result,
                    "error": error,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    database = str(record.get("nosql_command_database") or "admin")
    command_text = json.dumps(command or {}, ensure_ascii=False, separators=(",", ":"))
    lines = [f"{prefix} [*] Mongo Command database={database} command={_clip(command_text, 160)}"]
    if error:
        lines.append(f"{prefix} [!] command failed err={_clip(str(error), 160)}")
    elif result is not None:
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        lines.append(f"{prefix} {_clip(payload, 240)}")
    return lines


def _render_colored_mongodb_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag=_MONGODB_TAG,
        counts=(CountColorRule("DBs", "red"), CountColorRule("collections", "red"), CountColorRule("documents", "red")),
    )


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def audit_mongodb_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    credential_candidates: list[dict[str, Any]],
    auth_db: str,
    database: str | None,
    show_databases: bool,
    show_collections: bool,
    show_indexes: bool,
    collection_targets: list[str],
    collection_targets_by_database: dict[str | None, list[str]],
    dump_documents: bool,
    dump_limit: int | None,
    query_filter: dict[str, Any] | None,
    projection: dict[str, Any] | None,
    document_selector: Any | None = None,
    index_filter: str | None = None,
    nosql_command: dict[str, Any] | None = None,
    output_path: str | None = None,
    output_format: str = "txt",
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = False,
) -> tuple[int, int, int, int, int, int]:
    total = open_no_auth = weak = valid = auth_required = fail = 0
    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    progress = None
    try:
        indexed_hosts = list(enumerate(hosts))
        progress = start_audit_progress(_MONGODB_TAG, len(indexed_hosts), enabled=show_progress, leave=True)
        deep_requested = bool(
            show_databases
            or show_collections
            or show_indexes
            or collection_targets
            or dump_documents
            or query_filter is not None
            or index_filter is not None
            or nosql_command is not None
        )

        def _detect_task(host: str) -> dict[str, Any]:
            return _audit_mongodb_host_stage(
                host,
                port,
                timeout,
                retries,
                credential_candidates,
                auth_db,
                database,
                show_databases,
                show_collections,
                show_indexes,
                collection_targets,
                collection_targets_by_database,
                dump_documents,
                dump_limit,
                query_filter,
                projection,
                document_selector,
                index_filter,
                nosql_command,
                run_deep_checks=False,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
            )

        def _deep_task(host: str) -> dict[str, Any]:
            return _audit_mongodb_host_stage(
                host,
                port,
                timeout,
                retries,
                credential_candidates,
                auth_db,
                database,
                show_databases,
                show_collections,
                show_indexes,
                collection_targets,
                collection_targets_by_database,
                dump_documents,
                dump_limit,
                query_filter,
                projection,
                document_selector,
                index_filter,
                nosql_command,
                run_deep_checks=True,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
            )

        def _emit_detect(record: dict[str, Any]) -> None:
            if bool(record.get("is_mongodb")) and output_format == "txt":
                _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

        def _deep_gate(record: dict[str, Any]) -> tuple[bool, str]:
            status = str(record.get("status") or "fail")
            if deep_requested and status in _MONGODB_DEEP_STATUSES:
                return True, f"status={status}"
            return False, "no_data_actions" if not deep_requested else f"status={status}"

        pass_result = TwoPassAuditRunner(
            label=_MONGODB_TAG,
            workers=workers,
            debug_emit=debug_emit,
            progress=progress,
            detected_name="mongodb",
        ).run(
            indexed_hosts,
            detect_task=_detect_task,
            deep_task=_deep_task,
            is_detected=lambda record: bool(record.get("is_mongodb")),
            deep_gate=_deep_gate,
            emit_detect=_emit_detect,
            merge_records=_merge_stage2_record,
            not_detected_reason="not_mongodb",
        )
        if progress is not None:
            progress.close()
            progress = None

        for idx, _host in indexed_hosts:
            record = pass_result.final_records[idx]
            total += 1
            status = str(record.get("status") or "fail")
            if status == "open_no_auth":
                open_no_auth += 1
            elif status == "weak_default_creds":
                weak += 1
            elif status == "valid_credentials":
                valid += 1
            elif status == "auth_required":
                auth_required += 1
            elif status == "invalid_credentials_anonymous":
                pass
            else:
                fail += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)
            if output_format != "txt" and bool(record.get("is_mongodb")):
                _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

            suppress_auth_line = (
                output_format == "txt"
                and bool(record.get("is_mongodb"))
                and status == "auth_required"
                and not bool(record.get("provided_credentials"))
                and not bool(record.get("defcreds_enabled"))
            )
            suppress_fail_line = (
                suppress_timeout_status_lines and output_format == "txt" and _is_suppressed_fail_record(record)
            )
            if not suppress_auth_line and not suppress_fail_line:
                _emit_line(out_fh, emit_line, _format_record(record, output_format))
            for line in _format_databases_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)
            for line in _format_collections_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)
            for line in _format_indexes_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)
            for line in _format_documents_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)
            for line in _format_query_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)
            for line in _format_nosql_command_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, line)

            if logger is not None:
                logger.log(
                    "mongodb",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=status,
                    auth_required=record.get("auth_required"),
                    server_version=record.get("server_version"),
                    database_count=record.get("database_count"),
                    collection_count=len(record.get("collections") or []),
                    error=record.get("error"),
                )
    finally:
        if progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()
    return total, open_no_auth, weak, valid, auth_required, fail


def _open_client_for_successful_record(
    record: dict[str, Any],
    *,
    timeout: float,
    auth_db: str,
) -> MongoAuditClient:
    status = str(record.get("status") or "")
    if status == "open_no_auth":
        return _open_client(
            str(record.get("host") or ""),
            int(record.get("port") or 0),
            timeout,
            username=None,
            password=None,
            auth_db=auth_db,
        )
    if status in {"valid_credentials", "weak_default_creds"}:
        return _open_client(
            str(record.get("host") or ""),
            int(record.get("port") or 0),
            timeout,
            username=str(record.get("effective_username") or record.get("provided_username") or ""),
            password=None if record.get("provided_password") is None else str(record.get("provided_password")),
            auth_db=auth_db,
        )
    raise RuntimeError(f"mongodb shell requires successful access/auth, got status={status}")


def _run_mongodb_nosql_shell_session(
    client: MongoAuditClient,
    *,
    initial_database: str,
    input_func: Callable[[str], str],
    emit_line: Callable[[str], None],
) -> int:
    database = str(initial_database or "admin").strip() or "admin"
    while True:
        try:
            raw = input_func(f"mongodb:{database}> ")
        except EOFError:
            break
        line = str(raw or "").strip()
        if not line:
            continue
        if line.lower() in {"exit", "quit"}:
            break
        if line.lower().startswith("use "):
            next_database = line[4:].strip()
            if not next_database:
                emit_line("[!] database name is required")
                continue
            database = next_database
            emit_line(f"[*] switched to db {database}")
            continue
        command, error = _parse_json_object(line, field_name="command")
        if error:
            emit_line(f"[!] {error}")
            continue
        try:
            result = client.run_command(database, command or {})
            emit_line(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        except Exception as exc:
            emit_line(f"[!] command failed err={_clip(normalize_mongodb_error(exc), 160)}")
    return 0


def _run_mongodb_nosql_shell(
    *,
    host: str,
    port: int,
    timeout: float,
    retries: int,
    credential_candidates: list[dict[str, Any]],
    auth_db: str,
    database: str | None,
    emit_line: Callable[[str], None],
    shell_emit_line: Callable[[str], None],
    input_func: Callable[[str], str] = input,
) -> int:
    record = _audit_mongodb_host(
        host,
        port,
        timeout,
        retries,
        credential_candidates,
        auth_db,
        database,
        False,
        False,
        False,
        [],
        {},
        False,
        None,
        None,
        None,
    )
    if bool(record.get("is_mongodb")):
        emit_line(_format_detect_record(record, "txt"))
    emit_line(_format_record(record, "txt"))
    if str(record.get("status") or "") not in _MONGODB_DEEP_STATUSES:
        return 1
    client = _open_client_for_successful_record(record, timeout=timeout, auth_db=auth_db)
    try:
        return _run_mongodb_nosql_shell_session(
            client,
            initial_database=database or "admin",
            input_func=input_func,
            emit_line=shell_emit_line,
        )
    finally:
        client.close()


def run_mongodb_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console()
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
        if not ports:
            ports = [int(args.port)]
        hosts = collect_scan_targets(args.targets)
    except ValueError as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    if not hosts:
        console.error("mongodb requires -t/--targets")
        return 2

    credential_file_entries = None
    try:
        credential_file_entries = parse_username_password_credential_file(args.username, args.password)
    except ValueError as exc:
        console.error(str(exc))
        return 2

    if credential_file_entries is not None:
        credential_candidates = [
            {"username": item.username, "password": item.password, "default": False} for item in credential_file_entries
        ]
    else:
        credential_candidates = _credential_runs(args.username, args.password, defcreds=bool(args.defcreds))

    query_filter, query_error = _parse_json_object(getattr(args, "query", None), field_name="--query")
    if query_error:
        console.error(query_error)
        return 2
    nosql_command, nosql_error = _parse_json_object(getattr(args, "nosql_cmd", None), field_name="--nosql-cmd")
    if nosql_error:
        console.error(nosql_error)
        return 2
    if bool(getattr(args, "nosql_shell", False)) and nosql_command is not None:
        console.error("--nosql-shell cannot be used together with --nosql-cmd")
        return 2
    projection, projection_error = _parse_json_object(getattr(args, "projection", None), field_name="--projection")
    if projection_error:
        console.error(projection_error)
        return 2

    selected_database = str(getattr(args, "database", "") or "").strip() or None
    collection_targets_raw = _split_csv_values(list(getattr(args, "collections", []) or []))
    collection_targets, collection_targets_by_database, collection_error = _group_collection_targets(
        collection_targets_raw,
        selected_database,
    )
    if collection_error:
        console.error(collection_error)
        return 2
    document_selector_raw = getattr(args, "document", None)
    document_query_value: Any | None = None
    document_selector: Any | None = None
    if document_selector_raw is not None:
        if query_filter is not None:
            console.error("--document cannot be used together with --query")
            return 2
        if not collection_targets:
            console.error("--document requires at least one --collection target")
            return 2
        document_query_value, document_selector, document_error = _parse_document_selector(document_selector_raw)
        if document_error:
            console.error(document_error)
            return 2
        query_filter = {"_id": document_query_value}
    if query_filter is not None and not collection_targets:
        console.error("--query requires at least one --collection target")
        return 2
    if projection is not None and not (query_filter is not None or getattr(args, "dump", None) is not None):
        console.error("--projection requires --query or --dump")
        return 2

    dump_value = getattr(args, "dump", None)
    dump_documents = dump_value is not None
    dump_limit = dump_value if isinstance(dump_value, int) and dump_value > 0 else None
    index_filter = str(getattr(args, "index", "") or "").strip() or None
    show_indexes = bool(args.show_indexes or index_filter)
    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith(_MONGODB_TAG) and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, _MONGODB_TAG, payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_mongodb_line(console, line):
            return
        if args.debug:
            console.plain(line)

    def emit_debug(message: str) -> None:
        if not args.debug:
            return
        debug_method = getattr(console, "debug", None)
        if callable(debug_method):
            debug_method(message)
        else:
            console.info(message)

    if args.debug and args.output_format == "txt":
        if credential_file_entries is not None:
            mode = f"credfile={len(credential_file_entries)}"
        elif credential_candidates:
            mode = "credentials"
        else:
            mode = "detect-only"
        console.info(
            f"mongodb audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} auth_db={args.auth_db} format={args.output_format}"
        )

    if bool(getattr(args, "nosql_shell", False)):
        if len(hosts) != 1 or len(ports) != 1:
            console.error("--nosql-shell requires exactly one target and one port")
            return 2
        return _run_mongodb_nosql_shell(
            host=hosts[0],
            port=int(ports[0]),
            timeout=args.timeout,
            retries=args.retries,
            credential_candidates=credential_candidates,
            auth_db=str(args.auth_db or "admin"),
            database=selected_database,
            emit_line=emit_line,
            shell_emit_line=console.plain,
        )

    total = open_no_auth = weak = valid = auth_required = failed = 0
    hosts_by_port: dict[int, list[str]] = {int(port): list(hosts) for port in ports}
    if credential_file_entries is not None:
        for audit_port in ports:
            hosts_by_port[int(audit_port)] = filter_open_tcp_hosts_for_credential_file(
                hosts,
                int(audit_port),
                timeout=args.timeout,
                workers=args.workers,
            )
            if args.debug:
                emit_debug(
                    f"credential_prefilter port={int(audit_port)} open={len(hosts_by_port[int(audit_port)])}/{len(hosts)}"
                )

    outer_progress = None
    use_global_progress = should_use_global_progress(args.output_format, len(ports), 1)
    if use_global_progress:
        outer_progress = start_command_progress(
            args,
            _MONGODB_TAG,
            progress_total_from_groups(hosts_by_port.values(), 1),
            enabled=True,
            leave=True,
        )

    output_written = False
    try:
        for audit_port in ports:
            audit_hosts = hosts_by_port[int(audit_port)]
            if not audit_hosts:
                continue
            part_total, part_open, part_weak, part_valid, part_auth, part_failed = audit_mongodb_targets(
                hosts=audit_hosts,
                port=int(audit_port),
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                credential_candidates=credential_candidates,
                auth_db=str(args.auth_db or "admin"),
                database=selected_database,
                show_databases=bool(args.show_databases),
                show_collections=bool(args.show_collections),
                show_indexes=show_indexes,
                collection_targets=collection_targets,
                collection_targets_by_database=collection_targets_by_database,
                dump_documents=dump_documents,
                dump_limit=dump_limit,
                query_filter=query_filter,
                projection=projection,
                document_selector=document_selector,
                index_filter=index_filter,
                nosql_command=nosql_command,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=output_written,
                suppress_timeout_status_lines=not bool(args.debug),
                debug_emit=emit_debug if args.debug else None,
                show_progress=not use_global_progress,
            )
            total += part_total
            open_no_auth += part_open
            weak += part_weak
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
            if outer_progress is not None:
                outer_progress.advance(part_total)
            output_written = True
    except OSError as exc:
        console.error(f"failed to process mongodb output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if stream_to_stdout:
        if (
            args.output_format == "txt"
            and not args.debug
            and total > 0
            and open_no_auth == 0
            and weak == 0
            and valid == 0
            and auth_required == 0
            and failed == total
        ):
            console.warn(
                "all mongodb targets are unreachable; check host/port, network reachability, and service status"
            )
        if args.debug and args.output_format == "txt":
            console.info(
                f"mongodb audit complete: total={total} anonymous={open_no_auth} weak={weak} "
                f"valid={valid} auth={auth_required} fail={failed}"
            )
    elif args.debug:
        console.info(
            f"mongodb audit complete: total={total} anonymous={open_no_auth} weak={weak} "
            f"valid={valid} auth={auth_required} fail={failed} format={args.output_format} output={args.output}"
        )
    return 0


__all__ = [
    "_audit_mongodb_host",
    "_format_detect_record",
    "_format_record",
    "audit_mongodb_targets",
    "run_mongodb_stage",
]
