"""MongoDB audit stage."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from ...clients import transport
from ...clients.mongodb import (
    MongoAuditClient,
    MongoDependencyError,
    MongoNotMongoError,
    close_quietly,
    is_auth_error,
    is_transient_network_error,
    json_safe,
    non_system_databases,
    normalize_mongodb_error,
    open_mongodb_client,
)
from ...console import Console
from ...rendering import CountColorRule, render_colored_marker_line, render_tagged_detail_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    StageTelemetryBuilder,
    merge_stage_records,
)
from ...utils import (
    utc_now_iso,
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_timeout_error = transport.is_connection_timeout
_is_connection_refused_error = transport.is_connection_refused

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
            from bson import ObjectId

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
        # A8 fix: split on `.` FIRST so `--database mydb --collection users.audit`
        # correctly resolves to the (mydb, users.audit) → but split naturally
        # yields (users, audit). Prior behavior treated it as literal collection
        # "users.audit" under mydb and produced empty dumps. When --database is
        # set, a bare (no-dot) target still routes to that DB.
        if "." in value:
            database, collection = value.split(".", 1)
            database = database.strip()
            collection = collection.strip()
            if not database or not collection:
                return [], {}, f"invalid --collection target: {value}"
            grouped.setdefault(database, []).append(collection)
            normalized.append(value)
        elif selected_database:
            grouped.setdefault(selected_database, []).append(value)
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
    """Try each candidate; return the first success + the attempt log.

    A7 fix: transient network failures (connection refused/reset/timeout, DNS
    blips) are NOT recorded as credential attempts — the credential was never
    actually validated. Instead we mark them with `transient=True` so callers
    can distinguish "credentials rejected" (server said no) from "we never got
    to ask the server". Previously any exception looked like a rejected
    credential, so a brief network hiccup during the defcreds loop reported
    5 phantom failed credential probes.
    """
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
            transient = is_transient_network_error(exc) and not is_auth_error(exc)
            attempts.append(
                {
                    "username": username,
                    "password": password,
                    "ok": False,
                    "default": bool(candidate.get("default")),
                    "error": normalize_mongodb_error(exc),
                    "transient": transient,
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
        "show_databases_limit": None,
        "show_collections": show_collections,
        "show_collections_limit": None,
        "show_indexes": show_indexes,
        "show_indexes_limit": None,
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

    # A12 fix: persist credential_attempts across retries so the final fail
    # record still shows what was tried before the connection ultimately died.
    persisted_credential_attempts: list[dict[str, Any]] = []
    for attempt in range(attempts):
        started = time.monotonic()
        client: MongoAuditClient | None = None
        active_client_ref: MongoAuditClient | None = None
        active_client_owned_ref = False
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
            # "authentication required" is the canonical marker _try_list_databases sets
            # when is_auth_error matched, but some servers surface auth failures under
            # other normalized messages ("not authorized", "authentication failed"). If we
            # later authenticate successfully, the check at line 548 below promotes the
            # inference to True for any non-transport anon failure.
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
                # A12: cache the attempt log immediately after _try_credentials
                # returns, before any subsequent step can raise and lose it.
                if credential_attempts:
                    persisted_credential_attempts = list(credential_attempts)
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
                    # A10 fix: mirror ownership onto the outer refs so the finally
                    # block can close the credentialed client if _collect_mongodb_data
                    # (or anything after it) raises. Without this, active_client
                    # leaked pymongo topology/monitor threads under exceptions.
                    active_client_ref = active_client
                    active_client_owned_ref = True
                    database_names, database_error = _try_list_databases(active_client)
                    status = "weak_default_creds" if selected_credential.get("default") else "valid_credentials"
                    effective_username = selected_credential.get("username")
                    effective_password = selected_credential.get("password")
                    # Auth succeeded; if anon could not list databases (any auth-shaped or
                    # normalized-error response) that's evidence the server enforced auth,
                    # regardless of the exact anon_error string. Only report auth_required
                    # as False when the anon listing itself succeeded.
                    auth_required = anon_databases is None
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
                    # A7 fix: if every credential attempt was actually a network
                    # transient (nothing reached the server verdict), do NOT
                    # advertise "auth_required with N failed credentials". Report
                    # the underlying transport failure so the operator can retry.
                    non_transient_attempts = [item for item in credential_attempts if not item.get("transient")]
                    if credential_attempts and not non_transient_attempts:
                        first_error = credential_attempts[0].get("error") or "connection failed"
                        raise ConnectionError(first_error)
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
                # Ownership transferred to caller frame — cancel the
                # finally-block backup close for this attempt.
                active_client_owned_ref = False
                active_client_ref = None

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
                    # A11 fix: reflect actual attempts, not whether the caller
                    # *supplied* defaults. If the user's own credential succeeded
                    # first, the defcreds probes were never exercised and the
                    # report should not claim defcreds coverage.
                    "defcreds_enabled": any(bool(item.get("default")) for item in credential_attempts),
                    "effective_username": effective_username,
                    "credential_attempts": credential_attempts,
                    "server_version": version,
                    "hello": hello,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": data.get("query_error") or data.get("nosql_command_error") or database_error,
                }
            )
            return record
        except (MongoNotMongoError, MongoDependencyError) as exc:
            # A9 fix: fail-fast on terminal classifications. A non-MongoDB
            # endpoint (banner does not match) or a missing pymongo install
            # will never succeed on a retry — burning the retry budget just
            # multiplies latency across large scans.
            last_error = normalize_mongodb_error(exc)
            break
        except Exception as exc:
            last_error = normalize_mongodb_error(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
        finally:
            if client is not None:
                client.close()
            if active_client_owned_ref and active_client_ref is not None:
                try:
                    active_client_ref.close()
                except Exception:
                    pass

    record = dict(record_template)
    record.update(
        {
            "timestamp": utc_now_iso(),
            "status": "fail",
            "is_mongodb": False,
            "error": last_error or "connection failed",
            # A12 fix: surface any credential probes that reached the server
            # before the terminal failure — otherwise the final record silently
            # loses evidence of what was tried.
            "credential_attempts": persisted_credential_attempts,
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
    show_databases_limit: int | None = None,
    show_collections_limit: int | None = None,
    show_indexes_limit: int | None = None,
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
    record["show_databases_limit"] = show_databases_limit if run_deep_checks else None
    record["show_collections_limit"] = show_collections_limit if run_deep_checks else None
    record["show_indexes_limit"] = show_indexes_limit if run_deep_checks else None
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
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return f"{prefix} [+] {username}:{password_text} {_caps_suffix(record)}"
    if status == "invalid_credentials_anonymous":
        username = str(record.get("provided_username") or "-")
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return f"{prefix} [!] invalid credentials {username}:{password_text}; anonymous access still available {_caps_suffix(record)}"
    if status == "auth_required":
        attempts = _credential_attempt_rows(record)
        if len(attempts) > 1:
            return ""
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "-")
            provided_password = record.get("provided_password")
            password_text = "<empty>" if provided_password == "" else str(provided_password or "")
            return f"{prefix} [-] {username}:{password_text}"
        return f"{prefix} [-] authentication required"
    err = _clip(str(record.get("error") or "connection failed"), 96)
    return f"{prefix} [!] connection failed err={err}"


def _credential_attempt_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    attempted_rows = _generic_credential_attempt_rows(record.get("attempted_credentials"))
    if len(attempted_rows) > 1:
        return attempted_rows
    attempts = record.get("credential_attempts")
    if isinstance(attempts, list) and attempts:
        return [item for item in attempts if isinstance(item, dict)]
    return attempted_rows


def _generic_credential_attempt_rows(attempted_credentials: Any) -> list[dict[str, Any]]:
    if not isinstance(attempted_credentials, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in attempted_credentials:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        rows.append(
            {
                "username": item.get("username"),
                "password": item.get("password"),
                "ok": status in {"open_no_auth", "valid_credentials", "weak_default_creds"},
                "default": item.get("source") == "default",
                "error": status or None,
            }
        )
    return rows


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    if str(record.get("status") or "") != "auth_required":
        return []
    attempts = _credential_attempt_rows(record)
    if len(attempts) < 2:
        return []
    if output_format == "json":
        return []
    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        username = str(attempt.get("username") or "-")
        password = attempt.get("password")
        password_text = "<empty>" if password == "" else str(password or "")
        marker = "[+]" if attempt.get("ok") else "[-]"
        lines.append(f"{prefix} {marker} {username}:{password_text}")
    return lines


def _format_databases_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    names = record.get("database_names")
    if not isinstance(names, list):
        return []
    raw_limit = record.get("show_databases_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    meta = limit_metadata(names, limit)
    displayed_names = limit_sequence(names, limit)
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "databases",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "databases": displayed_names,
                    "databases_shown": meta["shown"],
                    "databases_limit": meta["limit"],
                    "databases_truncated": meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    if limit is not None and len(names) > len(displayed_names):
        header = f"{prefix} [*] Databases (showing:{len(displayed_names)} of {len(names)})"
    else:
        header = f"{prefix} [*] Databases"
    return [header] + [f"{prefix} {name}" for name in displayed_names]


def _format_collections_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("collections")
    if not isinstance(rows, list) or not rows:
        return []
    raw_limit = record.get("show_collections_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    meta = limit_metadata(rows, limit)
    displayed_rows = limit_sequence(rows, limit)
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "collections",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "collections": displayed_rows,
                    "collections_shown": meta["shown"],
                    "collections_limit": meta["limit"],
                    "collections_truncated": meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    if limit is not None and len(rows) > len(displayed_rows):
        lines = [f"{prefix} [*] Collections (showing:{len(displayed_rows)} of {len(rows)})"]
    else:
        lines = [f"{prefix} [*] Collections"]
    for row in displayed_rows:
        count = row.get("documents") if isinstance(row, dict) else None
        count_text = str(count) if isinstance(count, int) else "unknown"
        lines.append(f"{prefix} {row.get('database')}.{row.get('collection')} (documents:{count_text})")
    return lines


def _format_indexes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("indexes")
    if not isinstance(rows, list) or not rows:
        return []
    raw_limit = record.get("show_indexes_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    meta = limit_metadata(rows, limit)
    displayed_rows = limit_sequence(rows, limit)
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "indexes",
                    "service": "mongodb",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "indexes": displayed_rows,
                    "indexes_shown": meta["shown"],
                    "indexes_limit": meta["limit"],
                    "indexes_truncated": meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    if limit is not None and len(rows) > len(displayed_rows):
        lines = [f"{prefix} [*] Indexes (showing:{len(displayed_rows)} of {len(rows)})"]
    else:
        lines = [f"{prefix} [*] Indexes"]
    for row in displayed_rows:
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
    if render_colored_marker_line(
        console,
        line,
        tag=_MONGODB_TAG,
        counts=(CountColorRule("DBs", "red"), CountColorRule("collections", "red"), CountColorRule("documents", "red")),
    ):
        return True
    if line.startswith(_MONGODB_TAG) and "\t" in line:
        return render_tagged_detail_line(console, line, tag=_MONGODB_TAG, default_color="cyan")
    return False


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


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
    record_line = _format_record(record, "txt")
    if record_line:
        emit_line(record_line)
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


__all__ = [
    "_audit_mongodb_host",
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
]


# Typed runner boundary -----------------------------------------------------
host_stage = _audit_mongodb_host_stage
