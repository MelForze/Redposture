"""Anonymous MongoDB detection using PyMongo's native async client."""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients import mongodb as client_helpers
from ...clients.async_detect_stream import reraise_fallback
from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.async_mongodb_detect import open_client, probe_legacy_hello
from ...stage_runtime import StageTelemetryBuilder, _resolve_host_stage
from . import actions

_HOST_STAGE = actions.host_stage
_HOST_STAGE_IMPL = actions._audit_mongodb_host_stage
_AUDIT_HOST = actions._audit_mongodb_host
_OPEN_CLIENT = actions._open_client


def detect_sync(ctx: Any) -> AuditRecord:
    """Bind the anonymous backend contract without relying on CLI-only fields."""
    cfg = AuditConfig.from_namespace(ctx.args)
    tls = bool(getattr(ctx.args, "tls", False))
    tls_ca = getattr(ctx.args, "tls_ca", None)
    if tls_ca is None:
        tls_ca = getattr(ctx.args, "ca_file", None)
    tls_cert_key = getattr(ctx.args, "tls_cert_key", None)
    payload = _resolve_host_stage(actions.host_stage)(
        host=ctx.host,
        port=ctx.port,
        timeout=cfg.timeout,
        retries=cfg.retries,
        credential_candidates=[],
        auth_db=getattr(ctx.args, "auth_db", None) or "admin",
        database=getattr(ctx.args, "database", None),
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
        document_selector=None,
        index_filter=None,
        nosql_command=None,
        show_databases_limit=None,
        show_collections_limit=None,
        show_indexes_limit=None,
        tls=tls,
        tls_ca=tls_ca,
        tls_cert_key=tls_cert_key,
        tls_insecure=bool((tls or tls_cert_key) and not getattr(ctx.args, "tls_ca", None)),
        run_deep_checks=False,
        debug=cfg.debug,
        debug_emit=ctx.debug_emit,
    )
    return (
        payload
        if isinstance(payload, AuditRecord)
        else AuditRecord.from_mapping(payload, module="mongodb", service="mongodb")
    )


async def _anonymous_data(client: Any, names: list[str] | None, database: str | None) -> dict[str, Any]:
    # The empty collector is pure. An explicit database historically still walks
    # collections/counts during detection, despite all show/dump flags being off.
    # Preserve these existing requests with native awaits and the same outcomes.
    data = actions._collect_mongodb_data(
        cast(Any, None),
        database_names=names,
        selected_database=None,
        collection_targets=[],
        collection_targets_by_database={},
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    if not database:
        return data
    outcomes: dict[str, list[bool]] = {"can_list_collections": [], "can_read_documents": []}
    errors: list[str] = []

    def note(
        capability: str, ok: bool, operation: str, collection: str | None = None, error: str | None = None
    ) -> None:
        outcomes[capability].append(ok)
        row: dict[str, Any] = {"operation": operation, "ok": ok, "database": database}
        if collection is not None:
            row["collection"] = collection
        if error:
            row["error"] = error
            if error not in errors:
                errors.append(error)
        data["operation_results"].append(row)

    try:
        collections = await client.list_collection_names(database)
        note("can_list_collections", True, "list_collections")
    except Exception as exc:
        reraise_fallback(exc)
        collections = []
        note("can_list_collections", False, "list_collections", error=client_helpers.normalize_mongodb_error(exc))
    for collection in collections:
        try:
            count = await client.count_documents(database, collection)
            if count is not None:
                note("can_read_documents", True, "count_documents", collection)
        except Exception as exc:
            reraise_fallback(exc)
            note(
                "can_read_documents", False, "count_documents", collection, client_helpers.normalize_mongodb_error(exc)
            )
    for capability, values in outcomes.items():
        if not values:
            continue
        successes = sum(values)
        failures = len(values) - successes
        data["capabilities"][capability] = successes > 0
        data["capability_coverage"][capability] = {
            "state": "partial" if successes and failures else "allowed" if successes else "denied",
            "successes": successes,
            "failures": failures,
        }
    coverage = data["capability_coverage"].values()
    data["partial"] = (
        sum(row["successes"] for row in coverage) > 0
        and sum(row["failures"] for row in data["capability_coverage"].values()) > 0
    )
    data["query_error"] = "; ".join(errors) if errors else None
    return data


def _finish(ctx: Any, payload: dict[str, Any], cfg: AuditConfig, started: float) -> AuditRecord:
    status = str(payload.get("status") or "fail")
    detected = bool(payload.get("is_mongodb"))
    elapsed = int((time.monotonic() - started) * 1000)
    result = "ok" if detected else "error" if status == "fail" else "skip"
    error = str(payload.get("error") or "") if result == "error" else None
    telemetry = StageTelemetryBuilder(
        host=ctx.host, port=ctx.port, attempts=max(1, cfg.retries + 1), debug=cfg.debug, debug_emit=ctx.debug_emit
    )
    telemetry.stage(actions._STAGE_DETECT_PROTOCOL, result, error, 0)
    telemetry.stage(
        actions._STAGE_AUTH_INFERENCE,
        "ok" if detected and status in actions._MONGODB_DEEP_STATUSES.union({"auth_required"}) else result,
        error if result == "error" else None,
        0,
    )
    telemetry.stage(actions._STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
    telemetry.stage(actions._STAGE_DATA, "skip", "deep checks disabled", 0)
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{max(1, cfg.retries + 1)} "
        f"detect_ms=0 auth_ms=0 capabilities_ms=0 data_ms=0 total_ms={elapsed}"
    )
    payload = telemetry.attach(payload, status=status, total_ms=elapsed)
    return AuditRecord.from_mapping(payload, module="mongodb", service="mongodb")


async def detect(ctx: Any, _http: Any) -> AuditRecord:
    if (
        actions.host_stage is not _HOST_STAGE
        or actions._audit_mongodb_host_stage is not _HOST_STAGE_IMPL
        or actions._audit_mongodb_host is not _AUDIT_HOST
        or actions._open_client is not _OPEN_CLIENT
    ):
        raise AsyncHttpFallback("MongoDB detection override requires legacy verification")
    cfg = AuditConfig.from_namespace(ctx.args)
    auth_db = str(getattr(ctx.args, "auth_db", None) or "admin").strip() or "admin"
    database = str(getattr(ctx.args, "database", None) or "").strip() or None
    tls = bool(getattr(ctx.args, "tls", False))
    tls_ca = getattr(ctx.args, "tls_ca", None)
    tls_cert_key = getattr(ctx.args, "tls_cert_key", None)
    tls_insecure = bool((tls or tls_cert_key) and not tls_ca)
    template = actions._base_record(
        host=ctx.host,
        port=ctx.port,
        auth_db=auth_db,
        database=database,
        collection_targets=[],
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    stage_started = time.monotonic()
    last_error = None
    for attempt in range(max(1, cfg.retries + 1)):
        started = time.monotonic()
        client = None
        try:
            client = open_client(
                ctx.host,
                ctx.port,
                timeout=cfg.timeout,
                auth_db=auth_db,
                tls=tls,
                tls_ca=tls_ca,
                tls_cert_key=tls_cert_key,
                tls_insecure=tls_insecure,
            )
            hello = await client.hello()
            try:
                info = await client.server_info()
                version = str(info.get("version") or "").strip() or None
            except Exception as exc:
                reraise_fallback(exc)
                version = str(hello.get("version") or "").strip() or None
            try:
                names, error = await client.list_database_names(), None
            except Exception as exc:
                reraise_fallback(exc)
                names = None
                error = (
                    "authentication required"
                    if client_helpers.is_auth_error(exc)
                    else client_helpers.normalize_mongodb_error(exc)
                )
            required = names is None and error == "authentication required"
            status = "open_no_auth" if names is not None else "auth_required" if required else "fail"
            data = await _anonymous_data(client, names, database)
            payload = {
                **template,
                **data,
                "timestamp": actions.utc_now_iso(),
                "is_mongodb": True,
                "status": status,
                "auth_required": required,
                "server_version": version,
                "hello": hello,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": data.get("query_error") or data.get("nosql_command_error") or error,
            }
            return _finish(ctx, payload, cfg, stage_started)
        except AsyncHttpFallback:
            raise
        except (client_helpers.MongoNotMongoError, client_helpers.MongoDependencyError) as exc:
            last_error = client_helpers.normalize_mongodb_error(exc)
            break
        except Exception as exc:
            reraise_fallback(exc)
            if client_helpers.is_legacy_wire_error(exc):
                try:
                    legacy_hello = await probe_legacy_hello(
                        ctx.host,
                        ctx.port,
                        timeout=cfg.timeout,
                        tls=tls,
                        tls_ca_file=tls_ca,
                        tls_certificate_key_file=tls_cert_key,
                        tls_insecure=tls_insecure,
                    )
                except Exception as legacy_error:
                    reraise_fallback(legacy_error)
                    legacy_hello = None
                if legacy_hello is not None:
                    payload = {
                        **template,
                        "timestamp": actions.utc_now_iso(),
                        "is_mongodb": True,
                        "detection_status": "confirmed",
                        "detection_signals": ["legacy_ismaster_wire_reply"],
                        "status": "legacy_wire_unsupported",
                        "auth_required": None,
                        "credential_verification_status": "unavailable",
                        "credential_verification_reason": "legacy wire protocol is unsupported by installed PyMongo",
                        "hello": legacy_hello,
                        "error": "installed PyMongo cannot authenticate to this legacy MongoDB wire version",
                    }
                    return _finish(ctx, payload, cfg, stage_started)
            last_error = client_helpers.normalize_mongodb_error(exc)
            if attempt < max(1, cfg.retries + 1) - 1:
                await asyncio.sleep(actions._retry_delay(attempt))
        finally:
            if client is not None:
                await client.close()
    return _finish(
        ctx,
        {
            **template,
            "timestamp": actions.utc_now_iso(),
            "status": "fail",
            "is_mongodb": False,
            "error": last_error or "connection failed",
        },
        cfg,
        stage_started,
    )
