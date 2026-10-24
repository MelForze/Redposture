"""Native Oracle listener/service detection with the synchronous cache contract."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients import oracle as client_helpers
from ...clients.async_detect_stream import reraise_fallback
from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.async_oracle_detect import connect_probe, listener_command
from ...stage_runtime import StageTelemetryBuilder, _resolve_host_stage
from . import actions

_HOST_STAGE = actions.host_stage
_HOST_STAGE_IMPL = actions._audit_oracle_host_stage
_AUDIT_HOST = actions._audit_oracle_host
_OPEN_CLIENT = actions._open_client
_LISTENER_COMMAND = actions.tns_listener_command
_PROBE_TARGETS = actions._probe_listener_targets


def detect_sync(ctx: Any) -> AuditRecord:
    """Bind anonymous listener detection independently of optional CLI fields."""
    cfg = AuditConfig.from_namespace(ctx.args)
    payload = _resolve_host_stage(actions.host_stage)(
        host=ctx.host,
        port=ctx.port,
        timeout=cfg.timeout,
        retries=cfg.retries,
        protocol=getattr(ctx.args, "protocol", None),
        service=getattr(ctx.args, "service", None),
        sid=getattr(ctx.args, "sid", None),
        service_list=getattr(ctx.args, "service_list", None),
        sid_list=getattr(ctx.args, "sid_list", None),
        wallet=getattr(ctx.args, "wallet", None),
        ssl_server_dn=getattr(ctx.args, "ssl_server_dn", None),
        insecure=not any(
            getattr(ctx.args, name, None) for name in ("ca_file", "tls_ca", "ssl_ca", "ssl_server_dn", "wallet")
        ),
        credential_candidates=[],
        as_sysdba=bool(getattr(ctx.args, "as_sysdba", False)),
        listener_dump=bool(getattr(ctx.args, "listener_dump", False)),
        nne_check=bool(getattr(ctx.args, "nne_check", False)),
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=getattr(ctx.args, "schema", None),
        table=getattr(ctx.args, "table", None),
        dump_rows=False,
        dump_limit=None,
        query=None,
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method=getattr(ctx.args, "exec_method", None),
        reverse_shell=None,
        reverse_shell_type=getattr(ctx.args, "reverse_shell_type", None),
        fs_mode=getattr(ctx.args, "fs_mode", None),
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
        show_pdbs_limit=None,
        show_users_limit=None,
        show_schemas_limit=None,
        show_tables_limit=None,
        run_deep_checks=False,
        debug=cfg.debug,
        debug_emit=ctx.debug_emit,
        lifecycle_state=ctx.lifecycle_state,
        discover=False,
        discover_time=getattr(ctx.args, "discover_time", None),
        discover_max_bytes=getattr(ctx.args, "discover_max_bytes", None),
    )
    return (
        payload
        if isinstance(payload, AuditRecord)
        else AuditRecord.from_mapping(payload, module="oracle", service="oracle")
    )


async def probe_targets(
    host: str,
    port: int,
    timeout: float,
    *,
    protocol_candidates: list[str],
    target_candidates: list[dict[str, Any]],
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
    stop_on_available: bool = False,
) -> list[dict[str, Any]]:
    results = []
    for protocol in protocol_candidates:
        for candidate in target_candidates:
            service, sid = candidate.get("service"), candidate.get("sid")
            row = {
                "protocol": protocol,
                "service": service,
                "sid": sid,
                "status": "fail",
                "exists": None,
                "auth_required": None,
                "error": None,
            }
            connection = None
            try:
                connection = await connect_probe(
                    host,
                    port,
                    timeout=timeout,
                    protocol=protocol,
                    service=service,
                    sid=sid,
                    wallet=wallet,
                    ssl_server_dn=ssl_server_dn,
                    insecure=insecure,
                )
                row.update(status="accepted", exists=True, auth_required=False)
            except AsyncHttpFallback:
                raise
            except (
                client_helpers.OracleAuthError,
                client_helpers.OracleAccountLockedError,
                client_helpers.OracleAccountExpiredError,
            ) as exc:
                row.update(
                    status="available",
                    exists=True,
                    auth_required=True,
                    error=client_helpers.normalize_oracle_error(exc),
                )
            except client_helpers.OracleServiceError as exc:
                error = client_helpers.normalize_oracle_error(exc)
                if "restricted" in error:
                    row.update(status="restricted", exists=True, auth_required=True, error=error)
                else:
                    row.update(status="unknown", exists=False, auth_required=None, error=error)
            except Exception as exc:
                reraise_fallback(exc)
                row.update(
                    status="fail", exists=None, auth_required=None, error=client_helpers.normalize_oracle_error(exc)
                )
            finally:
                if connection is not None:
                    await connection.close()
            results.append(row)
            if stop_on_available and row["status"] in {"accepted", "available", "restricted"}:
                return results
    return results


async def _probe_dump(
    host: str, port: int, timeout: float, *, protocol: str, insecure: bool, status_response: dict[str, Any] | None
) -> dict[str, Any]:
    status = status_response or await listener_command(
        host, port, "status", timeout=timeout, protocol=protocol, insecure=insecure
    )
    services = await listener_command(host, port, "services", timeout=timeout, protocol=protocol, insecure=insecure)
    dump = actions.parse_listener_dump(status, services)
    dump["protocol"] = protocol
    return dump


def _finish(ctx: Any, record: dict[str, Any], cfg: AuditConfig, started: float) -> AuditRecord:
    for key in ("show_pdbs_limit", "show_users_limit", "show_schemas_limit", "show_tables_limit"):
        record[key] = None
    status = str(record.get("status") or "fail")
    detected = bool(record.get("is_oracle"))
    elapsed = int((time.monotonic() - started) * 1000)
    result = "ok" if detected else "error" if status == "fail" else "skip"
    error = str(record.get("error") or "") if result == "error" else None
    telemetry = StageTelemetryBuilder(
        host=ctx.host, port=ctx.port, attempts=max(1, cfg.retries + 1), debug=cfg.debug, debug_emit=ctx.debug_emit
    )
    telemetry.stage(actions._STAGE_DETECT_PROTOCOL, result, error, 0)
    statuses = actions._ORACLE_DEEP_STATUSES.union(
        {"auth_required", "account_locked", "account_expired", "invalid_credentials"}
    )
    auth_result = "ok" if detected and status in statuses else result
    telemetry.stage(actions._STAGE_AUTH_INFERENCE, auth_result, error if auth_result == "error" else None, 0)
    telemetry.stage(actions._STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
    telemetry.stage(actions._STAGE_DATA, "skip", "deep checks disabled", 0)
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{max(1, cfg.retries + 1)} "
        f"detect_ms=0 auth_ms=0 capabilities_ms=0 data_ms=0 total_ms={elapsed}"
    )
    return AuditRecord.from_mapping(
        telemetry.attach(record, status=status, total_ms=elapsed), module="oracle", service="oracle"
    )


async def detect(ctx: Any, _http: Any) -> AuditRecord:
    if (
        actions.host_stage is not _HOST_STAGE
        or actions._audit_oracle_host_stage is not _HOST_STAGE_IMPL
        or actions._audit_oracle_host is not _AUDIT_HOST
        or actions._open_client is not _OPEN_CLIENT
        or actions.tns_listener_command is not _LISTENER_COMMAND
        or actions._probe_listener_targets is not _PROBE_TARGETS
    ):
        raise AsyncHttpFallback("Oracle detection override requires legacy verification")
    cfg = AuditConfig.from_namespace(ctx.args)
    protocol: Any = getattr(ctx.args, "protocol", None)
    service, sid = getattr(ctx.args, "service", None), getattr(ctx.args, "sid", None)
    service_list, sid_list = getattr(ctx.args, "service_list", None), getattr(ctx.args, "sid_list", None)
    wallet, ssl_server_dn = getattr(ctx.args, "wallet", None), getattr(ctx.args, "ssl_server_dn", None)
    insecure = not any(
        getattr(ctx.args, key, None) for key in ("ca_file", "tls_ca", "ssl_ca", "ssl_server_dn", "wallet")
    )
    selected_protocol, selected_service, selected_sid = protocol, service, sid
    record = actions._base_record(ctx.host, ctx.port, service=service, sid=sid, protocol=protocol)
    started = time.monotonic()
    protocols = actions._protocols(protocol, ctx.port)
    candidates = actions._target_candidates(service, sid, service_list, sid_list)
    if candidates:
        selected_service, selected_sid = candidates[0].get("service"), candidates[0].get("sid")
        record.update(connect_service=selected_service, connect_sid=selected_sid)
    record["service_candidates"] = [row.get("service") for row in candidates if row.get("service")]
    record["sid_candidates"] = [row.get("sid") for row in candidates if row.get("sid")]
    last_error = None
    for attempt in range(max(1, cfg.retries + 1)):
        try:
            errors = []
            state = ctx.lifecycle_state if isinstance(ctx.lifecycle_state, dict) else None
            cached = state.get("oracle_detection") if state is not None else None
            if isinstance(cached, dict):
                targets = list(cached["listener_targets"])
                reachable = bool(cached["listener_reachable"])
                selected_protocol = str(cached["protocol"])
                selected_service, selected_sid = cached["service"], cached["sid"]
                record["listener_dump"] = cached.get("listener_dump")
                record["listener_restricted"] = cached.get("listener_restricted")
                record["listener_password_protected"] = cached.get("listener_password_protected")
            else:
                targets, reachable, response = [], False, None
                for proto in protocols:
                    current = await listener_command(
                        ctx.host, ctx.port, "status", timeout=min(cfg.timeout, 1.0), protocol=proto, insecure=insecure
                    )
                    if actions._status_confirms_oracle(current):
                        response, selected_protocol, reachable = current, proto, True
                        break
                    if current.get("error"):
                        errors.append(str(current["error"]))
                if response is not None:
                    advertised = actions.parse_listener_dump(response)
                    record["listener_restricted"] = bool(response.get("listener_restricted"))
                    record["listener_password_protected"] = bool(response.get("listener_password_protected"))
                    if not any((service, sid, service_list, sid_list)):
                        discovered = actions._target_candidates(
                            None, None, ",".join(advertised["services"]), ",".join(advertised["sids"])
                        )
                        ordered, seen = [], set()
                        for row in (*discovered, *candidates):
                            key = row.get("service"), row.get("sid")
                            if key not in seen:
                                seen.add(key)
                                ordered.append(row)
                        candidates = ordered
                    if not (
                        (advertised["listener_restricted"] or advertised["listener_password_protected"])
                        and not any((service, sid, service_list, sid_list))
                    ):
                        targets = await probe_targets(
                            ctx.host,
                            ctx.port,
                            cfg.timeout,
                            protocol_candidates=[selected_protocol],
                            target_candidates=candidates,
                            wallet=wallet,
                            ssl_server_dn=ssl_server_dn,
                            insecure=insecure,
                            stop_on_available=len(candidates) == 1,
                        )
                elif candidates:
                    targets = await probe_targets(
                        ctx.host,
                        ctx.port,
                        cfg.timeout,
                        protocol_candidates=protocols,
                        target_candidates=candidates[:1],
                        wallet=wallet,
                        ssl_server_dn=ssl_server_dn,
                        insecure=insecure,
                        stop_on_available=True,
                    )
                    reachable = actions._listener_probe_is_oracle(targets)
                    if reachable and len(candidates) > 1:
                        confirmed = next(
                            row
                            for row in targets
                            if row.get("status") in {"accepted", "available", "restricted", "unknown"}
                        )
                        selected_protocol = str(confirmed.get("protocol") or protocols[0])
                        targets.extend(
                            await probe_targets(
                                ctx.host,
                                ctx.port,
                                cfg.timeout,
                                protocol_candidates=[selected_protocol],
                                target_candidates=candidates[1:],
                                wallet=wallet,
                                ssl_server_dn=ssl_server_dn,
                                insecure=insecure,
                                stop_on_available=False,
                            )
                        )
                auth_probes = [row for row in targets if row.get("status") in {"accepted", "available", "restricted"}]
                if auth_probes:
                    selected = auth_probes[0]
                    selected_protocol = str(selected.get("protocol") or selected_protocol)
                    selected_service, selected_sid = selected.get("service"), selected.get("sid")
                if getattr(ctx.args, "listener_dump", False) and reachable:
                    record["listener_dump"] = await _probe_dump(
                        ctx.host,
                        ctx.port,
                        min(cfg.timeout, 1.5),
                        protocol=selected_protocol,
                        insecure=insecure,
                        status_response=response,
                    )
                if state is not None and reachable:
                    state["oracle_detection"] = {
                        "listener_targets": targets,
                        "listener_reachable": reachable,
                        "protocol": selected_protocol,
                        "service": selected_service,
                        "sid": selected_sid,
                        "auth_target": bool(auth_probes),
                        "auth_probes": auth_probes,
                        "listener_dump": record["listener_dump"],
                        "listener_restricted": record["listener_restricted"],
                        "listener_password_protected": record["listener_password_protected"],
                    }
            record["listener_targets"] = targets
            record["listener_services"] = [
                row
                for row in targets
                if row.get("service") and row.get("status") in {"accepted", "available", "restricted"}
            ]
            record["listener_sids"] = [
                row
                for row in targets
                if row.get("sid") and row.get("status") in {"accepted", "available", "restricted"}
            ]
            record["service_candidates"] = [row.get("service") for row in candidates if row.get("service")]
            record["sid_candidates"] = [row.get("sid") for row in candidates if row.get("sid")]
            if getattr(ctx.args, "nne_check", False):
                record["nne_check"] = actions.classify_nne_policy(
                    tcp_available=any(
                        row.get("protocol") == "tcp" and row.get("status") in {"accepted", "available", "restricted"}
                        for row in targets
                    ),
                    tcps_available=any(
                        row.get("protocol") == "tcps" and row.get("status") in {"accepted", "available", "restricted"}
                        for row in targets
                    ),
                    banners=[],
                )
            record.update(
                is_oracle=reachable,
                status="auth_required" if reachable else "fail",
                auth_required=True if reachable else None,
                transport_mode=selected_protocol,
                connect_service=selected_service,
                connect_sid=selected_sid,
                error=errors[-1] if errors else "authentication required" if reachable else "connection failed",
            )
            return _finish(ctx, record, cfg, started)
        except AsyncHttpFallback:
            raise
        except client_helpers.OracleDependencyError:
            raise
        except Exception as exc:
            reraise_fallback(exc)
            last_error = client_helpers.normalize_oracle_error(exc)
            if attempt < max(1, cfg.retries + 1) - 1:
                await asyncio.sleep(actions._retry_delay(attempt))
    record.update(
        timestamp=actions.utc_now_iso(), status="fail", is_oracle=False, error=last_error or "connection failed"
    )
    return _finish(ctx, record, cfg, started)
