"""Anonymous PostgreSQL startup over native asyncio streams.

Authentication and data collection deliberately remain in the synchronous hooks.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.async_detect_stream import close_stream, require_numeric_host
from ...clients.async_http_detect import AsyncHttpFallback
from . import actions


async def _read(reader: asyncio.StreamReader, size: int, timeout: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        try:
            chunk = await asyncio.wait_for(reader.read(size - len(data)), timeout)
        except TimeoutError as exc:
            raise TimeoutError("timed out") from exc
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


async def _send(writer: asyncio.StreamWriter, payload: bytes, timeout: float) -> None:
    writer.write(payload)
    try:
        await asyncio.wait_for(writer.drain(), timeout)
    except TimeoutError as exc:
        raise TimeoutError("timed out") from exc


async def _startup(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, database: str, timeout: float
) -> actions._PgSession:
    # Use the original packet builder against a write-only sink. It performs no
    # socket IO here, so startup parameters and byte encoding cannot drift.
    class Packet:
        def sendall(self, value: bytes) -> None:
            writer.write(value)

    actions._pg_send_startup(cast(Any, Packet()), username="postgres", database=database)
    try:
        await asyncio.wait_for(writer.drain(), timeout)
    except TimeoutError as exc:
        raise TimeoutError("timed out") from exc
    detected = False
    auth_required: bool | None = None
    auth_method: str | None = None
    version: str | None = None
    while True:
        header = await _read(reader, 5, timeout)
        kind = header[:1]
        length = int.from_bytes(header[1:], "big")
        if length < 4 or length > actions._PG_MAX_MESSAGE_SIZE:
            raise ValueError(f"invalid postgres message length: {length}")
        payload = await _read(reader, length - 4, timeout)
        if not detected and kind not in actions._PG_HANDSHAKE_TYPES:
            raise actions._PgAuditError(f"unexpected response prefix: {kind!r}", detected=False)
        if kind == b"R":
            detected = True
            if len(payload) < 4:
                raise actions._PgAuditError("invalid authentication payload", detected=True)
            code = int.from_bytes(payload[:4], "big")
            if code == 0:
                if auth_required is None:
                    auth_required = False
                continue
            method = {3: "cleartext", 5: "md5", 10: "scram-sha-256", 11: "scram-sha-256", 12: "scram-sha-256"}.get(code)
            if code == 5 and len(payload) < 8:
                raise actions._PgAuditError(
                    "invalid MD5 authentication payload", detected=True, auth_required=True, auth_method=method
                )
            message = {
                3: "password authentication required",
                5: "md5 authentication required",
                10: "SCRAM authentication required",
                11: "unexpected SCRAM continue",
                12: "unexpected SCRAM final",
            }.get(code, f"unsupported auth method: {code}")
            raise actions._PgAuditError(message, detected=True, auth_required=True, auth_method=method)
        if kind == b"S":
            detected = True
            key, value = actions._pg_parse_parameter_status(payload)
            if key == "server_version":
                version = value
            continue
        if kind in {b"K", b"N"}:
            detected = True
            continue
        if kind == b"E":
            sqlstate, message = actions._pg_parse_error(payload)
            lower = message.lower()
            auth_failure = sqlstate in {"28P01", "28000"} or "password authentication failed" in lower
            error_kind = (
                "authentication_failed"
                if auth_failure
                else "auth_configuration_error"
                if "no authentication method is found" in lower
                else "startup_rejected"
            )
            raise actions._PgAuditError(
                message,
                detected=True,
                auth_required=True if auth_failure else None,
                auth_method=auth_method,
                sqlstate=sqlstate,
                failure_phase="startup",
                error_kind=error_kind,
            )
        if kind == b"Z":
            return actions._PgSession(
                auth_required=False if auth_required is None else auth_required,
                auth_method=auth_method,
                server_version=version,
            )
        raise actions._PgAuditError(f"unexpected handshake message: {kind!r}", detected=detected)


async def _probe(
    host: str, port: int, timeout: float, config: actions._PgTlsConfig, database: str
) -> actions._PgSession:
    require_numeric_host(host)
    writer: asyncio.StreamWriter | None = None
    startup = False
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        assert writer is not None
        if config.sslmode != "disable":
            await _send(writer, (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big"), timeout)
            response = await _read(reader, 1, timeout)
            if response == b"S":
                if not callable(getattr(writer, "start_tls", None)):
                    raise AsyncHttpFallback("PostgreSQL stream TLS upgrade unavailable")
                verify = config.sslmode in {"verify-ca", "verify-full"} or bool(config.ca_file)
                context = actions.shared_client_ssl_context(
                    insecure=not verify,
                    ca_file=config.ca_file,
                    cert_file=config.cert_file,
                    key_file=config.key_file,
                    check_hostname=config.sslmode == "verify-full",
                )
                await asyncio.wait_for(
                    writer.start_tls(
                        context, server_hostname=config.server_name or host, ssl_handshake_timeout=timeout
                    ),
                    timeout,
                )
            elif response == b"N":
                if config.sslmode != "prefer":
                    raise actions._PgAuditError(
                        "PostgreSQL server refused TLS", detected=True, failure_phase="tls", error_kind="tls_required"
                    )
            else:
                raise actions._PgAuditError(
                    f"invalid PostgreSQL SSL negotiation response: {response!r}",
                    detected=False,
                    failure_phase="tls",
                    error_kind="protocol_error",
                )
        startup = True
        return await _startup(reader, writer, database, timeout)
    except TimeoutError as exc:
        raise TimeoutError("timed out") from exc
    finally:
        if writer is not None:
            await close_stream(writer, terminate=b"X\x00\x00\x00\x04" if startup else None)


async def detect(ctx: Any, _http: Any) -> AuditRecord:
    from . import stage

    if stage._postgres_host_stage_is_replaced():
        raise AsyncHttpFallback("PostgreSQL host-stage override requires legacy verification")
    cfg = AuditConfig.from_namespace(ctx.args)
    database = str(getattr(ctx.args, "database", "") or "").strip() or "postgres"
    started = time.monotonic()
    base = {
        "host": ctx.host,
        "port": ctx.port,
        "service": "postgres",
        "module": "postgres",
        "database": database,
        "auth_database": database,
        "provided_credentials": False,
        "defcreds_enabled": False,
        "effective_username": "postgres",
    }
    last_error: str | None = None
    for attempt in range(max(1, cfg.retries + 1)):
        try:
            session = await _probe(
                ctx.host, ctx.port, cfg.timeout, stage._postgres_tls_config_from_args(ctx.args), database
            )
            payload = {
                **base,
                "is_postgres": True,
                "status": "open_no_auth",
                "auth_required": session.auth_required,
                "auth_method": session.auth_method,
                "server_version": session.server_version,
                "error": None,
            }
            break
        except actions._PgAuditError as exc:
            status = (
                "auth_required"
                if exc.detected and exc.auth_required is True
                else "unknown_auth"
                if exc.detected
                else "fail"
            )
            payload = {
                **base,
                "is_postgres": bool(exc.detected),
                "status": status,
                "auth_required": True if status == "auth_required" else exc.auth_required,
                "auth_method": exc.auth_method,
                "sqlstate": exc.sqlstate,
                "failure_phase": exc.failure_phase or ("startup" if exc.detected else "connect"),
                "error_kind": exc.error_kind or ("startup_rejected" if exc.detected else "connection_error"),
                "error": str(exc),
            }
            break
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt < max(1, cfg.retries + 1) - 1:
                await asyncio.sleep(actions._retry_delay(attempt))
    else:
        payload = {
            **base,
            "is_postgres": False,
            "status": "fail",
            "auth_required": None,
            "error": last_error or "connection failed",
        }
    payload.update(timestamp=actions.utc_now_iso(), elapsed_ms=int((time.monotonic() - started) * 1000))
    record = stage._postgres_record(payload)
    if isinstance(ctx.lifecycle_state, stage._PostgresLifecycleState):
        ctx.lifecycle_state.detect_record = record
    return record
