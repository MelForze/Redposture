"""Native asyncio TNS listener commands and Thin-mode Oracle probe connections."""

from __future__ import annotations

import asyncio
import re
import struct
from typing import Any

from . import oracle as helpers
from .async_detect_stream import close_stream, require_numeric_host, reraise_fallback
from .async_http_detect import AsyncHttpFallback


async def _read(reader: asyncio.StreamReader, size: int, timeout: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = await asyncio.wait_for(reader.read(size - len(data)), max(0.1, timeout))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


async def listener_command(
    host: str, port: int, command: str, *, timeout: float = 1.0, protocol: str = "tcp", insecure: bool = False
) -> dict[str, Any]:
    require_numeric_host(host)
    cmd = re.sub(r"[^A-Za-z0-9_]", "", str(command or "")).lower() or "status"
    connect_data = (
        f"(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=redposture)(HOST={host})(USER=redposture))"
        f"(COMMAND={cmd})(ARGUMENTS=64)(SERVICE={host}:{int(port)})(VERSION=185599488)))"
    )
    packet = helpers.build_tns_connect_packet(connect_data)
    writer = None
    try:
        ssl_kwargs: dict[str, Any] = {}
        if str(protocol).lower() == "tcps":
            ssl_kwargs = {
                "ssl": helpers.shared_client_ssl_context(insecure=insecure),
                "server_hostname": host,
                "ssl_handshake_timeout": max(0.1, timeout),
            }
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port), **ssl_kwargs), max(0.1, timeout)
        )
        writer.write(packet)
        await asyncio.wait_for(writer.drain(), max(0.1, timeout))
        packets = []
        while True:
            try:
                header = await _read(reader, 8, timeout)
                if len(header) < 8:
                    break
                length = struct.unpack(">H", header[:2])[0]
                body = await _read(reader, max(0, length - 8), timeout)
                packets.append(helpers.parse_tns_packet(header + body))
            except TimeoutError:
                break
        text = helpers._tns_clean_text(packets)
        fields = helpers._extract_parenthesized_fields(text)
        protected = (
            "TNS-01169" in text
            or "ERR=1169" in text.upper()
            or "PASSWORD" in text.upper()
            and ("LISTENER" in text.upper() or "SECURITY" in text.upper())
        )
        restricted = any(
            token in text.upper()
            for token in (
                "TNS-01194",
                "(ERR=1194)",
                "(CODE=1194)",
                "TNS-12526",
                "TNS-12527",
                "TNS-12528",
                "ERR=12526",
                "ERR=12527",
                "ERR=12528",
            )
        )
        return {
            "command": cmd,
            "ok": bool(packets),
            "protocol": str(protocol).lower(),
            "packets": packets,
            "text": text,
            "fields": fields,
            "listener_password_protected": protected,
            "listener_restricted": restricted,
            "error": None if packets else "no listener response",
        }
    except Exception as exc:
        reraise_fallback(exc)
        # asyncio's bare TimeoutError carries no text; preserve the original
        # socket timeout normalization used by the synchronous listener.
        error = "connection timeout" if isinstance(exc, TimeoutError) else helpers.normalize_oracle_error(exc)
        return {
            "command": cmd,
            "ok": False,
            "protocol": str(protocol).lower(),
            "packets": [],
            "text": "",
            "fields": {},
            "listener_password_protected": False,
            "listener_restricted": False,
            "error": error,
        }
    finally:
        if writer is not None:
            await close_stream(writer)


async def connect_probe(
    host: str,
    port: int,
    *,
    timeout: float,
    protocol: str,
    service: str | None,
    sid: str | None,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
) -> Any:
    require_numeric_host(host)
    try:
        driver = helpers._load_oracledb()
    except helpers.OracleDependencyError as exc:
        raise AsyncHttpFallback(str(exc)) from exc
    factory = getattr(driver, "connect_async", None)
    thin = getattr(driver, "is_thin_mode", None)
    if not callable(factory) or not callable(thin) or not thin():
        raise AsyncHttpFallback("Oracle native async probes require connect_async and Thin mode")
    config = helpers.OracleConnectConfig(
        host=host,
        port=port,
        service=service,
        sid=sid,
        protocol=protocol,
        wallet=wallet,
        ssl_server_dn=ssl_server_dn,
        insecure=insecure,
    )
    dsn = helpers.build_oracle_dsn(host, port, service=service, sid=sid, protocol=protocol)
    kwargs = helpers._connect_kwargs(config)
    kwargs["tcp_connect_timeout"] = float(timeout)
    try:
        return await factory(user="REDPOSTURE_PROBE", password="redposture-probe-password", dsn=dsn, **kwargs)
    except Exception as exc:
        reraise_fallback(exc)
        kind = helpers.classify_oracle_error(exc)
        message = helpers.normalize_oracle_error(exc)
        if kind == "account_locked":
            raise helpers.OracleAccountLockedError(message) from exc
        if kind == "account_expired":
            raise helpers.OracleAccountExpiredError(message) from exc
        if kind == "invalid_credentials":
            raise helpers.OracleAuthError(message) from exc
        if kind in {"service_unknown", "listener_restricted"}:
            raise helpers.OracleServiceError(message) from exc
        raise helpers.OracleClientError(message) from exc


_SYNC_LISTENER_COMMAND = helpers.tns_listener_command
_SYNC_SERVICE_FINGERPRINT = helpers.tns_service_fingerprint
_FINGERPRINT_STEPS = helpers._tns_service_fingerprint_steps


async def service_fingerprint(
    host: str,
    port: int,
    *,
    service: str | None = None,
    sid: str | None = None,
    timeout: float = 1.0,
    protocol: str = "tcp",
    insecure: bool = False,
) -> bool:
    """The original descriptor proof with native IO and one total time budget."""
    from .async_retained_socket import detect_native

    if helpers._tns_service_fingerprint_steps is not _FINGERPRINT_STEPS:
        raise AsyncHttpFallback("Oracle descriptor fingerprint override")
    steps = helpers._tns_service_fingerprint_steps(
        host, port, service=service, sid=sid, timeout=timeout, protocol=protocol, insecure=insecure
    )
    try:
        async with asyncio.timeout(max(0.1, float(timeout))):
            return bool(await detect_native(steps, None, {_SYNC_SERVICE_FINGERPRINT: _FINGERPRINT_STEPS}))
    except TimeoutError:
        return False


async def spray_preflight(host: str, port: int, args: Any) -> bool:
    """Interpret the existing STATUS/first-descriptor spray guard before SDK IO."""
    from .. import stage_spray
    from ..detection_io import DetectCall

    if (
        stage_spray._oracle_spray_preflight is not stage_spray._ORACLE_SPRAY_PREFLIGHT_IMPL
        or stage_spray._oracle_spray_preflight_steps is not stage_spray._ORACLE_SPRAY_PREFLIGHT_STEPS
    ):
        raise AsyncHttpFallback("Oracle spray preflight override")
    value: Any
    steps = stage_spray._oracle_spray_preflight_steps(host, port, args)
    try:
        step = next(steps)
        while True:
            if not isinstance(step, DetectCall):
                raise AsyncHttpFallback("unsupported Oracle spray preflight operation")
            try:
                if step.function is _SYNC_LISTENER_COMMAND:
                    value = await listener_command(*step.args, **step.kwargs)
                elif step.function is _SYNC_SERVICE_FINGERPRINT:
                    value = await service_fingerprint(*step.args, **step.kwargs)
                else:
                    raise AsyncHttpFallback("Oracle spray listener/fingerprint helper override")
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                step = steps.throw(exc)
            else:
                step = steps.send(value)
    except StopIteration as result:
        return bool(result.value)
    finally:
        steps.close()
