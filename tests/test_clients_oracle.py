from __future__ import annotations

from redposture_core.clients.oracle import (
    OracleAuditClient,
    build_oracle_dsn,
    build_tns_connect_packet,
    classify_nne_policy,
    classify_oracle_error,
    json_safe,
    normalize_oracle_error,
    parse_listener_dump,
    parse_tns_packet,
)


class _Cursor:
    def __init__(self, rows, description) -> None:
        self.rows = list(rows)
        self.description = [(item,) for item in description]
        self.rowcount = len(rows)

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params or {}

    def fetchall(self):
        return list(self.rows)

    def fetchmany(self, count):
        return list(self.rows[:count])

    def close(self):
        self.closed = True


class _Connection:
    def __init__(self) -> None:
        self.queries = []

    def cursor(self):
        return _Cursor([(1, "alpha")], ["RESULT", "NAME"])

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def test_build_oracle_dsn_for_service_sid_and_plain_host() -> None:
    assert "SERVICE_NAME=FREEPDB1" in build_oracle_dsn("127.0.0.1", 1521, service="FREEPDB1")
    assert "SID=XE" in build_oracle_dsn("127.0.0.1", 1521, sid="XE")
    assert build_oracle_dsn("127.0.0.1", 1521) == "127.0.0.1:1521"
    assert "PROTOCOL=tcps" in build_oracle_dsn("db.local", 2484, service="ORCL", protocol="tcps")


def test_normalize_and_classify_oracle_errors() -> None:
    assert normalize_oracle_error(RuntimeError("ORA-01017: invalid username/password")) == "invalid credentials"
    assert classify_oracle_error("ORA-28000: the account is locked") == "account_locked"
    assert classify_oracle_error("ORA-28001: the password has expired") == "account_expired"
    assert classify_oracle_error("ORA-12514: listener does not currently know") == "service_unknown"
    assert (
        classify_oracle_error("ORA-12528: TNS listener: all appropriate instances are blocking")
        == "listener_restricted"
    )


def test_tns_packet_and_listener_dump_helpers() -> None:
    packet = build_tns_connect_packet("(CONNECT_DATA=(COMMAND=status))")
    parsed = parse_tns_packet(packet)
    assert parsed["length"] == len(packet)
    assert parsed["type"] == 1

    status_text = """
    STATUS of the LISTENER
    Security                  ON: Local OS Authentication
    VERSION                   TNSLSNR for Linux: Version 23.0.0.0.0
    """
    services_text = """
    Service "FREEPDB1" has 1 instance(s).
      Instance "FREE", status READY, has 1 handler(s) for this service...
    Service "FREE" has 1 instance(s).
    """
    dump = parse_listener_dump({"ok": True, "payload_text": status_text}, {"ok": True, "payload_text": services_text})
    assert dump["status_ok"] is True
    assert "FREEPDB1" in dump["services"]
    assert "FREE" in dump["sids"]
    assert dump["summary"]["restricted"] is False


def test_listener_dump_password_protected_and_nne_policy() -> None:
    dump = parse_listener_dump(
        {"ok": False, "payload_text": "TNS-01169: The listener has not recognized the password"},
        {"ok": False, "payload_text": ""},
    )
    assert dump["summary"]["password_protected"] is True
    weak = classify_nne_policy(
        tcp_available=True,
        tcps_available=False,
        banners=[{"network_service_banner": "Encryption service for Linux: RC4_40"}],
    )
    assert weak["weak"] is True
    assert "RC4" in weak["weak_reasons"]
    strong = classify_nne_policy(tcp_available=False, tcps_available=True, banners=[])
    assert strong["status"] == "tcps_only"
    assert (
        normalize_oracle_error(RuntimeError("DPY-6005: cannot connect"))
        == "connection refused (listener is not available)"
    )


def test_oracle_audit_client_query_execute_and_json_safe() -> None:
    raw = _Connection()
    client = OracleAuditClient(raw)
    assert client.query("select 1 as result from dual") == [{"result": 1, "name": "alpha"}]
    assert client.query("select 1 as result from dual", limit=1) == [{"result": 1, "name": "alpha"}]
    assert client.execute("begin null; end;") == {"ok": True, "rowcount": 1}

    class Weird:
        def __str__(self) -> str:
            return "weird"

    assert json_safe({"x": Weird()}) == {"x": "weird"}


class _SmartCursor:
    def __init__(self) -> None:
        self.description = []
        self.rows = []
        self.rowcount = 1

    def execute(self, sql, params=None):
        lower = sql.lower()
        if "count(*) as result" in lower or "case when" in lower:
            self.description = [("RESULT",)]
            self.rows = [(1,)]
        elif "v$version" in lower and "banner_full" in lower:
            self.description = [("BANNER_FULL",)]
            self.rows = [("Oracle Database 23ai Free",)]
        elif "sys_context" in lower:
            self.description = [("SESSION_USER",), ("CURRENT_SCHEMA",), ("CON_NAME",), ("CDB_NAME",)]
            self.rows = [("REDPOSTURE", "REDPOSTURE", "FREEPDB1", "FREE")]
        elif "v$pdbs" in lower:
            self.description = [("NAME",), ("OPEN_MODE",), ("RESTRICTED",)]
            self.rows = [("FREEPDB1", "READ WRITE", "NO")]
        elif "dba_users" in lower or "all_users" in lower:
            self.description = [("USERNAME",), ("ACCOUNT_STATUS",), ("DEFAULT_TABLESPACE",), ("PROFILE",)]
            self.rows = [("SYSTEM", "OPEN", "SYSTEM", "DEFAULT")]
        elif "user_role_privs" in lower and "granted_role" in lower:
            self.description = [("GRANTED_ROLE",), ("ADMIN_OPTION",), ("DEFAULT_ROLE",)]
            self.rows = [("DBA", "NO", "YES")]
        elif "user_sys_privs" in lower and "order by privilege" in lower:
            self.description = [("PRIVILEGE",), ("ADMIN_OPTION",)]
            self.rows = [("CREATE JOB", "NO")]
        elif "user_tab_privs" in lower:
            self.description = [("PRIVILEGE",), ("OWNER",), ("TABLE_NAME",)]
            self.rows = [("EXECUTE", "SYS", "DBMS_SCHEDULER")]
        elif "all_tables" in lower:
            self.description = [("OWNER",), ("TABLE_NAME",), ("NUM_ROWS",)]
            self.rows = [("REDPOSTURE", "ACCOUNTS", 3)]
        elif "all_tab_columns" in lower:
            self.description = [("OWNER",), ("TABLE_NAME",), ("COLUMN_NAME",)]
            self.rows = [("REDPOSTURE", "ACCOUNTS", "PASSWORD")]
        elif "all_directories" in lower or "dba_directories" in lower:
            self.description = [("DIRECTORY_NAME",), ("DIRECTORY_PATH",)]
            self.rows = [("DATA_PUMP_DIR", "/opt/oracle/admin/FREE/dpdump")]
        elif "bfilename" in lower:
            self.description = [("DATA",)]
            self.rows = [("wallet=WalletPass!2026",)]
        elif "sys.user$" in lower:
            self.description = [("NAME",), ("SPARE4",)]
            self.rows = [("SYSTEM", "S:HASH")]
        elif "dba_db_links" in lower or "user_db_links" in lower:
            self.description = [("OWNER",), ("DB_LINK",), ("USERNAME",), ("HOST",)]
            self.rows = [("REDPOSTURE", "PROD_LINK", "APP", "prod-db")]
        elif "redposture_java_exec" in lower:
            self.description = [("OUTPUT",)]
            self.rows = [("exit_code=0\nuid=54321(oracle)",)]
        elif "select * from" in lower:
            self.description = [("ID",), ("USERNAME",)]
            self.rows = [(1, "admin")]
        else:
            self.description = [("VALUE",)]
            self.rows = [(1,)]

    def fetchall(self):
        return self.rows

    def fetchmany(self, count):
        return self.rows[:count]

    def close(self):
        pass


class _SmartConnection:
    def cursor(self):
        return _SmartCursor()

    def commit(self):
        pass


def test_oracle_audit_client_metadata_privesc_and_exfil_helpers() -> None:
    client = OracleAuditClient(_SmartConnection())
    assert client.server_banner()["version"] == "23ai"
    assert client.current_context()["con_name"] == "FREEPDB1"
    assert client.list_pdbs()[0]["name"] == "FREEPDB1"
    assert client.list_users()[0]["username"] == "SYSTEM"
    assert client.list_roles()[0]["granted_role"] == "DBA"
    assert client.list_privileges()[0]["privilege"] == "CREATE JOB"
    assert client.list_schemas()[0]["owner"] == "REDPOSTURE"
    assert client.list_tables("REDPOSTURE")[0]["table_name"] == "ACCOUNTS"
    assert client.dump_table("REDPOSTURE", "ACCOUNTS", limit=1)[0]["username"] == "admin"
    findings = client.check_privesc()
    assert any(item["title"] == "DBA/SYSDBA capability" and item["result"] is True for item in findings)
    assert client.sensitive_scan()[0]["column_name"] == "PASSWORD"
    assert client.password_hashes()[0]["name"] == "SYSTEM"
    assert client.db_links()[0]["db_link"] == "PROD_LINK"
    assert client.list_directories()[0]["directory_name"] == "DATA_PUMP_DIR"
    assert (
        client.resolve_server_path("/opt/oracle/admin/FREE/dpdump/redposture_wallet_hint.txt")["directory"]
        == "DATA_PUMP_DIR"
    )
    assert client.os_read("redposture_wallet_hint.txt")["ok"] is True
    assert client.os_write("/opt/oracle/admin/FREE/dpdump/out.txt", "hello")["ok"] is True
    assert client.os_delete("/opt/oracle/admin/FREE/dpdump/out.txt")["ok"] is True
    scheduler = client.scheduler_exec("id")
    assert scheduler["ok"] is True
    assert scheduler["output_available"] is False
    java = client.java_exec("id")
    assert java["ok"] is True
    assert "uid=" in java["output"]


def test_scheduler_file_helpers_resolve_visible_directory_paths() -> None:
    client = OracleAuditClient(_SmartConnection())
    commands: list[str] = []
    client.list_directories = lambda: [  # type: ignore[method-assign]
        {"directory_name": "DATA_PUMP_DIR", "directory_path": "/opt/oracle/admin/FREE/dpdump"}
    ]
    client.scheduler_exec = lambda command, **_kwargs: commands.append(command) or {"ok": True, "error": None}  # type: ignore[method-assign]
    client._read_directory_file_chunk = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        "ok": True,
        "data": "large-file-data",
        "error": None,
    }
    client.os_delete = lambda *_args, **_kwargs: {"ok": True}  # type: ignore[method-assign]

    result = client.scheduler_read_file("redposture_large_file.txt")

    assert result["ok"] is True
    assert result["source_path"] == "/opt/oracle/admin/FREE/dpdump/redposture_large_file.txt"
    assert "/opt/oracle/admin/FREE/dpdump/redposture_large_file.txt" in commands[0]


def test_wallet_artifacts_try_directory_and_name_fallback() -> None:
    client = OracleAuditClient(_SmartConnection())
    seen_paths: list[str] = []
    client.list_directories = lambda: [  # type: ignore[method-assign]
        {"directory_name": "DATA_PUMP_DIR", "directory_path": "/opt/oracle/admin/FREE/dpdump"}
    ]

    def fake_read(path: str, **_kwargs):
        seen_paths.append(path)
        if path == "redposture_wallet_hint.txt":
            return {"ok": True, "method": "scheduler_readback", "data": "wallet=WalletPass!2026"}
        return {"ok": False, "error": "not found"}

    client.os_read = fake_read  # type: ignore[method-assign]

    artifacts = client.wallet_artifacts()

    assert any(item["file_name"] == "redposture_wallet_hint.txt" for item in artifacts)
    assert "/opt/oracle/admin/FREE/dpdump/redposture_wallet_hint.txt" in seen_paths
    assert "redposture_wallet_hint.txt" in seen_paths


def test_connect_oracle_with_fake_driver_and_error_classes() -> None:
    from redposture_core.clients.oracle import (
        OracleAccountExpiredError,
        OracleAccountLockedError,
        OracleAuthError,
        OracleClientError,
        OracleConnectConfig,
        OracleServiceError,
        connect_oracle,
    )

    class Driver:
        AUTH_MODE_SYSDBA = 2

        def __init__(self, exc=None) -> None:
            self.exc = exc
            self.calls = []

        def connect(self, **kwargs):
            self.calls.append(kwargs)
            if self.exc is not None:
                raise RuntimeError(self.exc)
            return "connection"

    config = OracleConnectConfig("db.local", 2484, service="FREEPDB1", protocol="tcps", insecure=True)
    driver = Driver()
    assert connect_oracle(config, username="sys", password="oracle", mode="sysdba", driver=driver) == "connection"
    assert driver.calls[0]["mode"] == 2

    for message, expected in [
        ("ORA-28000", OracleAccountLockedError),
        ("ORA-28001", OracleAccountExpiredError),
        ("ORA-01017", OracleAuthError),
        ("ORA-12514", OracleServiceError),
        ("ORA-12170", OracleClientError),
    ]:
        try:
            connect_oracle(config, username="x", password="y", driver=Driver(message))
        except expected:
            pass
        else:  # pragma: no cover - assertion guard
            raise AssertionError(f"expected {expected.__name__}")
