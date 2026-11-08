"""Product claims come from successful read-only SQL, never a startup error."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.postgres import actions

BANNER = "PostgreSQL 16.4 (Debian 16.4-1.pgdg120+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit"


def session(verified=True):
    return actions._PgSession(True, "scram-sha-256", "16.4", credential_verified=verified)


def test_verified_sql_identifies_backend_without_claiming_no_proxy(monkeypatch):
    queries = []

    def query(sock, sql):
        queries.append(sql)
        return [[BANNER, "16.4 (Debian build)", "160004"]], None

    monkeypatch.setattr(actions, "_pg_query_rows", query)
    state = session()
    got = actions._pg_server_implementation(object(), state, database="app")
    assert got["server_implementation"] == {
        "product": "PostgreSQL",
        "version": "16.4",
        "scope": "sql_backend",
        "evidence": "sql_version_and_settings",
    }
    assert actions._pg_startup_record_fields(state)["service_identity"] == "postgresql_compatible"
    assert queries == [
        "SELECT pg_catalog.version(), pg_catalog.current_setting('server_version'), pg_catalog.current_setting('server_version_num')"
    ]
    assert actions._pg_server_implementation(object(), state, database="app") == got
    assert len(queries) == 1


@pytest.mark.parametrize("verified", [None, False])
def test_no_identity_queries_without_confirmed_credentials(monkeypatch, verified):
    monkeypatch.setattr(actions, "_pg_query_rows", lambda *a, **k: pytest.fail("no confirmed auth"))
    assert actions._pg_server_implementation(object(), session(verified), database="app") == {}


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [["no such user"]],
        [["PostgreSQL 16.4", "16.4", "160004"]],
        [[BANNER, "16.5", "160005"]],
        [[BANNER, "16.4", "170004"]],
        [[BANNER, "16.4", "not-a-number"]],
        [[BANNER, None, "160004"]],
        [[BANNER.replace("Debian", "Greenplum Database"), "16.4", "160004"]],
        [[BANNER.replace("16.4 (", "16.4-YB-2.20 ("), "16.4", "160004"]],
        [[BANNER, "16.4", "160004"], [BANNER, "16.4", "160004"]],
    ],
)
def test_ambiguous_or_conflicting_sql_is_not_postgresql_product_evidence(monkeypatch, rows):
    monkeypatch.setattr(actions, "_pg_query_rows", lambda *a, **k: (rows, None))
    assert "server_implementation" not in actions._pg_server_implementation(object(), session(), database="app")


@pytest.mark.parametrize("database,expected", [("pgbouncer", True), ("app", False)])
def test_pgbouncer_requires_its_selected_console_and_show_version(monkeypatch, database, expected):
    calls = []

    def query(sock, sql):
        calls.append(sql)
        return [["PgBouncer 1.24.1"]], None

    monkeypatch.setattr(actions, "_pg_query_rows", query)
    got = actions._pg_server_implementation(object(), session(), database=database)
    assert ("server_implementation" in got) is expected
    if expected:
        assert calls == ["SHOW VERSION"]
        assert got["server_implementation"] == {
            "product": "PgBouncer",
            "version": "1.24.1",
            "scope": "proxy_console",
            "evidence": "show_version",
        }


@pytest.mark.parametrize("failure", ["permission denied", OSError("peer closed")])
def test_identity_failure_preserves_verified_credential_and_debug_reason(monkeypatch, failure):
    def query(sock, sql):
        if isinstance(failure, Exception):
            raise failure
        return [], failure

    monkeypatch.setattr(actions, "_pg_query_rows", query)
    state = session()
    got = actions._pg_server_implementation(object(), state, database="app")
    assert "server_implementation" not in got
    assert str(failure) in got["implementation_probe_error"]
    assert state.credential_verified is True


def test_output_labels_backend_separately_and_keeps_no_ansi():
    record = {
        "host": "qa",
        "port": 5432,
        "status": "valid_credentials",
        "effective_username": "a",
        "provided_password": "b",
        "server_implementation": {
            "product": "PostgreSQL",
            "version": "16.4",
            "scope": "sql_backend",
            "evidence": "sql_version_and_settings",
        },
    }
    txt = actions._format_record(record, "txt")
    assert "(backend:PostgreSQL)" in txt
    assert "(proxy:" not in txt
    assert "\x1b" not in txt + actions._format_record(record, "json")
    calls = []
    console = SimpleNamespace(
        _paint=lambda text, color, stream: calls.append((text, color)) or text, plain=lambda *a, **k: None
    )
    assert actions._render_colored_postgres_line(console, txt)
    assert ("backend:PostgreSQL", "orange") in calls
    assert ("a:b", "true_red") in calls


def test_each_valid_pair_owns_its_implementation_evidence(monkeypatch):
    from contextlib import nullcontext

    from redposture_core.modules.postgres import stage
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    def authenticate(sock, *, username, **kwargs):
        sock["user"] = username
        return session()

    def query(sock, sql):
        return ([[BANNER, "16.4", "160004"]], None) if sock["user"] == "reader" else ([], "permission denied")

    monkeypatch.setattr(actions, "_pg_open_socket", lambda *a, **kw: nullcontext({}))
    monkeypatch.setattr(actions, "_pg_startup_and_auth", authenticate)
    monkeypatch.setattr(actions, "_pg_query_rows", query)
    monkeypatch.setattr(actions, "_collect_postgres_privileges", lambda *a, **kw: (False, False, False, 0, None))
    monkeypatch.setattr(actions, "_pg_query_databases", lambda *a, **kw: ([], None))
    monkeypatch.setattr(actions, "_pg_send_terminate", lambda *a: None)
    records = []
    for user in ["reader", "limited"]:
        ctx = AuditHookContext(
            SimpleNamespace(timeout=1, retries=0), None, "qa", 5432, AuditCredentialRun(user, "pass", source="provided")
        )
        record = stage._postgres_probe_credential(ctx).to_dict()
        assert record["credential_verified"] is True
        assert record["status"] == "valid_credentials"
        records.append(record)
    assert records[0]["credential_capabilities"]["server_implementation"]["product"] == "PostgreSQL"
    assert "server_implementation" not in records[1]["credential_capabilities"]
    assert records[1]["implementation_probe_error"] == "permission denied"
    attempts = [
        {
            "username": r["effective_username"],
            "password": "pass",
            "status": r["status"],
            "credential_capabilities": r["credential_capabilities"],
        }
        for r in records
    ]
    lines = actions._format_credential_attempts_records(
        {"host": "qa", "port": 5432, "attempted_credentials": attempts}, "txt"
    )
    assert "(backend:PostgreSQL)" in lines[0]
    assert "(backend:" not in lines[1]


@pytest.mark.parametrize(
    ("banner", "setting", "number"),
    [
        ("PostgreSQL 9.6.24 on x86_64-pc-linux-gnu, compiled by gcc 8, 64-bit", "9.6.24", "90624"),
        ("PostgreSQL 17.2, compiled by Visual C++ build 1940, 64-bit", "17.2", "170002"),
    ],
)
def test_machine_version_matches_supported_postgresql_banner_variants(monkeypatch, banner, setting, number):
    monkeypatch.setattr(actions, "_pg_query_rows", lambda *a, **kw: ([[banner, setting, number]], None))
    assert (
        actions._pg_server_implementation(object(), session(), database="app")["server_implementation"]["version"]
        == setting
    )


@pytest.mark.parametrize(
    "banner",
    [
        "CockroachDB CCL v24.3.14 (aarch64-unknown-linux-gnu)",
        "PostgreSQL 8.0.2 on x86_64-pc-linux-gnu, compiled by GCC 4.8, 64-bit (Redshift 1.0)",
        "EnterpriseDB 16.4 on x86_64-pc-linux-gnu, compiled by gcc 12, 64-bit",
    ],
)
def test_other_implementations_keep_the_compatible_endpoint(monkeypatch, banner):
    monkeypatch.setattr(actions, "_pg_query_rows", lambda *a, **kw: ([[banner, "16.4", "160004"]], None))
    state = session()
    assert actions._pg_server_implementation(object(), state, database="app") == {}
    assert actions._pg_startup_record_fields(state)["service_identity"] == "postgresql_compatible"
