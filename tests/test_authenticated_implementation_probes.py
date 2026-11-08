"""Metadata is read only after verified login and belongs to that exact pair."""

from __future__ import annotations

from types import SimpleNamespace

from redposture_core.stage_runtime import AuditCredentialRun
from tests.test_authenticated_implementations import BUILD


def test_mongodb_denied_build_info_keeps_valid_pair_and_never_borrows_first(monkeypatch):
    from redposture_core.modules.mongodb import actions

    probes = []
    closed = []

    class Client:
        def __init__(self, user):
            self.user = user
            self.client = self

        def hello(self):
            return {"ok": 1.0}

        def run_command(self, db, command):
            assert command == {"connectionStatus": 1}
            return {
                "authInfo": {"authenticatedUsers": [] if self.user == "bad" else [{"user": self.user, "db": "admin"}]}
            }

        def server_info(self):
            probes.append(self.user)
            if self.user == "second":
                raise PermissionError("buildInfo denied")
            return dict(BUILD)

        def list_database_names(self):
            return []

        def close(self):
            closed.append(self.user)

    monkeypatch.setattr(actions, "_open_client", lambda *a, **kw: Client(kw["username"]))
    selected, attempts = actions._try_credentials(
        "qa",
        27017,
        1,
        auth_db="admin",
        credential_candidates=[{"username": u, "password": "qa-password"} for u in ("first", "second", "bad")],
    )
    first, second, bad = attempts
    assert selected is first
    assert first["credential_capabilities"]["server_implementation"]["product"] == "MongoDB"
    assert second["ok"] is True and "server_implementation" not in second["credential_capabilities"]
    assert "buildInfo denied" in second["credential_capabilities"]["implementation_probe_error"]
    assert bad["ok"] is False and "credential_capabilities" not in bad
    assert probes == ["first", "second"] and closed == ["first", "second", "bad"]


def test_oracle_banner_denial_keeps_valid_pair_and_does_not_probe_rejections(monkeypatch):
    from redposture_core.modules.oracle import actions

    probes = []

    class Client:
        def __init__(self, user):
            self.user = user

        def current_context(self):
            if self.user == "bad":
                raise actions.OracleAuthError("invalid username/password")
            return {"session_user": self.user}

        def server_banner(self):
            probes.append(self.user)
            if self.user == "second":
                raise PermissionError("v$version denied")
            return {"banner": "Oracle Database 26ai Free Release 23.26.0.0.0", "version": "23.26.0.0.0"}

        def close(self):
            pass

    monkeypatch.setattr(actions, "_open_client", lambda *a, **kw: Client(kw["username"]))
    selected, attempts, terminal = actions._try_credentials(
        "qa",
        1521,
        1,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=False,
        as_sysdba=False,
        credential_candidates=[{"username": u, "password": "qa-password"} for u in ("first", "second", "bad")],
    )
    first, second, bad = attempts
    assert selected is first and terminal is None
    assert first["credential_capabilities"]["server_implementation"]["product"] == "Oracle Database"
    assert second["ok"] is True and "server_implementation" not in second["credential_capabilities"]
    assert "v$version denied" in second["credential_capabilities"]["implementation_probe_error"]
    assert bad["ok"] is False and "credential_capabilities" not in bad
    assert probes == ["first", "second"]


def test_clickhouse_build_query_is_readonly_credential_bound_and_optional(monkeypatch):
    from redposture_core.modules.clickhouse import actions

    state = actions.ClickHouseLifecycleState()
    queries = []

    def open_session(protocol, host, port, timeout, user, password, database, **kw):
        if user == "bad":
            return None, "Code: 516. Authentication failed"
        return actions._ChSession("native", SimpleNamespace(disconnect=lambda: None), user, password, database), None

    def query(session, sql, **kw):
        assert sql == "SELECT version(), value FROM system.build_options WHERE name = 'VERSION_FULL'"
        queries.append(session.username)
        return (
            ([["24.8.14.39", "ClickHouse 24.8.14.39"]], None)
            if session.username == "first"
            else (None, "Code: 497. NOT_ENOUGH_PRIVILEGES")
        )

    monkeypatch.setattr(actions, "_open_operational_session", open_session)
    monkeypatch.setattr(actions, "_credential_capabilities", lambda session: {"database_count": 0})
    monkeypatch.setattr(actions, "_query_rows", query)
    records = []
    for user in ("first", "second", "bad"):
        ctx = SimpleNamespace(
            host="qa",
            port=9000,
            target=None,
            args=SimpleNamespace(timeout=1, retries=0),
            lifecycle_state=state,
            credential=AuditCredentialRun(username=user, password="qa-password", source="provided"),
        )
        records.append(
            actions.authenticate_clickhouse(
                ctx, {"status": "auth_required"}, {"protocol": "native", "database": "default"}
            )
        )
    first, second, bad = records
    assert first["credential_capabilities"]["server_implementation"]["product"] == "ClickHouse"
    assert (
        second["provided_credentials_ok"] is True and "server_implementation" not in second["credential_capabilities"]
    )
    assert "NOT_ENOUGH_PRIVILEGES" in second["credential_capabilities"]["implementation_probe_error"]
    assert bad["provided_credentials_ok"] is False and not bad["credential_capabilities"]
    assert queries == ["first", "second"]
    state.close()
