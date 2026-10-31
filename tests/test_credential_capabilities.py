"""AUTH-01: successful identities must never borrow another identity's ACLs."""

from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("module", ["etcd", "mongodb", "clickhouse", "postgres", "grafana"])
def test_successful_pairs_render_their_own_capabilities(module: str) -> None:
    actions = import_module(f"redposture_core.modules.{module}.actions")
    fields = {
        "etcd": ({"key_count": 7}, {"key_count": 0}, "(keys:7)", "(keys:0)"),
        "mongodb": (
            {"database_count": 7, "collection_count": 3},
            {"database_count": 0, "collection_count": 0},
            "(DBs:7) (collections:3)",
            "(DBs:0) (collections:0)",
        ),
        "clickhouse": (
            {"read_capability": True, "execute_capability": True, "admin_capability": True, "database_count": 7},
            {"read_capability": False, "execute_capability": False, "admin_capability": False, "database_count": 0},
            "(read:true) (rce:true) (admin:true) (DBs:7)",
            "(read:false) (rce:false) (admin:false) (DBs:0)",
        ),
        "postgres": (
            {"superuser": True, "can_execute_commands": True, "can_read_tables": True, "database_count": 7},
            {"superuser": False, "can_execute_commands": False, "can_read_tables": False, "database_count": 0},
            "(superuser:True) (rce:True) (read:True) (DBs:7)",
            "(superuser:False) (rce:False) (read:False) (DBs:0)",
        ),
        "grafana": ({"datasource_count": 7}, {"datasource_count": 0}, "(datasources:7)", "(datasources:0)"),
    }
    first, second, first_suffix, second_suffix = fields[module]
    attempts = [
        {
            "username": "same",
            "password": password,
            "source": "default",
            "ok": True,
            "status": "weak_default_creds",
            "credential_verified": True,
            "credential_capabilities": caps,
        }
        for password, caps in [("one", first), ("two", second)]
    ]
    record = {
        "host": "127.0.0.1",
        "port": 1234,
        "effective_username": "same",
        "effective_password": "one",
        "provided_password": "one",
        "credentials_source": "default",
        **first,
        "attempted_credentials": attempts,
        "credential_attempts": attempts,
        "auth_attempts": attempts,
    }
    formatter = (
        getattr(actions, "_format_credential_attempts_records", None) or actions._format_auth_attempt_detail_records
    )
    lines = formatter(record, "txt")
    assert len(lines) == 2
    assert f"[+] same:one {first_suffix}" in lines[0]
    assert f"[+] same:two {second_suffix}" in lines[1]
    assert first_suffix not in lines[1]


@pytest.mark.parametrize("module", ["airflow", "minio"])
def test_secondary_success_keeps_capabilities_and_exact_password_selection(module: str) -> None:
    render = import_module(f"redposture_core.modules.{module}.render")
    first: dict[str, object]
    second: dict[str, object]
    if module == "airflow":
        first = {
            f"authenticated_{key}_{field}": value
            for key in ("dags", "keys", "connections")
            for field, value in [("access", "allowed"), ("count", 7)]
        }
        second = {f"authenticated_{key}_access": "denied" for key in ("dags", "keys", "connections")}
        expected = "(Dags:Access Denied) (Keys:Access Denied) (Connections:Access Denied)"
        identity = "username"
        secret = "credential_password"
    else:
        first = {"admin_capability": "confirmed", "bucket_count": 7}
        second = {"admin_capability": "not_confirmed", "bucket_count": 0}
        expected = "(admin:False) (buckets:0)"
        identity = "access_key"
        secret = "credential_secret"
    # The selected identity is the second row with the same username. A
    # username-only match must not hide the first row's different password.
    attempts = [
        {"username": "same", "password": password, "credential_state": "valid", "credential_capabilities": caps}
        for password, caps in [("two", second), ("one", first)]
    ]
    record = {
        "host": "127.0.0.1",
        "port": 1234,
        "credential_state": "valid",
        "credential_results": [{identity: "same"}],
        secret: "one",
        **first,
        "attempted_credentials": attempts,
    }
    lines = render._format_credential_attempts_records(record, "txt")
    assert len(lines) == 1
    assert f"[+] same:two {expected}" in lines[0]


def test_jenkins_already_preserves_independent_jobs_access() -> None:
    from redposture_core.modules.jenkins import render

    record = {
        "host": "127.0.0.1",
        "port": 8080,
        "credential_jobs_count": 99,
        "attempted_credentials": [
            {
                "username": "same",
                "password": "one",
                "status": "valid_credentials",
                "credential_jobs_access": "allowed",
                "credential_jobs_count": 7,
            },
            {"username": "same", "password": "two", "status": "valid_credentials", "credential_jobs_access": "denied"},
        ],
    }
    lines = render._format_credential_attempts_records(record, "txt")
    assert "same:one (Jobs:7)" in lines[0]
    assert "same:two (Jobs:Access Denied)" in lines[1]
    assert "99" not in "\n".join(lines)


@pytest.mark.parametrize("fault", [False, True])
def test_airflow_auth_collects_access_in_each_verified_session(monkeypatch: pytest.MonkeyPatch, fault: bool) -> None:
    from redposture_core.modules.airflow import actions

    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda _factory, _gen, user, _password: SimpleNamespace(
            state="valid", username=user, bearer_token=None, error_code=None, proof_surface="api"
        ),
    )
    monkeypatch.setattr(actions, "_client_for", lambda ctx, **_kwargs: ctx.credential.username)

    def classify(client, _generation):
        if fault and client == "two":
            raise TimeoutError("resource timeout")
        access = SimpleNamespace(
            status="allowed" if client == "one" else "denied",
            count=7 if client == "one" else None,
            http_status=200 if client == "one" else 403,
            error=None,
        )
        return SimpleNamespace(dags=access, keys=access, connections=access)

    monkeypatch.setattr(actions, "classify_capabilities", classify)
    results = [
        actions.auth_record(
            SimpleNamespace(credential=SimpleNamespace(username=user, password="p", source="default")),
            {"auth_required": True, "api_generation": "v1"},
        )
        for user in ("one", "two")
    ]
    assert results[0]["credential_capabilities"]["authenticated_dags_count"] == 7
    if fault:
        assert results[1]["credential_capabilities"] == {"capability_error": "resource timeout"}
        assert not results[1].get("_credential_capabilities_pending")
    else:
        assert results[1]["credential_capabilities"]["authenticated_dags_access"] == "denied"
    assert all(result["provided_credentials_ok"] is True for result in results)


def test_minio_auth_keeps_admin_evidence_for_each_valid_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.minio import actions

    monkeypatch.setattr(actions, "_client_for", lambda ctx, _credential: ctx.credential.username)
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda client, **_kwargs: SimpleNamespace(state="valid", access_key=client, error_code=None),
    )
    monkeypatch.setattr(
        actions,
        "classify_admin_capability",
        lambda client: SimpleNamespace(
            capability="confirmed" if client == "one" else "not_confirmed", identity_kind="user", evidence={}
        ),
    )
    results = [
        actions.auth_record(
            SimpleNamespace(
                args=SimpleNamespace(), credential=SimpleNamespace(username=user, password="p", source="default")
            ),
            {"auth_required": True},
        )
        for user in ("one", "two")
    ]
    assert results[0]["credential_capabilities"]["admin_capability"] == "confirmed"
    assert results[1]["credential_capabilities"]["admin_capability"] == "not_confirmed"


@pytest.mark.parametrize("fault", [False, True])
def test_clickhouse_auth_snapshots_capabilities_before_other_sessions(
    monkeypatch: pytest.MonkeyPatch, fault: bool
) -> None:
    from redposture_core.modules.clickhouse import actions
    from redposture_core.stage_runtime import AuditCredentialRun

    monkeypatch.setattr(actions, "_ch_transport_from_context", lambda _ctx: (None, None))
    monkeypatch.setattr(
        actions,
        "_open_operational_session",
        lambda _protocol, _host, _port, _timeout, user, _password, database, **_kwargs: (
            SimpleNamespace(username=user, database=database),
            None,
        ),
    )

    def capabilities(session, **_kwargs):
        if fault and session.username == "two":
            raise OSError("grants interrupted")
        return session.username == "one", False, False, 7 if session.username == "one" else 0, None, None

    monkeypatch.setattr(actions, "_collect_capabilities", capabilities)
    state = actions.ClickHouseLifecycleState()
    state.auth_required = True
    for user in ("one", "two"):
        ctx = SimpleNamespace(
            args=SimpleNamespace(timeout=1, retries=0),
            lifecycle_state=state,
            host="localhost",
            port=8123,
            credential=AuditCredentialRun(user, "p", source="default"),
        )
        actions.authenticate_clickhouse(ctx, {"status": "auth_required"}, {"protocol": "http", "database": "default"})
    assert state.auth_attempts[0]["credential_capabilities"]["database_count"] == 7
    if fault:
        assert state.auth_attempts[1]["credential_capabilities"] == {"capability_error": "grants interrupted"}
    else:
        assert state.auth_attempts[1]["credential_capabilities"]["database_count"] == 0
    assert state.auth_attempts[1]["ok"] is True


def test_grafana_auth_fetches_datasources_for_every_accepted_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.grafana import actions
    from redposture_core.stage_runtime import AuditCredentialRun

    monkeypatch.setattr(actions, "_activate_grafana_transport", lambda _state: None)
    monkeypatch.setattr(actions, "_verify_credentials", lambda *_args: (True, None))
    monkeypatch.setattr(
        actions,
        "_fetch_datasources",
        lambda *_args, auth_header: (
            ([{"name": "metrics"}], None, 200)
            if auth_header == actions._auth_header("one", "p")
            else (None, "access denied", 403)
        ),
    )
    state = actions.GrafanaLifecycleState()
    for user in ("one", "two"):
        ctx = SimpleNamespace(
            args=SimpleNamespace(timeout=1, retries=0, defcreds=True),
            lifecycle_state=state,
            host="localhost",
            port=3000,
            credential=AuditCredentialRun(user, "p", source="default"),
        )
        actions.authenticate_grafana(ctx, {"auth_required": True, "server_version": "13.0.0"}, {"check_urls": []})
    assert state.auth_attempts[0]["credential_capabilities"]["datasource_count"] == 1
    assert state.auth_attempts[1]["credential_capabilities"]["datasource_count"] is None
    assert state.auth_attempts[1]["credential_capabilities"]["datasource_error"] == "access denied"
    assert state.effective_username == "one"


@pytest.mark.parametrize("fault", [False, True])
def test_mongodb_identity_retains_own_inventory_and_closes_sessions(
    monkeypatch: pytest.MonkeyPatch, fault: bool
) -> None:
    from redposture_core.modules.mongodb import actions

    closed = []

    class Client:
        def __init__(self, user):
            self.user = user
            self.client = self

        def hello(self):
            return {}

        def run_command(self, _db, _command):
            return {"authInfo": {"authenticatedUsers": [{"user": self.user, "db": "admin"}]}}

        def list_database_names(self):
            return ["app"] if self.user == "one" else []

        def list_collection_names(self, _db):
            if fault:
                raise RuntimeError("not authorized on app")
            return ["events", "users"]

        def close(self):
            closed.append(self.user)

    monkeypatch.setattr(actions, "_open_client", lambda *_args, username, **_kwargs: Client(username))
    _selected, rows = actions._try_credentials(
        "localhost",
        27017,
        1,
        auth_db="admin",
        credential_candidates=[{"username": user, "password": "p"} for user in ("one", "two")],
    )
    assert rows[0]["credential_capabilities"]["database_count"] == 1
    assert rows[0]["credential_capabilities"]["collection_count"] == (None if fault else 2)
    assert rows[0]["ok"] is True
    assert rows[1]["credential_capabilities"]["database_count"] == 0
    assert closed == ["one", "two"]


@pytest.mark.parametrize("database_error", [False, True])
def test_postgres_auth_reads_each_pair_capabilities_without_sampling_rows(
    monkeypatch: pytest.MonkeyPatch, database_error: bool
) -> None:
    from contextlib import nullcontext

    from redposture_core.modules.postgres import actions, stage
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    def authenticate(sock, *, username, **_kwargs):
        sock["user"] = username
        return actions._PgSession(
            auth_required=True, auth_method="scram-sha-256", server_version="16.4", credential_verified=True
        )

    def privileges(sock, *, probe_readable_table_sample):
        assert probe_readable_table_sample is False
        allowed = sock["user"] == "one"
        return allowed, allowed, allowed, None, None

    monkeypatch.setattr(actions, "_pg_open_socket", lambda *_args, **_kwargs: nullcontext({}))
    monkeypatch.setattr(actions, "_pg_startup_and_auth", authenticate)
    monkeypatch.setattr(actions, "_collect_postgres_privileges", privileges)

    def databases(sock):
        if database_error and sock["user"] == "two":
            raise OSError("catalog interrupted")
        return (["app"] if sock["user"] == "one" else [], None)

    monkeypatch.setattr(actions, "_pg_query_databases", databases)
    monkeypatch.setattr(actions, "_pg_send_terminate", lambda _sock: None)
    records = [
        stage._postgres_probe_credential(
            AuditHookContext(
                SimpleNamespace(timeout=1, retries=0, defcreds=True),
                None,
                "localhost",
                5432,
                AuditCredentialRun(user, "p", source="default"),
            )
        )
        for user in ("one", "two")
    ]
    assert records[0].extra["credential_capabilities"]["superuser"] is True
    assert records[1].extra["credential_capabilities"]["superuser"] is False
    assert records[1].extra["credential_capabilities"].get("database_count") == (None if database_error else 0)
    assert records[1].extra["credential_verified"] is True


def test_missing_evidence_does_not_borrow_another_sources_rights() -> None:
    from redposture_core.credential_evidence import attempt_capabilities

    first = {"username": "same", "password": "p", "source": "provided", "credential_capabilities": {"key_count": 7}}
    second = {"username": "same", "password": "p", "source": "default", "credential_capabilities": {"key_count": 0}}
    record = {"key_count": 99, "attempted_credentials": [first, second]}
    assert attempt_capabilities(record, {"username": "same", "password": "p"}) == {}
    assert attempt_capabilities(record, {"username": "same", "password": "p", "source": "default"}) == {"key_count": 0}
    assert attempt_capabilities(record, {"credential_capabilities": {}}, selected=True) == {}
    assert attempt_capabilities({"attempted_credentials": 1, "key_count": 7}, {}, selected=True)["key_count"] == 7


def test_native_attempt_evidence_survives_audit_record_roundtrip() -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.modules.mongodb import actions

    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 27017,
            "effective_username": "one",
            "provided_password": "p",
            "credential_attempts": [
                {
                    "username": "one",
                    "password": "p",
                    "source": "default",
                    "ok": True,
                    "credential_capabilities": {"database_count": 7, "collection_count": 3},
                },
                {
                    "username": "two",
                    "password": "p",
                    "source": "default",
                    "ok": True,
                    "credential_capabilities": {"database_count": 0, "collection_count": 0},
                },
            ],
        }
    ).to_dict()
    lines = actions._format_credential_attempts_records(record, "txt")
    assert "[+] one:p (DBs:7) (collections:3)" in lines[0]
    assert "[+] two:p (DBs:0) (collections:0)" in lines[1]
    assert record["credential_attempts"][1]["source"] == "default"


def test_postgres_verified_but_incomplete_startup_never_borrows_selected_rights() -> None:
    from redposture_core.modules.postgres import actions

    lines = actions._format_credential_attempts_records(
        {
            "host": "localhost",
            "port": 5432,
            "effective_username": "selected",
            "provided_password": "p",
            "superuser": True,
            "can_execute_commands": True,
            "database_count": 7,
            "attempted_credentials": [
                {
                    "username": "incomplete",
                    "password": "p",
                    "credential_verified": True,
                    "status": "unknown_auth",
                    "startup_complete": False,
                },
                {
                    "username": "selected",
                    "password": "p",
                    "credential_verified": True,
                    "status": "valid_credentials",
                    "startup_complete": True,
                },
            ],
        },
        "txt",
    )
    assert "[+] incomplete:p (superuser:unknown)" in lines[0]
    assert "[+] selected:p (superuser:True)" in lines[1]


def test_selected_minio_inventory_error_does_not_become_empty_safe_count() -> None:
    from redposture_core.modules.minio import render

    record = {
        "host": "localhost",
        "port": 9000,
        "credential_state": "valid",
        "credential_results": [{"access_key": "one"}],
        "credential_secret": "p",
        "admin_capability": "not_confirmed",
        "buckets": [],
        "objects_count": 0,
        "credential_capabilities": {"bucket_count": None, "objects_count": None, "inventory_error": "HTTP 403"},
    }
    line = render._format_record(record, "txt")
    assert "(buckets:unknown) (objects:unknown)" in line
    assert "(buckets:0)" not in line


def test_clickhouse_auth_metadata_does_not_execute_command(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.clickhouse import actions
    from redposture_core.stage_runtime import AuditCredentialRun

    monkeypatch.setattr(actions, "_ch_transport_from_context", lambda _ctx: (None, None))
    monkeypatch.setattr(
        actions, "_open_operational_session", lambda *_args, **_kwargs: (SimpleNamespace(database="default"), None)
    )
    monkeypatch.setattr(actions, "_query_database_count", lambda _session: (2, None))
    monkeypatch.setattr(actions, "_query_show_grants", lambda _session: (["GRANT SELECT ON *.* TO one"], None))
    monkeypatch.setattr(actions, "_query_rows", lambda *_args: ([], None))
    executions = []
    monkeypatch.setattr(actions, "_run_execute_command", lambda *_args: (executions.append("command") or "", None))
    state = actions.ClickHouseLifecycleState()
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        lifecycle_state=state,
        host="localhost",
        port=8123,
        credential=AuditCredentialRun("one", "p", source="default"),
    )
    result = actions.authenticate_clickhouse(
        ctx, {"status": "auth_required"}, {"protocol": "http", "database": "default"}
    )
    assert executions == []
    assert result["credential_capabilities"]["database_count"] == 2
    assert result["credential_capabilities"]["execute_capability"] is None


@pytest.mark.parametrize("database_available", [False, True])
def test_clickhouse_shell_legacy_path_keeps_all_pairs_metadata(
    monkeypatch: pytest.MonkeyPatch, database_available: bool
) -> None:
    from redposture_core.modules.clickhouse import actions

    def connect(_protocol, _host, _port, _timeout, username, password, *, database="default", **_kwargs):
        if (username, password) in {("admin", "admin"), ("default", "default")}:
            return SimpleNamespace(
                username=username, password=password, database=database, client=None, protocol="native"
            ), None
        return None, actions._ChProbeError(
            "Code: 516. Authentication failed", kind="auth", confirms_service=True, auth_required=True
        )

    probes = []

    def capabilities(session, *, include_database_names=True, probe_execute=True):
        if probe_execute:
            probes.append(session.username)
        return (
            session.username == "admin",
            True if probe_execute else None,
            False,
            2 if session.username == "admin" else 0,
            None,
            None,
        )

    monkeypatch.setattr(actions, "_connect_and_probe", connect)
    if not database_available:
        monkeypatch.setattr(actions, "_open_operational_session", lambda *_args, **_kwargs: (None, "connection failed"))
    monkeypatch.setattr(actions, "_collect_capabilities", capabilities)
    monkeypatch.setattr(actions, "_close_client", lambda *_args: None)
    result = actions._audit_clickhouse_host_on_protocol(
        host="localhost",
        port=9000,
        timeout=1,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="default" if database_available else "app",
        protocol="native",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )
    accepted = {a["username"]: a for a in result["credential_attempts"] if a.get("ok")}
    assert accepted["admin"]["credential_capabilities"]["database_count"] == 2
    assert accepted["default"]["credential_capabilities"]["database_count"] == 0
    assert probes == (["admin"] if database_available else [])


@pytest.mark.parametrize("api", ["v2", "v3"])
def test_etcd_metadata_timeout_keeps_confirmed_auth(monkeypatch: pytest.MonkeyPatch, api: str) -> None:
    from redposture_core.modules.etcd import actions

    def request(_host, _port, _method, path, _timeout, *, payload=None, auth_token=None, basic_auth=None, **_kwargs):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            if api != "v2":
                return 404, ""
            if basic_auth:
                raise TimeoutError("metadata timeout")
            return 401, '{"message":"authentication required"}'
        if path == "/v3/auth/status":
            return (200, '{"enabled":true}') if api == "v3" else (404, "")
        if path == "/v3/kv/range":
            if api != "v3":
                return 404, ""
            if auth_token:
                raise TimeoutError("metadata timeout")
            return 401, '{"error":"authentication required"}'
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_json_request", request)
    monkeypatch.setattr(actions, "_etcd_v3_authenticate", lambda *_args: ("own-token", None))
    monkeypatch.setattr(actions, "_etcd_v2_authenticate", lambda *_args: (True, None))
    result = actions._audit_etcd_host(
        "localhost",
        2379,
        1,
        0,
        False,
        False,
        None,
        username="one",
        password="p",
        defcreds=False,
        dump_batch=10,
        dump_delay=0,
    )
    assert result["status"] == "valid_credentials"
    assert result["credential_attempts"][0]["ok"] is True
    assert "timeout" in str(result["credential_attempts"][0]["credential_capabilities"]["key_count_error"])


def test_minio_denied_inventory_keeps_valid_pair_and_unknown_counts() -> None:
    from redposture_core.modules.minio import render

    record = {
        "host": "localhost",
        "port": 9000,
        "credential_state": "valid",
        "credential_results": [{"access_key": "one"}],
        "credential_secret": "p",
        "admin_capability": "not_confirmed",
        "bucket_count": None,
        "objects_count": None,
    }
    line = render._format_record(record, "txt")
    assert "[+] one:p (admin:False) (buckets:unknown) (objects:unknown)" in line


@pytest.mark.parametrize(
    "module", ["etcd", "mongodb", "clickhouse", "postgres", "grafana", "airflow", "minio", "jenkins"]
)
def test_runtime_history_keeps_each_success_evidence(module: str) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.cli_args import parse_args
    from redposture_core.console import Console
    from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun

    args = parse_args([module, "-t", "127.0.0.1:1234", "--defcreds"])
    stage = import_module(f"redposture_core.modules.{module}.stage")
    spec = getattr(stage, f"build_{module}_spec")(args)
    runner = AuditCommandRunner(args=args, spec=spec, logger=None, console=Console())
    first = {"credential_capabilities": {"database_count": 7}, "credential_jobs_count": 7}
    second = {"credential_capabilities": {"database_count": 0}, "credential_jobs_count": 0}
    history = [
        (
            AuditCredentialRun("same", password, source="default"),
            AuditRecord.from_mapping({"host": "127.0.0.1", "port": 1234, "status": "valid_credentials", **fields}),
        )
        for password, fields in [("one", first), ("two", second)]
    ]
    result = runner._with_attempted_credentials(history[0][1], history, force=True).to_dict()["attempted_credentials"]
    key = "credential_jobs_count" if module == "jenkins" else "credential_capabilities"
    assert result[0][key] == first[key]
    assert result[1][key] == second[key]


@pytest.mark.parametrize("module", ["airflow", "minio"])
def test_saved_json_keeps_all_successful_pairs_evidence(module: str, tmp_path) -> None:
    import json
    from dataclasses import replace

    from redposture_core.audit_models import AuditRecord
    from redposture_core.cli_args import parse_args
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun

    args = parse_args([module, "-t", "localhost:1234", "--defcreds", "--format", "json", "--no-color"])
    stage = import_module(f"redposture_core.modules.{module}.stage")
    spec = getattr(stage, f"build_{module}_spec")(args)

    def detect(_ctx):
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 1234, "status": "auth_required", "auth_required": True, "is_" + module: True},
            module=module,
        )

    def auth(ctx, record):
        return AuditRecord.from_mapping(
            {
                **record.to_dict(),
                "status": "valid_credentials",
                "provided_credentials_ok": True,
                "credential_state": "valid",
                "credential_capabilities": {"resource_count": 7 if ctx.credential.password == "one" else 0},
            },
            module=module,
        )

    spec = replace(
        spec,
        detect=detect,
        detect_async=None,
        async_detect_sync_hook=None,
        auth=auth,
        capabilities=None,
        data=lambda _ctx, record: record,
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
    )
    path = tmp_path / "result.json"
    plan = AuditCommandPlan(
        targets_by_port={1234: ("localhost",)},
        output_format="json",
        output_path=str(path),
        credential_runs=tuple(AuditCredentialRun("same", password, source="default") for password in ("one", "two")),
    )
    AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)
    text = path.read_text()
    attempts = json.loads(text)["attempted_credentials"]
    assert [(a["password"], a["credential_capabilities"]["resource_count"]) for a in attempts] == [
        ("one", 7),
        ("two", 0),
    ]
    assert "\x1b" not in text


@pytest.mark.parametrize("module", ["etcd", "mongodb"])
def test_full_runtime_ledger_wins_over_selected_native_attempt(module: str) -> None:
    actions = import_module(f"redposture_core.modules.{module}.actions")
    first = {
        "username": "one",
        "password": "p",
        "ok": True,
        "status": "valid_credentials",
        "credential_capabilities": {"key_count": 7, "database_count": 7, "collection_count": 3},
    }
    second = {
        "username": "two",
        "password": "p",
        "status": "valid_credentials",
        "credential_capabilities": {"key_count": 0, "database_count": 0, "collection_count": 0},
    }
    record = {
        "host": "localhost",
        "port": 1234,
        "effective_username": "one",
        "effective_password": "p",
        "provided_password": "p",
        "credential_attempts": [first],
        "attempted_credentials": [first, second],
    }
    lines = actions._format_credential_attempts_records(record, "txt")
    assert len(lines) == 2
    assert "[+] two:p" in lines[1]
    assert "(keys:0)" in lines[1] if module == "etcd" else "(DBs:0) (collections:0)" in lines[1]


def test_minio_selected_bucket_does_not_require_listing_all_buckets(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.minio import actions
    from redposture_core.modules.minio import enumerate as enumeration

    monkeypatch.setattr(actions, "_client_for", lambda *_args: "user")
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda *_args, **_kwargs: SimpleNamespace(state="valid_but_restricted", access_key="user", error_code=None),
    )
    monkeypatch.setattr(
        actions,
        "classify_admin_capability",
        lambda _client: SimpleNamespace(capability="not_confirmed", identity_kind="user", evidence={}),
    )
    monkeypatch.setattr(
        enumeration, "iter_buckets", lambda *_args, **_kwargs: pytest.fail("selected bucket must scope the inventory")
    )
    monkeypatch.setattr(
        enumeration,
        "iter_objects",
        lambda _client, bucket, **_kwargs: iter(["object-a", "object-b"]) if bucket == "app" else pytest.fail(bucket),
    )
    result = actions.auth_record(
        SimpleNamespace(
            args=SimpleNamespace(show_objects=True, bucket="app"),
            credential=SimpleNamespace(username="user", password="p", source="provided"),
        ),
        {"auth_required": True},
    )
    assert result["credential_capabilities"]["objects_count"] == 2


@pytest.mark.parametrize(
    "module,field",
    [
        ("etcd", "keys:0"),
        ("mongodb", "DBs:0"),
        ("clickhouse", "DBs:0"),
        ("postgres", "DBs:0"),
        ("grafana", "datasources:0"),
        ("airflow", "Dags:0"),
        ("minio", "buckets:0"),
        ("jenkins", "Jobs:0"),
    ],
)
def test_per_pair_capabilities_keep_pair_palette_and_plain_output(
    module: str, field: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from redposture_core.console import Console
    from tests.test_stage_color_renderers import _RecordingConsole

    render = import_module(f"redposture_core.modules.{module}.render")
    colorize = getattr(render, f"_render_colored_{module}_line")
    line = f"{module.upper()}\t127.0.0.1\t1234\t [+] same:two ({field})"
    console = _RecordingConsole()
    assert colorize(console, line)
    assert any("[+]" in text and color == "bright_green" for text, color in console.paint_calls)
    assert any("same:two" in text and color == "true_red" for text, color in console.paint_calls)
    assert any(field in text and color == "bright_green" for text, color in console.paint_calls)
    console = _RecordingConsole()
    assert colorize(console, line.replace("[+]", "[-]"))
    assert any("[-]" in text and color == "true_red" for text, color in console.paint_calls)
    assert any("same:two" in text and color == "white" for text, color in console.paint_calls)
    assert colorize(Console(no_color=True), line)
    output = capsys.readouterr().out
    assert "same:two" in output and field in output and "\x1b" not in output
