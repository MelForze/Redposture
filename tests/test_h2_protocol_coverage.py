from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from redposture_core.clients.zookeeper import (
    _ZK_ERR_NOAUTH,
    _ZK_ERR_OK,
    ZkImplementationFingerprint,
    ZkTransportConfig,
)
from redposture_core.modules.clickhouse import actions as clickhouse
from redposture_core.modules.elastic import actions as elastic
from redposture_core.modules.kafka import actions as kafka
from redposture_core.modules.keeper import actions as keeper
from redposture_core.modules.keeper.types import KeeperFingerprintCache
from redposture_core.modules.registry import actions as registry
from redposture_core.modules.zookeeper import actions as zookeeper
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext
from redposture_core.targeting import ScanTargetSpec


def _ctx(
    state: Any,
    *,
    credential: AuditCredentialRun | None = None,
    retries: int = 0,
    scheme: str | None = None,
    debug_emit: Any = None,
) -> AuditHookContext:
    return AuditHookContext(
        args=SimpleNamespace(timeout=0.1, retries=retries, debug=False, ca_file=None),
        logger=None,
        host="127.0.0.1",
        port=1234,
        credential=credential or AuditCredentialRun(),
        target=ScanTargetSpec("127.0.0.1", scheme=scheme),
        debug_emit=debug_emit,
        lifecycle_state=state,
    )


def _clickhouse_options(*, database: str = "default") -> dict[str, Any]:
    return {
        "database": database,
        "protocol": "native",
        "show_databases": False,
        "show_tables": False,
        "show_columns": False,
        "table_targets": [],
        "table_columns": [],
        "dump_table_rows": False,
        "dump_row_limit": None,
        "execute_command": None,
        "sql_command": None,
        "show_databases_limit": None,
        "show_tables_limit": None,
        "show_columns_limit": None,
    }


def _registry_options(*, nexus: bool = False) -> dict[str, Any]:
    return {
        "docker": False,
        "show_images": False,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "harbor": False,
        "gitlab": False,
        "nexus": nexus,
        "assets": False,
        "inspect": False,
        "image": None,
        "download": False,
        "download_dir": ".",
        "console": SimpleNamespace(),
    }


def _zookeeper_options(**overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "show_znodes": False,
        "dump": False,
        "dump_limit": None,
        "query_znode": None,
        "max_znodes": 20,
        "enum_workers": 2,
        "transport_config": None,
    }
    options.update(overrides)
    return options


class _CloseTrackingClient:
    def __init__(self, *, close_error: bool = False) -> None:
        self.close_calls = 0
        self.disconnect_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error:
            raise OSError("close failed")

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        if self.close_error:
            raise OSError("disconnect failed")


def test_clickhouse_detect_retries_protocols_then_accepts_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = clickhouse.ClickHouseLifecycleState()
    calls: list[str] = []
    answers = iter(
        [
            (None, "connection timeout"),
            (None, "connection refused"),
            (None, "DB::Exception: Code: 210"),
        ]
    )

    def fake_probe(protocol: str, *_args: Any, **_kwargs: Any) -> tuple[Any, str | None]:
        calls.append(protocol)
        return next(answers)

    monkeypatch.setattr(clickhouse, "_protocol_attempt_order", lambda _protocol: ["native", "http"])
    monkeypatch.setattr(clickhouse, "_connect_and_probe", fake_probe)
    monkeypatch.setattr(clickhouse.time, "sleep", lambda _delay: None)

    record = clickhouse.detect_clickhouse(_ctx(state, retries=1), _clickhouse_options())

    assert calls == ["native", "http", "native"]
    assert record["status"] == "detected"
    assert record["is_clickhouse"] is True
    assert state.selected_protocol == "native"
    assert state.auth_required is None


def test_clickhouse_collect_reopens_database_and_reports_open_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_client = _CloseTrackingClient()
    state = clickhouse.ClickHouseLifecycleState(
        anonymous_session=clickhouse._ChSession("native", old_client, "default", "", "default"),
        selected_protocol="native",
        auth_required=False,
    )
    reopen_calls: list[tuple[str, str]] = []

    def fake_reopen(
        _protocol: str,
        _host: str,
        _port: int,
        _timeout: float,
        username: str,
        _password: str,
        database: str,
    ) -> tuple[None, str]:
        reopen_calls.append((username, database))
        return None, "connection reset"

    monkeypatch.setattr(clickhouse, "_open_operational_session", fake_reopen)

    result = clickhouse.collect_clickhouse_data(
        _ctx(state),
        {"status": "open_no_auth", "is_clickhouse": True},
        _clickhouse_options(database="analytics"),
    )

    assert reopen_calls == [("default", "analytics")]
    assert old_client.disconnect_calls == 1
    assert state.anonymous_session is None
    assert result["error"] == "connection reset"


def test_clickhouse_lifecycle_close_deduplicates_and_swallows_close_errors() -> None:
    shared = _CloseTrackingClient(close_error=True)
    state = clickhouse.ClickHouseLifecycleState(
        anonymous_session=clickhouse._ChSession("http", shared, "default", "", "default"),
        credential_sessions={
            ("admin", "secret", "provided"): clickhouse._ChSession("http", shared, "admin", "secret", "default")
        },
    )

    state.close()

    assert shared.close_calls == 1
    assert state.anonymous_session is None
    assert state.credential_sessions == {}


def test_keeper_non_zookeeper_and_apache_fingerprint_short_circuit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = {
        **_zookeeper_options(),
        "show_znodes_limit": None,
        "keeper_probe_cache": KeeperFingerprintCache(),
        "tls": False,
        "no_tls": True,
        "insecure": False,
        "ca_file": None,
        "tls_cert": None,
        "tls_key": None,
    }
    state = keeper.KeeperLifecycleState(ZkTransportConfig(mode="plaintext"))
    ctx = _ctx(state)
    monkeypatch.setattr(
        keeper.zookeeper_actions,
        "detect_zookeeper",
        lambda *_args, **_kwargs: {
            "status": "fail",
            "is_zookeeper": False,
            "auth_required": None,
            "error": "connection timeout",
        },
    )

    failed = keeper.detect_keeper(ctx, options)

    assert failed["status"] == "fail"
    assert failed["is_keeper"] is None
    assert failed["error"] == "connection timeout"

    state.zookeeper_state.selected_transport_config = ZkTransportConfig(mode="plaintext")
    monkeypatch.setattr(
        keeper.zookeeper_actions,
        "detect_zookeeper",
        lambda *_args, **_kwargs: {
            "status": "open_no_auth",
            "is_zookeeper": True,
            "auth_required": False,
        },
    )
    monkeypatch.setattr(
        options["keeper_probe_cache"],
        "get_or_probe",
        lambda *_args, **_kwargs: ZkImplementationFingerprint(
            "apache-zookeeper",
            False,
            "confirmed",
            version="3.9.3",
        ),
    )

    apache = keeper.detect_keeper(ctx, options)
    auth = keeper.authenticate_keeper(ctx, apache, options)
    data = keeper.collect_keeper_data(ctx, auth, options)

    assert apache["status"] == "not_keeper"
    assert apache["is_zookeeper_compatible"] is True
    assert auth == apache
    assert data == apache


def test_registry_detect_and_authenticate_nexus_only_with_transient_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = registry.RegistryLifecycleState()
    options = _registry_options(nexus=True)
    credential = AuditCredentialRun("admin", "secret", source="provided")
    ctx = _ctx(state, credential=credential, retries=1)
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *_args, **_kwargs: (404, b"not found", {}, None),
    )
    nexus_answers = iter(
        [
            ({"version": "3.75"}, None),
            (None, "connection timeout"),
            ({"version": "3.75", "authenticated": True}, None),
        ]
    )
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: next(nexus_answers))
    monkeypatch.setattr(registry.time, "sleep", lambda _delay: None)

    detected = registry.detect_registry(ctx, options)
    authenticated = registry.authenticate_registry(ctx, detected, options)

    assert detected["status"] == "open_no_auth"
    assert detected["is_nexus"] is True
    assert authenticated["status"] == "invalid_credentials_anonymous"
    assert authenticated["auth_transport_attempts"] == 2
    assert authenticated["provided_credentials_ok"] is False
    key = ("admin", "secret", None, "provided")
    assert state.credential_nexus[key][0] == {"version": "3.75", "authenticated": True}


def test_registry_nexus_definitive_rejection_and_data_retry_preserve_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _registry_options(nexus=True)
    credential = AuditCredentialRun(token="bad-token", source="provided")
    ctx = _ctx(registry.RegistryLifecycleState(), credential=credential, retries=2)
    ctx.lifecycle_state.anonymous_probe = (404, b"", {}, None)
    ctx.lifecycle_state.anonymous_nexus = (None, "authentication required")
    prior = {
        "status": "auth_required",
        "is_registry": True,
        "is_nexus": True,
        "auth_required": True,
        "probe_status": 404,
    }
    nexus_calls = 0

    def reject_nexus(*_args: Any, **_kwargs: Any) -> tuple[None, str]:
        nonlocal nexus_calls
        nexus_calls += 1
        return None, "authentication required"

    monkeypatch.setattr(registry, "_fetch_nexus_info", reject_nexus)

    rejected = registry.authenticate_registry(ctx, prior, options)

    assert nexus_calls == 1
    assert rejected["status"] == "auth_required"
    assert rejected["provided_credentials_ok"] is False

    anonymous_ctx = _ctx(ctx.lifecycle_state, retries=1)
    anonymous_ctx.lifecycle_state.anonymous_probe = (
        200,
        b"{}",
        {"docker-distribution-api-version": "registry/2.0"},
        None,
    )
    core_calls = 0

    def fake_core(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal core_calls
        core_calls += 1
        assert kwargs["username"] is None
        assert kwargs["initial_probe"] is anonymous_ctx.lifecycle_state.anonymous_probe
        return {
            "status": "fail",
            "is_registry": False,
            "error": None,
            "images_error": "connection timeout" if core_calls == 1 else None,
        }

    monkeypatch.setattr(registry, "_audit_registry_host_core", fake_core)
    monkeypatch.setattr(registry.time, "sleep", lambda _delay: None)
    collected = registry.collect_registry_data(
        anonymous_ctx,
        {"status": "invalid_credentials_anonymous", "is_registry": True, "auth_required": False},
        options,
    )

    assert core_calls == 2
    assert collected["data_transport_attempts"] == 2
    assert collected["status"] == "invalid_credentials_anonymous"
    assert collected["is_registry"] is True
    assert collected["detection_preserved"] is True


def test_kafka_detect_caches_anonymous_protocol_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = kafka.KafkaLifecycleState()

    def fake_audit(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        lifecycle_state = kwargs["lifecycle_state"]
        lifecycle_state.anonymous_metadata = {"topic_map": {"orders": 2}}
        return {
            "is_kafka": True,
            "status": "auth_required",
            "auth_required": True,
            "transport_mode": "tls",
            "auth_flow": "sasl_fallback",
        }

    monkeypatch.setattr(kafka, "_audit_kafka_host", fake_audit)
    record = kafka.detect_kafka(
        _ctx(state),
        {
            "max_messages": 10,
        },
    )

    assert record["is_kafka"] is True
    assert state.is_kafka is True
    assert state.auth_required is True
    assert state.transport_mode == "tls"
    assert state.sasl_first is True
    assert state.anonymous_metadata == {"topic_map": {"orders": 2}}


@pytest.mark.parametrize(
    ("auth_required", "ok", "source", "expected_status", "expected_ok"),
    [
        (True, True, "default", "weak_default_creds", None),
        (False, False, "provided", "invalid_credentials_anonymous", False),
        (True, False, "provided", "auth_required", False),
    ],
)
def test_kafka_authentication_outcomes_and_metadata_cache(
    monkeypatch: pytest.MonkeyPatch,
    auth_required: bool,
    ok: bool,
    source: str,
    expected_status: str,
    expected_ok: bool | None,
) -> None:
    state = kafka.KafkaLifecycleState(auth_required=auth_required, transport_mode="tls", sasl_first=True)
    credential = AuditCredentialRun("alice", "secret", source=source)
    metadata = {"topic_map": {"orders": 3}} if ok else None
    monkeypatch.setattr(
        kafka,
        "_authenticate_and_fetch_metadata",
        lambda *_args, **_kwargs: (ok, metadata, None if ok else "SASL_AUTHENTICATION_FAILED", "tls"),
    )

    result = kafka.authenticate_kafka(
        _ctx(state, credential=credential),
        {"status": "auth_required" if auth_required else "open_no_auth"},
        {},
    )

    assert result["status"] == expected_status
    assert result["provided_credentials_ok"] is expected_ok
    if ok:
        assert state.credential_metadata[("alice", "secret", source)] == metadata
        assert result["topic_count"] == 1
    else:
        assert state.credential_metadata == {}


def test_kafka_collect_uses_cached_metadata_for_dump_and_acl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = {"topic_map": {"orders": 2}}
    state = kafka.KafkaLifecycleState(
        auth_required=True,
        transport_mode="tls",
        sasl_first=True,
        credential_metadata={("alice", "secret", "provided"): metadata},
    )
    credential = AuditCredentialRun("alice", "secret", source="provided")
    dump_kwargs: dict[str, Any] = {}

    def fake_dump(**kwargs: Any) -> tuple[dict[str, list[str]], dict[str, str]]:
        dump_kwargs.update(kwargs)
        return {"orders": ["p0@1 hello"]}, {"orders": "connection reset"}

    monkeypatch.setattr(kafka, "_read_dump_topics", fake_dump)
    monkeypatch.setattr(
        kafka,
        "_probe_kafka_acl_state",
        lambda **_kwargs: ({"orders": {"read": True, "write": False}}, {"create": False, "delete": None}),
    )
    result = kafka.collect_kafka_data(
        _ctx(state, credential=credential),
        {"status": "valid_credentials", "transport_mode": "tls", "error": "prior warning"},
        {
            "show_topics": True,
            "show_topics_limit": 1,
            "query_topic": "orders",
            "dump": True,
            "max_messages": 5,
            "max_messages_explicit": True,
            "probe_write": True,
        },
    )

    assert dump_kwargs["bootstrap_metadata"] is metadata
    assert dump_kwargs["sasl_first"] is True
    assert result["query_topic_value"] == "orders (partitions:2)"
    assert result["topic_messages"] == ["p0@1 hello"]
    assert result["topic_read_error"] == "connection reset"
    assert result["cluster_permissions"] == {"create": False, "delete": None}
    assert result["error"] == "prior warning; connection reset"


def test_kafka_collect_anonymous_without_metadata_reports_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = kafka.KafkaLifecycleState(auth_required=False)
    monkeypatch.setattr(
        kafka,
        "_probe_kafka_acl_state",
        lambda **_kwargs: ({}, {"create": None, "delete": None}),
    )

    result = kafka.collect_kafka_data(
        _ctx(state),
        {"status": "open_no_auth", "topic_count": None},
        {
            "show_topics": False,
            "show_topics_limit": None,
            "query_topic": "missing",
            "dump": True,
            "max_messages": 2,
            "max_messages_explicit": False,
            "probe_write": False,
        },
    )

    assert result["query_topic_value"] == "missing:<not available>"
    assert result["dump_error"] == "topic metadata unavailable"
    assert result["topic_read_error"] == "topic metadata unavailable"
    assert result["cluster_permissions"] is None


def test_elastic_detect_auth_and_full_data_collection_use_cached_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = elastic.ElasticLifecycleState()
    credential = AuditCredentialRun(token="api-key", source="provided")
    ctx = _ctx(state, credential=credential, scheme="http")
    monkeypatch.setattr(
        elastic,
        "_audit_elastic_host",
        lambda *_args, **kwargs: {
            "is_elastic": True,
            "status": "auth_required",
            "auth_required": True,
            "scheme": kwargs["preferred_scheme"],
            "insecure_effective": False,
            "server_version": None,
        },
    )
    monkeypatch.setattr(
        elastic,
        "_verify_authenticate",
        lambda *_args, **_kwargs: (True, None, "elastic"),
    )
    monkeypatch.setattr(
        elastic,
        "_resolve_server_version_with_auth",
        lambda *_args, **_kwargs: ("8.18.1", None),
    )

    detected = elastic.detect_elastic(ctx, {})
    authenticated = elastic.authenticate_elastic(ctx, detected, {})
    cached_headers = state.auth_headers[(None, None, "api-key", "provided")]
    assert detected["scheme"] == "http"
    assert authenticated["status"] == "valid_credentials"
    assert authenticated["server_version"] == "8.18.1"
    assert cached_headers["Authorization"] == "ApiKey api-key"

    seen_headers: list[dict[str, str]] = []

    def capture(result: Any):
        def callback(*_args: Any, **kwargs: Any) -> Any:
            seen_headers.append(kwargs["auth_headers"])
            return result

        return callback

    monkeypatch.setattr(elastic, "_check_privileges", capture((True, True, False, False, "rights warning")))
    monkeypatch.setattr(elastic, "_verify_api_key_probe", capture(("valid", "api key warning")))
    monkeypatch.setattr(
        elastic,
        "_fetch_cat_endpoints",
        capture((["/_cat/indices"], "endpoint warning", [{"path": "/_cat/indices"}])),
    )
    monkeypatch.setattr(elastic, "_fetch_cat_plugins", capture(([{"name": "analysis-icu"}], None)))
    monkeypatch.setattr(
        elastic,
        "_fetch_cluster_data",
        capture(({"status": "yellow"}, [{"name": "node-1"}], "cluster warning")),
    )
    monkeypatch.setattr(
        elastic,
        "_fetch_cluster_misconfig_findings",
        capture(([{"key": "network.host", "value": "0.0.0.0"}], None)),
    )
    monkeypatch.setattr(elastic, "_fetch_security_users", capture(([{"username": "elastic"}], None)))
    monkeypatch.setattr(
        elastic,
        "_collect_discover_results",
        capture(([{"index": "secrets", "hits": 1}], "discover warning")),
    )

    result = elastic.collect_elastic_data(
        ctx,
        authenticated,
        {
            "show_endpoints": True,
            "show_plugins": True,
            "show_cluster": True,
            "show_users": True,
            "discover": True,
        },
    )

    assert len(seen_headers) == 8
    assert all(headers is cached_headers for headers in seen_headers)
    assert result["access_level"] == "more_than_read"
    assert result["api_key_probe_status"] == "valid"
    assert result["cat_plugins"] == [{"name": "analysis-icu"}]
    assert result["discover_results"] == [{"index": "secrets", "hits": 1}]
    assert result["error"] == ("rights warning; api key warning; endpoint warning; cluster warning; discover warning")


@pytest.mark.parametrize(
    ("auth_valid", "auth_required", "expected_status"),
    [
        (False, False, "invalid_credentials_anonymous"),
        (None, False, "open_no_auth"),
        (False, True, "auth_required"),
        (None, None, "unknown_auth"),
    ],
)
def test_elastic_authentication_fallback_statuses(
    monkeypatch: pytest.MonkeyPatch,
    auth_valid: bool | None,
    auth_required: bool | None,
    expected_status: str,
) -> None:
    state = elastic.ElasticLifecycleState()
    credential = AuditCredentialRun("elastic", "bad", source="provided")
    monkeypatch.setattr(
        elastic,
        "_verify_authenticate",
        lambda *_args, **_kwargs: (auth_valid, "authentication failed", None),
    )

    result = elastic.authenticate_elastic(
        _ctx(state, credential=credential),
        {
            "status": "auth_required",
            "auth_required": auth_required,
            "scheme": "https",
            "insecure_effective": True,
            "server_version": "8.18.1",
        },
        {},
    )

    assert result["status"] == expected_status
    assert result["error"] is None if expected_status == "invalid_credentials_anonymous" else "authentication failed"


def test_zookeeper_detect_retries_then_keeps_anonymous_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Any] = []

    class FakeClient:
        selected_transport = "plaintext"

        def __init__(self, fail: bool) -> None:
            self.fail = fail
            self.close_calls = 0

        def connect(self) -> None:
            if self.fail:
                raise TimeoutError("timed out")

        def get_children2(self, _path: str) -> tuple[list[str], int, dict[str, Any]]:
            return ["app"], _ZK_ERR_NOAUTH, {}

        def close(self) -> None:
            self.close_calls += 1

    def fake_client(*_args: Any, **_kwargs: Any) -> FakeClient:
        client = FakeClient(fail=not created)
        created.append(client)
        return client

    state = zookeeper.ZooKeeperLifecycleState()
    monkeypatch.setattr(zookeeper, "_zookeeper_lifecycle_client", fake_client)
    monkeypatch.setattr(
        zookeeper,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(zookeeper.time, "sleep", lambda _delay: None)

    result = zookeeper.detect_zookeeper(_ctx(state, retries=1), _zookeeper_options())

    assert len(created) == 2
    assert created[0].close_calls == 1
    assert created[1].close_calls == 0
    assert state.anonymous_client is created[1]
    assert state.root_children == ["app"]
    assert result["status"] == "auth_required"
    assert result["is_zookeeper"] is True


def test_zookeeper_auth_retries_transient_then_caches_valid_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Any] = []

    class FakeClient:
        def __init__(self, transient: bool) -> None:
            self.transient = transient
            self.close_calls = 0

        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str) -> tuple[bool, str | None]:
            if self.transient:
                return False, "OPERATIONTIMEOUT"
            return True, None

        def get_children2(self, _path: str) -> tuple[list[str], int, dict[str, Any]]:
            return [], _ZK_ERR_OK, {}

        def close(self) -> None:
            self.close_calls += 1

    def fake_client(*_args: Any, **_kwargs: Any) -> FakeClient:
        client = FakeClient(transient=not created)
        created.append(client)
        return client

    state = zookeeper.ZooKeeperLifecycleState(root_err=_ZK_ERR_NOAUTH, auth_required=True)
    credential = AuditCredentialRun("digest", "secret", source="provided")
    ctx = _ctx(state, credential=credential, retries=1)
    monkeypatch.setattr(zookeeper, "_zookeeper_lifecycle_client", fake_client)
    monkeypatch.setattr(zookeeper.time, "sleep", lambda _delay: None)

    result = zookeeper.authenticate_zookeeper(
        ctx,
        {"status": "auth_required", "is_zookeeper": True},
        _zookeeper_options(),
    )

    assert len(created) == 2
    assert created[0].close_calls == 1
    assert created[1].close_calls == 0
    assert state.credential_clients[("digest", "secret", "provided")] is created[1]
    assert result["status"] == "valid_credentials"
    assert result["credential_verdict"] == "valid"


def test_zookeeper_definitive_rejection_and_anonymous_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectedClient:
        def __init__(self) -> None:
            self.closed = False

        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str) -> tuple[bool, str]:
            return False, "AUTHFAILED"

        def close(self) -> None:
            self.closed = True

    rejected_client = RejectedClient()
    monkeypatch.setattr(zookeeper, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: rejected_client)
    credential = AuditCredentialRun("digest", "bad", source="provided")
    state = zookeeper.ZooKeeperLifecycleState(root_err=_ZK_ERR_OK, auth_required=False)

    result = zookeeper.authenticate_zookeeper(
        _ctx(state, credential=credential, retries=3),
        {"status": "open_no_auth", "is_zookeeper": True},
        _zookeeper_options(),
    )

    assert rejected_client.closed is True
    assert result["status"] == "invalid_credentials_anonymous"
    assert result["provided_credentials_ok"] is False
    assert result["error"] is None


def test_zookeeper_collect_reopens_after_transient_capability_and_records_dump_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def __init__(self, name: str) -> None:
            self.name = name
            self.close_calls = 0

        def connect(self) -> None:
            return

        def get_data(self, path: str) -> tuple[bytes, int, dict[str, Any]]:
            if path == "/a":
                return b"value", _ZK_ERR_OK, {}
            return b"", _ZK_ERR_NOAUTH, {}

        def close(self) -> None:
            self.close_calls += 1

    old = FakeClient("old")
    reopened = FakeClient("reopened")
    state = zookeeper.ZooKeeperLifecycleState(
        anonymous_client=old,
        root_children=["a", "b"],
        root_err=_ZK_ERR_OK,
        auth_required=False,
    )
    capability_calls = 0

    def fake_capability(*_args: Any, **_kwargs: Any) -> tuple[bool | None, bool | None, str | None]:
        nonlocal capability_calls
        capability_calls += 1
        if capability_calls == 1:
            return None, None, "OPERATIONTIMEOUT"
        return True, False, None

    monkeypatch.setattr(zookeeper, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: reopened)
    monkeypatch.setattr(zookeeper, "_probe_znode_create_delete", fake_capability)
    monkeypatch.setattr(
        zookeeper,
        "_enumerate_zookeeper_lifecycle",
        lambda *_args, **_kwargs: (
            ["/b", "/a"],
            2,
            False,
            {"/a": {"data_length": 5}, "/b": {"data_length": 0}},
            None,
        ),
    )
    monkeypatch.setattr(zookeeper.time, "sleep", lambda _delay: None)

    result = zookeeper.collect_zookeeper_data(
        _ctx(state, retries=1),
        {"status": "open_no_auth", "is_zookeeper": True, "stage_attempts": {"detect_protocol": 1}},
        _zookeeper_options(show_znodes=True, dump=True, dump_limit=2),
    )

    assert capability_calls == 2
    assert old.close_calls == 1
    assert state.anonymous_client is reopened
    assert result["attempts"] == 2
    assert result["znodes"] == ["/a", "/b"]
    assert result["znode_values"] == ["/a:value", "/b:<Access Denied>"]
    assert result["dump_error"] == "NOAUTH"
    assert result["stage_attempts"] == {
        "detect_protocol": 1,
        "access_capabilities": 2,
        "data": 2,
    }


def test_zookeeper_lifecycle_close_deduplicates_and_ignores_oserror() -> None:
    class BrokenClient:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            raise OSError("close failed")

    shared = BrokenClient()
    state = zookeeper.ZooKeeperLifecycleState(
        anonymous_client=cast(Any, shared),
        credential_clients={("user", "pass", "provided"): cast(Any, shared)},
    )

    state.close()

    assert shared.close_calls == 1
    assert state.anonymous_client is None
    assert state.credential_clients == {}
