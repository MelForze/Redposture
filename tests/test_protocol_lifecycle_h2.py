from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.elastic import actions as elastic_actions
from redposture_core.modules.elastic import stage as elastic_stage
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kafka import stage as kafka_stage
from redposture_core.modules.zookeeper import actions as zookeeper_actions
from redposture_core.modules.zookeeper import stage as zookeeper_stage
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
)


def _run_one_target(args, spec, port: int, credential_runs: tuple[AuditCredentialRun, ...]):
    plan = AuditCommandPlan(
        targets_by_port={port: ("service.internal",)},
        credential_runs=credential_runs,
        output_format="json",
        workers=1,
    )
    return AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)


def test_kafka_lifecycle_classifies_once_then_authenticates_until_success_and_dumps_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_topics=True,
        dump=True,
        max_messages=2,
        topic="orders",
        probe_write=False,
    )
    spec = kafka_stage.build_kafka_spec(args)
    events: list[str] = []

    class _Socket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def close(self) -> None:
            return

    monkeypatch.setattr(kafka_actions, "open_kafka_socket", lambda *_args, **_kwargs: (_Socket(), "plaintext"))
    monkeypatch.setattr(
        kafka_actions,
        "_probe_apiversions",
        lambda *_args, **_kwargs: (events.append("detect:ApiVersions") or True, None, None),
    )
    monkeypatch.setattr(
        kafka_actions,
        "_fetch_metadata",
        lambda *_args, **_kwargs: ({"auth_required": True, "error_codes": [29], "topic_map": {}}, None),
    )

    def _authenticate(_host, _port, _timeout, username, _password, **_kwargs):
        events.append(f"auth:{username}")
        if username == "good":
            return True, {"auth_required": False, "topic_map": {"orders": 1}}, None, "plaintext"
        return False, None, "authentication failed", "plaintext"

    monkeypatch.setattr(kafka_actions, "_authenticate_and_fetch_metadata", _authenticate)
    monkeypatch.setattr(
        kafka_actions,
        "_read_dump_topics",
        lambda **_kwargs: (events.append("data:dump") or {"orders": ["p0@1 payload"]}, {}),
    )
    monkeypatch.setattr(
        kafka_actions,
        "_probe_kafka_acl_state",
        lambda **_kwargs: ({}, {"create": None, "delete": None}),
    )

    result = _run_one_target(
        args,
        spec,
        9092,
        (
            AuditCredentialRun(username="bad", password="bad", source="file"),
            AuditCredentialRun(username="good", password="good", source="file"),
            AuditCredentialRun(username="unused", password="unused", source="file"),
        ),
    )

    assert events == ["detect:ApiVersions", "auth:bad", "auth:good", "data:dump"]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["dump_results"] == {"orders": ["p0@1 payload"]}


def test_elastic_lifecycle_detect_is_anonymous_and_actions_use_only_selected_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        endpoints=True,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
        ca_file=None,
    )
    spec = elastic_stage.build_elastic_spec(args)
    events: list[str] = []

    def _detect(*call_args, **_kwargs):
        username, password, token = call_args[4:7]
        events.append("detect:anonymous")
        assert (username, password, token) == (None, None, None)
        return {
            "timestamp": "2026-07-16T00:00:00Z",
            "host": "service.internal",
            "port": 9200,
            "is_elastic": True,
            "status": "auth_required",
            "auth_required": True,
            "server_version": "8.17.3",
            "scheme": "http",
            "insecure_effective": False,
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
            "detect_confidence": "high",
            "detect_signals": ["root_version_shape"],
            "detect_probe_trace": [{"path": "/", "status": 401, "scheme": "http"}],
            "error": None,
        }

    monkeypatch.setattr(elastic_actions, "_audit_elastic_host", _detect)

    auth_attempts = 0

    def _probe_auth(*_args, **kwargs):
        nonlocal auth_attempts
        auth_attempts += 1
        authorization = str(kwargs["auth_headers"].get("Authorization") or "")
        events.append(f"auth:{auth_attempts}")
        assert authorization.startswith("Basic ")
        return elastic_actions.ElasticAuthProbeResult(
            valid=auth_attempts == 2,
            error=None if auth_attempts == 2 else "authentication failed",
            username="good" if auth_attempts == 2 else None,
            status=200 if auth_attempts == 2 else 401,
            endpoint="/_security/_authenticate",
            detail=None,
        )

    monkeypatch.setattr(elastic_actions, "_probe_authenticate", _probe_auth)
    monkeypatch.setattr(
        elastic_actions,
        "_check_privileges",
        lambda *_args, **_kwargs: (True, False, False, False, None),
    )

    def _fetch_endpoints(*_args, **kwargs):
        events.append("data:endpoints")
        assert str(kwargs["auth_headers"].get("Authorization") or "").startswith("Basic ")
        return ["/_cluster/health"], None, []

    monkeypatch.setattr(elastic_actions, "_fetch_cat_endpoints", _fetch_endpoints)

    result = _run_one_target(
        args,
        spec,
        9200,
        (
            AuditCredentialRun(username="bad", password="bad", source="file"),
            AuditCredentialRun(username="good", password="good", source="file"),
            AuditCredentialRun(username="unused", password="unused", source="file"),
        ),
    )

    assert events == ["detect:anonymous", "auth:1", "auth:2", "data:endpoints"]
    assert result.records[0]["server_version"] == "8.17.3"
    assert result.records[0]["cat_endpoints"] == ["/_cluster/health"]


def test_zookeeper_lifecycle_reuses_anonymous_detect_and_runs_selected_data_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_znodes=True,
        dump=True,
        znode=None,
        max_znodes=10,
        enum_workers=1,
    )
    spec = zookeeper_stage.build_zookeeper_spec(args)
    events: list[str] = []

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            self.username: str | None = None

        def connect(self) -> None:
            events.append("connect")

        def close(self) -> None:
            return

        def auth_digest(self, username: str, _password: str):
            self.username = username
            events.append(f"auth:{username}")
            return username == "good", None if username == "good" else "authentication failed"

        def get_children2(self, path: str):
            assert path == "/"
            if self.username == "good":
                return ["app"], zookeeper_actions._ZK_ERR_OK, {}
            return [], zookeeper_actions._ZK_ERR_NOAUTH, {}

        def get_data(self, _path: str):
            return b"value", zookeeper_actions._ZK_ERR_OK, {}

    monkeypatch.setattr(zookeeper_actions, "_ZkClient", _Client)
    monkeypatch.setattr(
        zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(
        zookeeper_actions,
        "_probe_znode_create_delete",
        lambda *_args, **_kwargs: (events.append("data:capabilities") or True, False, None),
    )
    monkeypatch.setattr(
        zookeeper_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: (
            events.append("data:enumerate") or ["/app"],
            1,
            False,
            {"/app": {"path": "/app", "children": 0, "bytes": 5, "error": None}},
            None,
        ),
    )

    result = _run_one_target(
        args,
        spec,
        2181,
        (
            AuditCredentialRun(username="bad", password="bad", source="file"),
            AuditCredentialRun(username="good", password="good", source="file"),
            AuditCredentialRun(username="unused", password="unused", source="file"),
        ),
    )

    assert events == [
        "connect",
        "connect",
        "auth:bad",
        "connect",
        "auth:good",
        "data:capabilities",
        "data:enumerate",
    ]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["znode_count"] == 1


def test_zookeeper_lifecycle_retries_transient_auth_without_repeating_detect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=1,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_znodes=False,
        dump=False,
        znode=None,
        max_znodes=10,
        enum_workers=1,
    )
    spec = zookeeper_stage.build_zookeeper_spec(args)
    counts = {"detect_root": 0, "auth": 0}
    instances = 0

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            nonlocal instances
            instances += 1
            self.instance = instances
            self.authenticated = False

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            counts["auth"] += 1
            if counts["auth"] == 1:
                return False, "connection timeout"
            self.authenticated = True
            return True, None

        def get_children2(self, path: str):
            assert path == "/"
            if self.instance == 1:
                counts["detect_root"] += 1
                return [], zookeeper_actions._ZK_ERR_NOAUTH, {}
            assert self.authenticated
            return ["app"], zookeeper_actions._ZK_ERR_OK, {}

    monkeypatch.setattr(zookeeper_actions, "_ZkClient", _Client)
    monkeypatch.setattr(
        zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(zookeeper_actions, "_probe_znode_create_delete", lambda *_args, **_kwargs: (True, True, None))
    monkeypatch.setattr(
        zookeeper_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: ([], 0, False, {}, None),
    )
    monkeypatch.setattr(zookeeper_actions, "_retry_delay", lambda _attempt: 0.0)

    result = _run_one_target(
        args,
        spec,
        2181,
        (AuditCredentialRun(username="good", password="good", source="file"),),
    )

    assert counts == {"detect_root": 1, "auth": 2}
    assert result.records[0]["status"] == "valid_credentials"


def test_zookeeper_lifecycle_does_not_retry_definitive_digest_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=2,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_znodes=False,
        dump=False,
        znode=None,
        max_znodes=10,
        enum_workers=1,
    )
    spec = zookeeper_stage.build_zookeeper_spec(args)
    counts = {"detect_root": 0, "auth": 0}
    instances = 0

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            nonlocal instances
            instances += 1
            self.instance = instances

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            counts["auth"] += 1
            return False, "authentication failed: AUTHFAILED"

        def get_children2(self, path: str):
            assert path == "/"
            counts["detect_root"] += 1
            return [], zookeeper_actions._ZK_ERR_NOAUTH, {}

    monkeypatch.setattr(zookeeper_actions, "_ZkClient", _Client)
    monkeypatch.setattr(
        zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )

    result = _run_one_target(
        args,
        spec,
        2181,
        (AuditCredentialRun(username="bad", password="bad", source="file"),),
    )

    assert counts == {"detect_root": 1, "auth": 1}
    assert result.records[0]["status"] == "auth_required"
    assert result.records[0]["provided_credentials_ok"] is False
    assert result.records[0]["credential_verdict"] == "rejected"


def test_zookeeper_lifecycle_transient_auth_exhaustion_is_unverified_not_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=1,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_znodes=False,
        dump=False,
        znode=None,
        max_znodes=10,
        enum_workers=1,
    )
    spec = zookeeper_stage.build_zookeeper_spec(args)
    counts = {"detect_root": 0, "auth": 0}
    instances = 0

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            nonlocal instances
            instances += 1
            self.instance = instances

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            counts["auth"] += 1
            return False, "connection timeout"

        def get_children2(self, path: str):
            assert path == "/"
            counts["detect_root"] += 1
            return [], zookeeper_actions._ZK_ERR_NOAUTH, {}

    monkeypatch.setattr(zookeeper_actions, "_ZkClient", _Client)
    monkeypatch.setattr(
        zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(zookeeper_actions, "_retry_delay", lambda _attempt: 0.0)

    result = _run_one_target(
        args,
        spec,
        2181,
        (AuditCredentialRun(username="uncertain", password="secret", source="file"),),
    )

    assert counts == {"detect_root": 1, "auth": 2}
    assert result.records[0]["status"] == "fail"
    assert result.records[0]["provided_credentials_ok"] is None
    assert result.records[0]["credential_verdict"] == "unverified"


def test_zookeeper_lifecycle_retries_throttled_enumeration_without_redetect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=2,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        show_znodes=True,
        dump=False,
        znode=None,
        max_znodes=10,
        enum_workers=1,
    )
    spec = zookeeper_stage.build_zookeeper_spec(args)
    counts = {"detect_root": 0, "enumerate": 0}

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            assert path == "/"
            counts["detect_root"] += 1
            return ["app"], zookeeper_actions._ZK_ERR_OK, {}

    def _enumerate(*_args, **_kwargs):
        counts["enumerate"] += 1
        if counts["enumerate"] < 3:
            return [], 0, False, {}, "getChildren failed for /: THROTTLEDOP"
        return ["/app"], 1, False, {"/app": {"path": "/app", "children": 0, "bytes": 0}}, None

    monkeypatch.setattr(zookeeper_actions, "_ZkClient", _Client)
    monkeypatch.setattr(
        zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (False, "root_ok", ["/:ok"]),
    )
    monkeypatch.setattr(zookeeper_actions, "_probe_znode_create_delete", lambda *_args, **_kwargs: (True, True, None))
    monkeypatch.setattr(zookeeper_actions, "_enumerate_znodes", _enumerate)
    monkeypatch.setattr(zookeeper_actions, "_retry_delay", lambda _attempt: 0.0)

    result = _run_one_target(
        args,
        spec,
        2181,
        (AuditCredentialRun(source="anonymous"),),
    )

    assert counts == {"detect_root": 1, "enumerate": 3}
    assert result.records[0]["status"] == "open_no_auth"
    assert result.records[0]["znode_count"] == 1
    assert result.records[0]["attempts"] == 3


def test_elastic_uncertain_auth_on_anonymous_open_preserves_open_status_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="json",
        defcreds=False,
        endpoints=True,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
        ca_file=None,
    )
    spec = elastic_stage.build_elastic_spec(args)

    monkeypatch.setattr(
        elastic_actions,
        "_audit_elastic_host",
        lambda *_args, **_kwargs: {
            "timestamp": "2026-07-16T00:00:00Z",
            "host": "service.internal",
            "port": 9200,
            "is_elastic": True,
            "status": "open_no_auth",
            "auth_required": False,
            "server_version": "8.17.3",
            "scheme": "http",
            "insecure_effective": False,
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
            "detect_confidence": "high",
            "detect_signals": ["root_version_shape"],
            "detect_probe_trace": [{"path": "/", "status": 200, "scheme": "http"}],
            "error": None,
        },
    )
    monkeypatch.setattr(
        elastic_actions,
        "_probe_authenticate",
        lambda *_args, **_kwargs: elastic_actions.ElasticAuthProbeResult(
            valid=None,
            error="authentication probe timed out",
            username=None,
            status=0,
            endpoint="/_security/_authenticate",
            detail={
                "status": 0,
                "type": "transport_error",
                "reason": "authentication probe timed out",
                "root_cause": [],
            },
        ),
    )

    def _fetch_endpoints(*_args, **kwargs):
        assert "Authorization" not in kwargs["auth_headers"]
        return ["/_cluster/health"], None, []

    monkeypatch.setattr(elastic_actions, "_fetch_cat_endpoints", _fetch_endpoints)

    result = _run_one_target(
        args,
        spec,
        9200,
        (AuditCredentialRun(username="elastic", password="secret", source="provided"),),
    )

    record = result.records[0]
    assert record["status"] == "open_no_auth"
    assert record["auth_valid"] is None
    assert record["cat_endpoints"] == ["/_cluster/health"]
    assert record["error"] == "authentication probe timed out"
