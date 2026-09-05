from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio import actions, policy, stage
from redposture_core.modules.minio.types import AnonymousResult, CredentialResult, MinioDetection


def test_build_minio_plan_default_ports():
    plan = stage.build_minio_plan(parse_args(["minio", "-t", "127.0.0.1"]))
    assert plan.ports == (9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001)


def test_build_minio_spec_wires_hooks():
    spec = stage.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1"]))
    assert spec.module == "minio"
    assert spec.label == "MINIO"
    assert spec.detect is not None
    assert spec.auth is not None
    assert spec.colorize is not None
    assert spec.skip_credentials_without_verifier is True


def test_minio_credential_gate_verified_and_rejected():
    verified = AuditRecord(
        host="h", port=9000, service="minio", status="detected", extra={"provided_credentials_ok": True}
    )
    rejected = AuditRecord(
        host="h", port=9000, service="minio", status="detected", extra={"provided_credentials_ok": False}
    )

    ok, reason = stage._minio_credential_gate(None, verified)
    assert ok is True
    assert "verified" in reason

    ok, reason = stage._minio_credential_gate(None, rejected)
    assert ok is False
    assert "rejected" in reason


def test_run_minio_stage_returns_validation_error_without_network():
    args = parse_args(["minio", "-t", "127.0.0.1", "--session-token", "TOK"])
    rc = stage.run_minio_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 2


def _fake_args(**overrides: object) -> SimpleNamespace:
    base = dict(timeout=1.0, retries=0, session_token=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_minio_lifecycle_state_factory_builds_pool_and_closes():
    ctx = SimpleNamespace(args=_fake_args(), host="127.0.0.1", port=9000)
    state = actions.minio_lifecycle_state_factory(ctx)
    assert isinstance(state, actions.MinioLifecycleState)
    assert state.pool.insecure is True  # certificates are always accepted
    state.close()  # must not raise


def test_transport_mismatch_classifier():
    # tried https but the peer speaks plaintext -> mismatch, flip to http
    assert actions._transport_mismatch("https", "[SSL: WRONG_VERSION_NUMBER] wrong version number") is True
    assert actions._transport_mismatch("https", "SSLV3_ALERT_HANDSHAKE_FAILURE") is True
    # tried http but the peer requires TLS -> mismatch, flip to https
    assert actions._transport_mismatch("http", "BadStatusLine: '\\x15\\x03\\x01'") is True
    assert actions._transport_mismatch("http", "RemoteDisconnected('Remote end closed connection')") is True
    # unrelated transport failures are NOT a scheme mismatch
    assert actions._transport_mismatch("http", "ConnectionRefusedError: [Errno 61] Connection refused") is False
    assert actions._transport_mismatch("https", "timed out") is False


def test_resolve_scheme_flips_on_mismatch_and_caches(monkeypatch: pytest.MonkeyPatch):
    # http-heuristic port (9000) but the server is TLS -> flip to https, once.
    state = actions.MinioLifecycleState(_fake_args(), "10.0.0.9", 9000)
    calls: list[str] = []

    def fake_probe(scheme: str) -> MinioResponse:
        calls.append(scheme)
        if scheme == "http":
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error="RemoteDisconnected")
        return MinioResponse(http_status=403, headers={}, body=b"<Error/>")

    monkeypatch.setattr(state, "_probe", fake_probe)
    assert state.resolve_scheme() == "https"
    assert state.resolve_scheme() == "https"  # cached: no second probe
    assert calls == ["http"]
    state.close()


def test_resolve_scheme_keeps_guess_when_no_mismatch(monkeypatch: pytest.MonkeyPatch):
    state = actions.MinioLifecycleState(_fake_args(), "10.0.0.9", 443)  # TLS-port heuristic -> https
    monkeypatch.setattr(state, "_probe", lambda scheme: MinioResponse(http_status=200, headers={}, body=b""))
    assert state.resolve_scheme() == "https"
    state.close()


def test_client_for_scheme_selection_and_pool_reuse(monkeypatch: pytest.MonkeyPatch):
    args = _fake_args()
    state = actions.MinioLifecycleState(args, "127.0.0.1", 9000)
    # No network: a clean probe leaves the port heuristic (http) in place.
    monkeypatch.setattr(state, "_probe", lambda scheme: MinioResponse(http_status=200, headers={}, body=b""))
    try:
        credential = SimpleNamespace(username="AK", password="SK")

        ctx = SimpleNamespace(args=args, host="127.0.0.1", port=9000, lifecycle_state=state)
        client = actions._client_for(ctx, credential)
        assert client.scheme == "http"
        assert client._pool is state.pool
        assert client.access_key == "AK"
        assert client.secret_key == "SK"

        # No lifecycle state -> fall back to the port heuristic directly (https on 443).
        ctx_tls = SimpleNamespace(args=args, host="127.0.0.1", port=443, lifecycle_state=None)
        client_tls = actions._client_for(ctx_tls, credential)
        assert client_tls.scheme == "https"
        assert client_tls._pool is not state.pool
        assert client_tls._pool.insecure is True
    finally:
        state.close()


def test_detect_record_confirmed_includes_anonymous_fields(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        actions,
        "detect_minio",
        lambda client: MinioDetection(status="confirmed", api_endpoint="http://h:9000", evidence={"ok": True}),
    )
    monkeypatch.setattr(
        actions,
        "classify_anonymous",
        lambda client, known_bucket=None: AnonymousResult(
            api_reachable=True, classification="anonymous_list_ok", buckets=("b1",)
        ),
    )
    ctx = SimpleNamespace(
        args=_fake_args(),
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username=None, password=None),
        lifecycle_state=None,
    )
    record = actions.detect_record(ctx)
    assert record["status"] == "detected"
    assert record["credential_verification_status"] == "available"
    assert record["anonymous"] == "anonymous_list_ok"
    assert record["auth_required"] is False
    assert record["anonymous_buckets"] == ["b1"]


def test_detect_record_probable_skips_anonymous_probe(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        actions,
        "detect_minio",
        lambda client: MinioDetection(status="probable", api_endpoint="http://h:9000", evidence={}),
    )

    def _must_not_run(*_a: object, **_k: object) -> None:
        raise AssertionError("classify_anonymous must not run for a non-confirmed detection")

    monkeypatch.setattr(actions, "classify_anonymous", _must_not_run)
    ctx = SimpleNamespace(
        args=_fake_args(),
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username=None, password=None),
        lifecycle_state=None,
    )
    record = actions.detect_record(ctx)
    assert record["status"] == "probable"
    assert record["credential_verification_status"] == "unavailable"
    assert "anonymous" not in record


def test_auth_record_without_credentials_returns_prior_copy():
    ctx = SimpleNamespace(
        args=_fake_args(),
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username=None, password=None),
        lifecycle_state=None,
    )
    prior = {"host": "127.0.0.1", "port": 9000, "status": "detected"}
    merged = actions.auth_record(ctx, prior)
    assert merged == prior
    assert merged is not prior


def test_auth_record_with_credentials_marks_verified(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        actions, "verify_credential", lambda client: CredentialResult(state="valid", access_key="AK", error_code=None)
    )
    ctx = SimpleNamespace(
        args=_fake_args(session_token="TOK"),
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username="AK", password="SK"),
        lifecycle_state=None,
    )
    merged = actions.auth_record(ctx, {"host": "127.0.0.1", "port": 9000, "status": "detected"})
    assert merged["credential_state"] == "valid"
    assert merged["credential_type"] == "session-token"
    assert merged["provided_credentials_ok"] is True
    assert merged["credential_results"] == [{"access_key": "AK", "state": "valid", "error_code": None}]


def test_build_minio_spec_detect_and_auth_hooks_end_to_end(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        actions,
        "detect_minio",
        lambda client: MinioDetection(status="confirmed", api_endpoint="http://127.0.0.1:9000", evidence={}),
    )
    monkeypatch.setattr(
        actions,
        "classify_anonymous",
        lambda client, known_bucket=None: AnonymousResult(api_reachable=True, classification="authentication_required"),
    )
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda client: CredentialResult(state="valid_but_restricted", access_key="AK", error_code="AccessDenied"),
    )
    spec = stage.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1", "-u", "AK", "-p", "SK"]))
    ctx = SimpleNamespace(
        args=_fake_args(),
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username="AK", password="SK"),
        lifecycle_state=None,
    )

    assert spec.detect is not None
    assert spec.auth is not None

    detected = spec.detect(ctx)
    assert isinstance(detected, AuditRecord)
    assert detected.extra["detection_status"] == "confirmed"
    assert detected.auth_required is True

    authed = spec.auth(ctx, detected)
    assert isinstance(authed, AuditRecord)
    assert authed.extra["credential_state"] == "valid_but_restricted"
    assert authed.extra["provided_credentials_ok"] is True


def test_minio_policy_validate_args_branches():
    errors: list[str] = []
    console = SimpleNamespace(error=lambda msg: errors.append(msg))

    assert policy.validate_args(SimpleNamespace(port=0, session_token=None), console) == 2
    assert errors[-1] == "--port must be > 0"

    assert (
        policy.validate_args(SimpleNamespace(port=None, session_token="TOK", username=None, password=None), console)
        == 2
    )
    assert errors[-1] == "--session-token requires -u/--username and -p/--password"

    assert (
        policy.validate_args(SimpleNamespace(port=None, session_token="TOK", username="AK", password="SK"), console)
        is None
    )


def test_spec_wires_capabilities_hook():
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.minio import stage as _s

    spec = _s.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1"]))
    assert spec.capabilities is not None


def test_probe_write_flag_is_inert_and_parses():
    from redposture_core.cli_args import parse_args

    args = parse_args(["minio", "-t", "127.0.0.1", "--probe-write"])
    assert args.probe_write is True


def test_spec_wires_data_hook():
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.minio import stage as _s

    spec = _s.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1"]))
    assert spec.data is not None


def test_enumeration_flags_parse():
    from redposture_core.cli_args import parse_args

    args = parse_args(
        [
            "minio",
            "-t",
            "127.0.0.1",
            "--show-buckets",
            "--show-objects",
            "--bucket",
            "b",
            "--prefix",
            "p/",
            "--discover",
            "--max-objects",
            "7",
        ]
    )
    assert args.show_buckets and args.show_objects and args.discover
    assert args.bucket == "b" and args.prefix == "p/" and args.max_objects == 7


def test_data_record_noop_without_flags():
    from redposture_core.modules.minio import actions as _a

    class _Ctx:
        class args:
            show_buckets = show_objects = discover = False

        host, port = "h", 9000
        lifecycle_state = None

        class credential:
            username = password = None

    assert _a.data_record(_Ctx(), {"detection_status": "confirmed"}) == {"detection_status": "confirmed"}


def test_data_record_streams_objects_to_tempfile_across_all_buckets(monkeypatch: pytest.MonkeyPatch):
    import os

    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio import enumerate as _enum

    monkeypatch.setattr(
        _enum,
        "iter_buckets",
        lambda client, limit=None: [_enum.BucketInfo(name="b1"), _enum.BucketInfo(name="b2")],
    )

    seen: dict[str, object] = {}

    def fake_multi(client, buckets, *, prefix="", limit=None, page_size=1000):
        seen["buckets"] = list(buckets)
        seen["limit"] = limit
        yield _enum.ObjectInfo(bucket="b1", key="k1", size=1)
        yield _enum.ObjectInfo(bucket="b2", key="k2", size=2)

    monkeypatch.setattr(_enum, "iter_objects_multi", fake_multi)

    class _Ctx:
        class args:
            show_buckets = False
            show_objects = True
            discover = False
            probe_write = False
            bucket = None
            prefix = ""
            timeout = 1.0
            session_token = None
            output_format = "txt"

        host, port = "10.0.0.5", 9000
        lifecycle_state = None

        class credential:
            username = "AK"
            password = "SK"

    out = _a.data_record(_Ctx(), {"detection_status": "confirmed"})
    assert seen["buckets"] == ["b1", "b2"]  # no --bucket -> every listable bucket
    assert seen["limit"] is None  # unbounded listing (no --limit)
    assert out["objects_streamed"] is True
    assert out["objects_count"] == 2
    assert "objects" not in out  # not materialised into the record
    path = out["_stream_lines_file"]
    try:
        streamed = open(path, encoding="utf-8").read().splitlines()
        assert streamed == [
            "MINIO\t10.0.0.5\t9000\t b1/k1 (size:1)",
            "MINIO\t10.0.0.5\t9000\t b2/k2 (size:2)",
        ]
    finally:
        os.remove(path)


def test_data_record_write_probe_runs_on_all_buckets(monkeypatch: pytest.MonkeyPatch):
    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio import enumerate as _enum

    monkeypatch.setattr(
        _enum, "iter_buckets", lambda client, limit=None: [_enum.BucketInfo(name="rw"), _enum.BucketInfo(name="ro")]
    )
    captured: dict[str, object] = {}

    def fake_probe(client, buckets):
        captured["buckets"] = list(buckets)
        return {"rw": {"write": True, "cleanup": "ok"}, "ro": {"write": False}}, []

    monkeypatch.setattr(_a, "probe_write_capability", fake_probe)

    class _Ctx:
        class args:
            show_buckets = True
            show_objects = False
            discover = False
            probe_write = True
            bucket = None
            prefix = ""
            timeout = 1.0
            session_token = None
            output_format = "txt"

        host, port = "h", 9000
        lifecycle_state = None

        class credential:
            username = "AK"
            password = "SK"

    out = _a.data_record(_Ctx(), {"detection_status": "confirmed"})
    assert captured["buckets"] == ["rw", "ro"]
    assert out["write_probe"] == {"rw": {"write": True, "cleanup": "ok"}, "ro": {"write": False}}
    assert out["write_probe_leftovers"] == []


def test_data_record_discover_computes_coverage_percent(monkeypatch: pytest.MonkeyPatch):
    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio import discover as _disc
    from redposture_core.modules.minio import enumerate as _enum

    monkeypatch.setattr(_enum, "iter_buckets", lambda client, limit=None: [_enum.BucketInfo(name="b1")])
    monkeypatch.setattr(_enum, "iter_objects_multi", lambda *a, **k: iter([]))

    result = _disc.DiscoverResult(
        findings=[{"type": "x"}],
        candidates=[{"k": i} for i in range(7)],
        objects_scanned=3,
        bytes_read=100,
        partial_reasons=["object_limit"],
        coverage_complete=False,
    )
    monkeypatch.setattr(_disc, "discover_secrets", lambda client, objects, budget=None, on_finding=None: result)

    class _Ctx:
        class args:
            show_buckets = False
            show_objects = False
            discover = True
            probe_write = False
            object = None
            dump = False
            download = None
            bucket = None
            prefix = ""
            timeout = 1.0
            session_token = None
            output_format = "txt"
            max_object_size = 10 * 1024 * 1024
            max_objects = 50
            discover_time = 5.0

        host, port = "h", 9000
        lifecycle_state = None

        class credential:
            username = "AK"
            password = "SK"

    out = _a.data_record(_Ctx(), {"detection_status": "confirmed"})
    assert out["discover_requested"] is True
    assert out["discover_coverage"] == "partial"
    assert out["discover_candidates_count"] == 7
    assert out["discover_objects_scanned"] == 3
    assert out["discover_coverage_percent"] == 42.86  # 3/7 candidates inspected
    assert out["secret_findings"] == [{"type": "x"}]


def test_data_record_discover_self_emits_live_in_txt(monkeypatch: pytest.MonkeyPatch):
    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio import discover as _disc
    from redposture_core.modules.minio import enumerate as _enum

    monkeypatch.setattr(_enum, "iter_buckets", lambda client, limit=None: [_enum.BucketInfo(name="b1")])
    monkeypatch.setattr(_enum, "iter_objects_multi", lambda *a, **k: iter([]))

    findings = [
        {"type": "aws_access_key", "bucket": "b", "key": "app.env", "value": "AKIAEXAMPLE", "object_path": "$"},
        {"type": "password", "bucket": "b", "key": "cfg.yaml", "value": "s3cr3t", "object_path": "$"},
    ]

    def fake_discover(client, objects, *, budget=None, on_finding=None):
        for f in findings:
            if on_finding:
                on_finding(f)  # real-time
        return _disc.DiscoverResult(findings=findings, candidates=[{}, {}], objects_scanned=2, coverage_complete=True)

    monkeypatch.setattr(_disc, "discover_secrets", fake_discover)

    captured: list[str] = []

    class _Ctx:
        class args:
            show_buckets = False
            show_objects = False
            discover = True
            probe_write = False
            object = None
            dump = False
            download = None
            bucket = None
            prefix = ""
            timeout = 1.0
            session_token = None
            output_format = "txt"
            max_object_size = 100 * 1024 * 1024
            max_objects = 1000
            discover_time = 30.0

        host, port = "10.0.0.5", 19000
        lifecycle_state = None
        live_emit = staticmethod(lambda lines: captured.extend(lines))

        class credential:
            username = "minioadmin"
            password = "minioadmin"

    prior = {
        "host": "10.0.0.5",
        "port": 19000,
        "detection_status": "confirmed",
        "auth_required": True,
        "credential_state": "valid",
        "credential_results": [{"access_key": "minioadmin", "state": "valid"}],
        "admin_capability": "confirmed",
    }
    out = _a.data_record(_Ctx(), prior)

    assert out["_self_emitted"] is True
    assert out["_self_emitted_lines"] == len(captured)
    # ordered live output: detect, credential, findings (as found), then summary footer
    assert captured[0] == "MINIO\t10.0.0.5\t19000\t [*] MinIO (auth required:True)"
    assert captured[1] == "MINIO\t10.0.0.5\t19000\t [+] minioadmin (admin:True)"
    assert any('[+] aws_access_key value="AKIAEXAMPLE"' in line for line in captured)
    assert any('[+] password value="s3cr3t"' in line for line in captured)
    summary_idx = next(i for i, line in enumerate(captured) if "Discover Secrets" in line)
    finding_idx = next(i for i, line in enumerate(captured) if "aws_access_key value=" in line)
    assert finding_idx < summary_idx  # findings stream before the final summary
    assert "(status:complete) (coverage:100.00%) (findings:2) (objects:2)" in captured[summary_idx]


def test_data_record_discover_batches_when_no_live_sink(monkeypatch: pytest.MonkeyPatch):
    # No live_emit on the ctx -> batched (record rendered by the runtime, no self-emit).
    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio import discover as _disc
    from redposture_core.modules.minio import enumerate as _enum

    monkeypatch.setattr(_enum, "iter_buckets", lambda client, limit=None: [])
    monkeypatch.setattr(_enum, "iter_objects_multi", lambda *a, **k: iter([]))
    monkeypatch.setattr(
        _disc,
        "discover_secrets",
        lambda client, objects, budget=None, on_finding=None: _disc.DiscoverResult(coverage_complete=True),
    )

    class _Ctx:
        class args:
            show_buckets = show_objects = probe_write = dump = False
            discover = True
            object = download = None
            bucket = None
            prefix = ""
            timeout = 1.0
            session_token = None
            output_format = "txt"
            max_object_size = 100 * 1024 * 1024
            max_objects = 1000
            discover_time = 30.0

        host, port = "h", 9000
        lifecycle_state = None  # no live_emit attribute at all

        class credential:
            username = "AK"
            password = "SK"

    out = _a.data_record(_Ctx(), {"detection_status": "confirmed"})
    assert "_self_emitted" not in out
    assert out["discover_requested"] is True
