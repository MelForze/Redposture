from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.elastic import actions as elastic_actions


def _audit_detect_only(*, retries: int = 0) -> dict[str, Any]:
    return elastic_actions._audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        retries,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
        preferred_scheme="http",
        run_deep_checks=False,
    )


def test_hard_positive_root_skips_all_confirmation_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            (b'{"name":"node-1","cluster_name":"prod","version":{"number":"2.19.1","distribution":"opensearch"}}'),
            {},
            None,
            "http",
            False,
            True,
        ),
    )
    confirm_calls: list[str] = []

    def unexpected_confirm(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        confirm_calls.append(path)
        return 404, b"{}", {}, None, "http"

    monkeypatch.setattr(elastic_actions, "_request_detect_probe", unexpected_confirm)

    record = _audit_detect_only()

    assert record["is_elastic"] is True
    assert record["vendor"] == "opensearch"
    assert confirm_calls == []


def test_transport_fallback_is_not_attempted_for_protocol_independent_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []

    def refused(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        *,
        use_https: bool,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        calls.append(use_https)
        return 0, b"", {}, "connection refused"

    monkeypatch.setattr(elastic_actions, "_elastic_request", refused)

    result = elastic_actions._request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
        preferred_scheme="http",
    )

    assert calls == [False]
    assert result[0] == 0
    assert "http=connection refused" in str(result[3])


def test_transport_fallback_tries_tls_once_for_protocol_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def request(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        *,
        use_https: bool,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        calls.append(use_https)
        if not use_https:
            return 0, b"", {}, "connection reset by peer during plaintext HTTP request"
        return 200, b'{"tagline":"You Know, for Search"}', {}, None

    monkeypatch.setattr(elastic_actions, "_elastic_request", request)

    result = elastic_actions._request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
        preferred_scheme="http",
    )

    assert calls == [False, True]
    assert result[0] == 200
    assert result[4] == "https"


def test_explicit_scheme_disables_transport_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def failed(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        *,
        use_https: bool,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        calls.append(use_https)
        return 0, b"", {}, "wrong version number"

    monkeypatch.setattr(elastic_actions, "_elastic_request", failed)

    elastic_actions._request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
        preferred_scheme="https",
        allow_fallback=False,
    )

    assert calls == [True]


def test_permanent_root_failure_is_not_retried_or_backed_off(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def failed(*_args: Any, **_kwargs: Any) -> tuple[int, bytes, dict[str, str], str | None, str, bool, bool]:
        nonlocal calls
        calls += 1
        return 0, b"", {}, "http=connection refused", "http", False, True

    monkeypatch.setattr(elastic_actions, "_request_with_tls_fallback", failed)
    monkeypatch.setattr(
        elastic_actions.time,
        "sleep",
        lambda _delay: pytest.fail("permanent failure must not sleep"),
    )

    record = _audit_detect_only(retries=3)

    assert calls == 1
    assert record["status"] == "fail"


def test_progressive_detection_stops_after_second_independent_soft_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"cluster_name":"prod","name":"node-1"}',
            {"Content-Type": "application/json"},
            None,
            "http",
            False,
            True,
        ),
    )
    calls: list[str] = []

    def soft_probe(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        calls.append(path)
        if path.startswith("/_nodes"):
            return 200, b'{"nodes":{"node-1":{}}}', {}, None, "http"
        return 200, b'{"cluster_name":"prod","status":"green"}', {}, None, "http"

    monkeypatch.setattr(elastic_actions, "_request_detect_probe", soft_probe)

    record = _audit_detect_only()

    assert record["is_elastic"] is True
    assert record["detect_confidence"] == "medium"
    assert len(calls) == 1


def test_deterministic_ambiguous_responses_are_not_replayed_with_hidden_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            400,
            b'{"message":"bad request"}',
            {"Content-Type": "application/json"},
            None,
            "http",
            False,
            True,
        ),
    )
    calls: list[tuple[str, float]] = []

    def neutral_probe(
        _host: str,
        _port: int,
        path: str,
        timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        calls.append((path, timeout))
        return 404, b"{}", {"Content-Type": "application/json"}, None, "http"

    monkeypatch.setattr(elastic_actions, "_request_detect_probe", neutral_probe)

    record = _audit_detect_only()

    assert record["is_elastic"] is False
    assert len(calls) == len(elastic_actions._DETECT_CONFIRM_PATHS)
    assert {timeout for _path, timeout in calls} == {1.0}


def test_detection_does_not_launch_cosmetic_version_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"tagline":"You Know, for Search"}',
            {},
            None,
            "http",
            False,
            True,
        ),
    )
    monkeypatch.setattr(
        elastic_actions,
        "_resolve_server_version_without_auth",
        lambda *_args, **_kwargs: pytest.fail("detection must reuse probe responses"),
    )

    record = _audit_detect_only()

    assert record["is_elastic"] is True
    assert record["server_version"] is None


def test_legacy_credential_only_path_skips_privilege_and_api_key_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"tagline":"You Know, for Search","version":{"number":"8.17.3"}}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "http",
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        elastic_actions,
        "_probe_authenticate",
        lambda *_args, **_kwargs: elastic_actions.ElasticAuthProbeResult(
            valid=True,
            error=None,
            username="elastic",
            status=200,
            endpoint="/_security/_authenticate",
            detail=None,
        ),
    )
    monkeypatch.setattr(
        elastic_actions,
        "_check_privileges",
        lambda *_args, **_kwargs: pytest.fail("credential-only mode must not probe privileges"),
    )
    monkeypatch.setattr(
        elastic_actions,
        "_verify_api_key_probe",
        lambda *_args, **_kwargs: pytest.fail("credential-only mode must not probe API-key capabilities"),
    )

    record = elastic_actions._audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        username=None,
        password=None,
        api_token="opaque-token",
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
        preferred_scheme="http",
    )

    assert record["status"] == "valid_credentials"
    assert record["api_key_probe_status"] == "not_run"
    assert record["rights_error"] is None


@pytest.mark.parametrize(
    ("target_scheme", "expected_scheme", "scheme_locked"),
    [
        (None, "http", False),
        ("https", "https", True),
    ],
)
def test_lifecycle_detection_uses_target_scheme_policy_and_closes_phase_session(
    monkeypatch: pytest.MonkeyPatch,
    target_scheme: str | None,
    expected_scheme: str,
    scheme_locked: bool,
) -> None:
    sessions: list[Any] = []
    audit_kwargs: dict[str, Any] = {}

    class FakeSession:
        def __init__(self, host: str, port: int, **_kwargs: Any) -> None:
            self.host = host
            self.port = port
            self.closed = False
            sessions.append(self)

        def close(self) -> None:
            self.closed = True

    def fake_audit(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        audit_kwargs.update(kwargs)
        return {
            "host": "127.0.0.1",
            "port": 9200,
            "status": "open_no_auth",
            "is_elastic": True,
        }

    monkeypatch.setattr(elastic_actions, "ElasticHttpSession", FakeSession)
    monkeypatch.setattr(elastic_actions, "_audit_elastic_host", fake_audit)
    state = elastic_actions.ElasticLifecycleState()
    ctx = SimpleNamespace(
        lifecycle_state=state,
        host="127.0.0.1",
        port=9200,
        target=SimpleNamespace(scheme=target_scheme),
        args=SimpleNamespace(
            timeout=1.0,
            retries=0,
            ca_file=None,
            proxy=None,
            debug=False,
        ),
    )

    record = elastic_actions.detect_elastic(ctx, {})

    assert record["is_elastic"] is True
    assert audit_kwargs["preferred_scheme"] == expected_scheme
    assert audit_kwargs["scheme_locked"] is scheme_locked
    assert len(sessions) == 1
    assert sessions[0].closed is True
    assert state.session is None
