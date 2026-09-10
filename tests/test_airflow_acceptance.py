"""Negative and edge acceptance scenarios for the Airflow module.

Complements the happy-path unit tests: every branch that a hostile or merely
broken server can push the module through — malformed bodies, ambiguous HTTP
codes, partial transport failures in a probe ladder, empty/coerced values,
unknown API generations — plus the record-shaping logic of the detect/auth/
capabilities hooks. No Docker or network.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions
from redposture_core.modules.airflow.types import CredentialResult, RoleCapability


class FakeClient:
    """Path-keyed fake AirflowClient. Response values are ``(status, body)`` or the
    sentinel ``"TRANSPORT"`` for a transport error. Records every call so tests can
    assert which endpoints were (not) reached."""

    base_url = "http://h:8080"

    def __init__(self, responses: dict | None = None, *, default: tuple = (404, b"")) -> None:
        self.responses = responses or {}
        self.default = default
        self.calls: list = []

    def _resp(self, path: str) -> AirflowResponse:
        value = self.responses.get(path, self.default)
        if value == "TRANSPORT":
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error="connection refused")
        status, body = value
        return AirflowResponse(http_status=status, headers={}, body=body)

    def get(self, path: str, *, authed: bool = True) -> AirflowResponse:
        self.calls.append(("GET", path, authed))
        return self._resp(path)

    def post_json(self, path: str, payload: dict, *, authed: bool = False) -> AirflowResponse:
        self.calls.append(("POST", path, authed, payload))
        return self._resp(path)


def _patch_client(monkeypatch, client: FakeClient) -> None:
    monkeypatch.setattr(actions, "_client_for", lambda ctx, **kw: client)


# --- detection: malformed / ambiguous version bodies -----------------------


def test_detect_short_circuits_on_v2_and_skips_v1():
    client = FakeClient({"/api/v2/version": (200, b'{"version":"3.0.0"}')})
    detection = actions.detect_airflow(client)
    assert detection.status == "confirmed" and detection.api_generation == "v2"
    assert ("GET", "/api/v1/version", False) not in client.calls


def test_detect_ignores_non_json_version_body():
    client = FakeClient({"/api/v2/version": (200, b"<html>not json</html>"), "/api/v1/version": (404, b"")})
    assert actions.detect_airflow(client).status == "not_airflow"


def test_detect_ignores_json_without_version_key():
    client = FakeClient({"/api/v1/version": (200, b'{"git_version":"abc"}'), "/api/v2/version": (404, b"")})
    assert actions.detect_airflow(client).status == "not_airflow"


def test_detect_rejects_empty_version_value():
    client = FakeClient({"/api/v1/version": (200, b'{"version":""}'), "/api/v2/version": (404, b"")})
    assert actions.detect_airflow(client).status == "not_airflow"


def test_detect_ignores_json_array_version_body():
    client = FakeClient({"/api/v2/version": (200, b"[]"), "/api/v1/version": (404, b"")})
    assert actions.detect_airflow(client).status == "not_airflow"


def test_detect_coerces_non_string_version():
    client = FakeClient({"/api/v2/version": (200, b'{"version":2}')})
    detection = actions.detect_airflow(client)
    assert detection.status == "confirmed" and detection.version == "2"


def test_detect_confirms_v1_when_only_v2_transport_fails():
    client = FakeClient({"/api/v2/version": "TRANSPORT", "/api/v1/version": (200, b'{"version":"2.10.5"}')})
    detection = actions.detect_airflow(client)
    assert detection.status == "confirmed" and detection.api_generation == "v1"


def test_detect_probable_requires_health_shape():
    # Both health endpoints answer 200 but with a body that is not an Airflow health
    # document -> must NOT be classified as probable.
    client = FakeClient(
        {
            "/api/v2/version": (403, b""),
            "/api/v1/version": (403, b""),
            "/api/v2/monitor/health": (200, b'{"foo":1}'),
            "/api/v1/health": (200, b'{"bar":2}'),
        }
    )
    assert actions.detect_airflow(client).status == "not_airflow"


def test_detect_probable_on_scheduler_only_health():
    client = FakeClient(
        {
            "/api/v2/version": (401, b""),
            "/api/v1/version": (401, b""),
            "/api/v2/monitor/health": (200, b'{"scheduler":{"status":"healthy"}}'),
        }
    )
    detection = actions.detect_airflow(client)
    assert detection.status == "probable" and detection.api_generation == "v2"


# --- anonymous ladder: partial transport, ambiguous codes ------------------


def test_anonymous_partial_transport_in_ladder_still_admin():
    client = FakeClient({"/api/v1/dags": (200, b"[]"), "/api/v1/pools": "TRANSPORT", "/api/v1/eventLogs": (200, b"[]")})
    result = actions.classify_anonymous(client, "v1")
    assert result.auth_required is False and result.role == "admin"


def test_anonymous_non200_rungs_not_promoted():
    client = FakeClient({"/api/v1/dags": (200, b"[]"), "/api/v1/pools": (500, b""), "/api/v1/eventLogs": (500, b"")})
    assert actions.classify_anonymous(client, "v1").role == "viewer"


@pytest.mark.parametrize("status", [500, 429, 302, 418])
def test_anonymous_ambiguous_viewer_status_is_unknown(status):
    client = FakeClient({"/api/v1/dags": (status, b"")})
    result = actions.classify_anonymous(client, "v1")
    assert result.auth_required is None and result.role == "unknown"


def test_anonymous_unknown_generation_falls_back_to_v1():
    client = FakeClient({"/api/v1/dags": (401, b"")})
    result = actions.classify_anonymous(client, "v9")
    assert result.auth_required is True and result.role == "none"
    assert ("GET", "/api/v1/dags", False) in client.calls


# --- credential verification: full status matrix ---------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, "valid"),
        (204, "verification_unavailable"),
        (299, "verification_unavailable"),
        (401, "invalid"),
        (403, "valid_but_restricted"),
        (500, "verification_unavailable"),
        (302, "verification_unavailable"),
    ],
)
def test_v1_basic_status_mapping(status, expected):
    if status == 200:
        body = b'{"dags":[],"total_entries":0}'
    elif status in {401, 403}:
        title = b"Unauthorized" if status == 401 else b"Forbidden"
        body = b'{"status":' + str(status).encode() + b',"title":"' + title + b'","detail":"denied"}'
    else:
        body = b""
    client = FakeClient({"/api/v1/dags": (status, body)})
    assert actions.verify_credential(lambda **k: client, "v1", "u", "p").state == expected


def test_v1_transport_is_transient():
    client = FakeClient({"/api/v1/dags": "TRANSPORT"})
    assert actions.verify_credential(lambda **k: client, "v1", "u", "p").state == "transient_failure"


def test_v2_missing_token_is_transient():
    client = FakeClient({"/auth/token": (200, b'{"token_type":"Bearer"}')})
    assert actions.verify_credential(lambda **k: client, "v2", "u", "p").state == "transient_failure"


def test_v2_empty_token_is_transient():
    client = FakeClient({"/auth/token": (200, b'{"access_token":""}')})
    assert actions.verify_credential(lambda **k: client, "v2", "u", "p").state == "transient_failure"


def test_v2_non_string_token_coerced():
    client = FakeClient({"/auth/token": (200, b'{"access_token":12345}')})
    result = actions.verify_credential(lambda **k: client, "v2", "u", "p")
    assert result.state == "valid" and result.bearer_token == "12345"


def test_v2_403_is_invalid():
    client = FakeClient({"/auth/token": (403, b"")})
    assert actions.verify_credential(lambda **k: client, "v2", "u", "p").state == "invalid"


def test_v2_transport_is_transient():
    client = FakeClient({"/auth/token": "TRANSPORT"})
    assert actions.verify_credential(lambda **k: client, "v2", "u", "p").state == "transient_failure"


def test_v2_non_json_body_is_transient():
    client = FakeClient({"/auth/token": (200, b"garbage")})
    assert actions.verify_credential(lambda **k: client, "v2", "u", "p").state == "transient_failure"


def test_unknown_generation_uses_v1_basic():
    client = FakeClient({"/api/v1/dags": (200, b'{"dags":[],"total_entries":0}')})
    captured: dict = {}

    def factory(basic_user=None, basic_password=None):
        captured["u"], captured["p"] = basic_user, basic_password
        return client

    result = actions.verify_credential(factory, "v3", "airflow", "pw")
    assert result.state == "valid" and captured == {"u": "airflow", "p": "pw"}


# --- authenticated role ladder: none vs unknown, partial transport ---------


def test_role_all_admin():
    client = FakeClient(
        {"/api/v1/dags": (200, b"[]"), "/api/v1/pools": (200, b"[]"), "/api/v1/eventLogs": (200, b"[]")}
    )
    assert actions.classify_role(client, "v1").role == "admin"


def test_role_viewer_only():
    client = FakeClient({"/api/v1/dags": (200, b"[]"), "/api/v1/pools": (403, b""), "/api/v1/eventLogs": (403, b"")})
    assert actions.classify_role(client, "v1").role == "viewer"


def test_role_none_when_all_denied():
    client = FakeClient({"/api/v1/dags": (403, b""), "/api/v1/pools": (403, b""), "/api/v1/eventLogs": (403, b"")})
    assert actions.classify_role(client, "v1").role == "none"


def test_role_unknown_when_all_transport_error():
    client = FakeClient({"/api/v1/dags": "TRANSPORT", "/api/v1/pools": "TRANSPORT", "/api/v1/eventLogs": "TRANSPORT"})
    assert actions.classify_role(client, "v1").role == "unknown"


def test_role_none_distinct_from_unknown_on_server_error():
    # 5xx across the board is "reachable but denied" (none), not the all-transport
    # "unknown" — the two must not collapse.
    client = FakeClient({"/api/v1/dags": (500, b""), "/api/v1/pools": (500, b""), "/api/v1/eventLogs": (500, b"")})
    assert actions.classify_role(client, "v1").role == "none"


def test_role_admin_survives_partial_transport():
    client = FakeClient({"/api/v1/dags": (200, b"[]"), "/api/v1/pools": "TRANSPORT", "/api/v1/eventLogs": (200, b"[]")})
    assert actions.classify_role(client, "v1").role == "admin"


# --- detect_record shaping -------------------------------------------------


def test_detect_record_not_airflow_shape(monkeypatch):
    _patch_client(monkeypatch, FakeClient({}))
    record = actions.detect_record(SimpleNamespace(host="h", port=8080))
    assert record["status"] == "not_service"
    assert record["detection_status"] == "not_airflow"
    assert record["credential_verification_status"] == "unavailable"
    assert "anonymous_role" not in record and "auth_required" not in record


def test_detect_record_confirmed_includes_anon_and_version(monkeypatch):
    _patch_client(
        monkeypatch,
        FakeClient({"/api/v2/version": (200, b'{"version":"3.0.1"}'), "/api/v2/dags": (401, b"")}),
    )
    record = actions.detect_record(SimpleNamespace(host="h", port=8080))
    assert record["detection_status"] == "confirmed"
    assert record["version"] == "3.0.1"
    assert record["api_generation"] == "v2"
    assert record["auth_required"] is True and record["anonymous_role"] == "none"
    assert record["credential_verification_status"] == "available"


# --- auth_record shaping ---------------------------------------------------


def _cred(username, password, source="provided"):
    return SimpleNamespace(username=username, password=password, source=source)


def test_auth_record_no_credential_returns_prior_copy():
    ctx = SimpleNamespace(credential=_cred(None, None), lifecycle_state=None)
    prior = {"api_generation": "v1", "status": "detected"}
    out = actions.auth_record(ctx, prior)
    assert out == prior and out is not prior


def test_auth_record_empty_password_is_still_attempted(monkeypatch):
    seen: dict = {}

    def fake_verify(_factory, gen, user, pw):
        seen["args"] = (gen, user, pw)
        return CredentialResult(state="invalid", username=user, error_code="401")

    monkeypatch.setattr(actions, "verify_credential", fake_verify)
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: FakeClient())
    ctx = SimpleNamespace(credential=_cred("airflow", ""), lifecycle_state=None)
    out = actions.auth_record(ctx, {"api_generation": "v1"})
    assert seen["args"] == ("v1", "airflow", "")
    assert out["provided_credentials_ok"] is False and "credential_password" not in out


def test_auth_record_valid_sets_password_and_flags(monkeypatch):
    monkeypatch.setattr(
        actions, "verify_credential", lambda *a, **k: CredentialResult(state="valid", username="airflow")
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: FakeClient())
    ctx = SimpleNamespace(credential=_cred("airflow", "airflow"), lifecycle_state=None)
    out = actions.auth_record(ctx, {"api_generation": "v1"})
    assert out["provided_credentials_ok"] is True
    assert out["credential_password"] == "airflow"
    assert out["credential_state"] == "valid"
    assert out["default_credentials"] is False
    assert out["credential_results"][0]["username"] == "airflow"


def test_auth_record_invalid_omits_password(monkeypatch):
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda *a, **k: CredentialResult(state="invalid", username="admin", error_code="401"),
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: FakeClient())
    ctx = SimpleNamespace(credential=_cred("admin", "wrong"), lifecycle_state=None)
    out = actions.auth_record(ctx, {"api_generation": "v1"})
    assert out["provided_credentials_ok"] is False
    assert "credential_password" not in out
    assert out["default_credentials"] is False


def test_auth_record_default_source_valid_flags_default_credentials(monkeypatch):
    monkeypatch.setattr(
        actions, "verify_credential", lambda *a, **k: CredentialResult(state="valid", username="airflow")
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: FakeClient())
    ctx = SimpleNamespace(credential=_cred("airflow", "airflow", source="default"), lifecycle_state=None)
    out = actions.auth_record(ctx, {"api_generation": "v1"})
    assert out["default_credentials"] is True


def test_auth_record_restricted_counts_as_ok(monkeypatch):
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda *a, **k: CredentialResult(state="valid_but_restricted", username="u", error_code="403"),
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: FakeClient())
    ctx = SimpleNamespace(credential=_cred("u", "p"), lifecycle_state=None)
    out = actions.auth_record(ctx, {"api_generation": "v1"})
    assert out["provided_credentials_ok"] is True and out["credential_password"] == "p"


# --- capabilities_record shaping -------------------------------------------


def test_capabilities_skipped_when_credential_not_valid():
    ctx = SimpleNamespace(credential=_cred("u", "p"), lifecycle_state=None)
    out = actions.capabilities_record(ctx, {"api_generation": "v1", "credential_state": "invalid"})
    assert "role" not in out


def test_capabilities_sets_role_for_valid_v1(monkeypatch):
    monkeypatch.setattr(
        actions, "classify_role", lambda client, gen: RoleCapability(role="admin", evidence={"viewer": "200"})
    )
    captured: dict = {}
    monkeypatch.setattr(actions, "_client_for", lambda ctx, **kw: captured.update(kw) or FakeClient())
    ctx = SimpleNamespace(credential=_cred("airflow", "airflow"), lifecycle_state=None)
    out = actions.capabilities_record(ctx, {"api_generation": "v1", "credential_state": "valid"})
    assert out["role"] == "admin" and out["role_evidence"] == {"viewer": "200"}
    assert captured.get("basic_user") == "airflow" and captured.get("basic_password") == "airflow"


def test_capabilities_uses_bearer_for_v2(monkeypatch):
    monkeypatch.setattr(actions, "classify_role", lambda client, gen: RoleCapability(role="op", evidence={}))
    captured: dict = {}
    monkeypatch.setattr(actions, "_client_for", lambda ctx, **kw: captured.update(kw) or FakeClient())
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    state.bearer_token = "JWT-XYZ"
    ctx = SimpleNamespace(credential=_cred("airflow", "airflow"), lifecycle_state=state)
    try:
        out = actions.capabilities_record(ctx, {"api_generation": "v2", "credential_state": "valid"})
    finally:
        state.close()
    assert out["role"] == "op" and captured.get("bearer_token") == "JWT-XYZ"


# --- credential candidate building -----------------------------------------


def test_candidates_empty_username_kept_with_password():
    assert actions._build_credential_candidates(None, "pw", False) == [("", "pw", "provided")]


def test_candidates_whitespace_username_is_stripped():
    candidates = actions._build_credential_candidates("  airflow  ", "pw", False)
    assert candidates[0] == ("airflow", "pw", "provided")


def test_candidates_provided_matching_default_not_duplicated():
    candidates = actions._build_credential_candidates("admin", "admin", True)
    assert candidates[0] == ("admin", "admin", "provided")
    assert sum(1 for user, pw, _ in candidates if (user, pw) == ("admin", "admin")) == 1


def test_candidates_none_password_yields_defaults_only():
    candidates = actions._build_credential_candidates("airflow", None, True)
    assert candidates and all(source == "default" for *_, source in candidates)
    assert ("airflow", "airflow", "default") in candidates


# --- response parsing edges ------------------------------------------------


def test_response_json_none_on_transport_error():
    assert AirflowResponse(http_status=0, headers={}, body=b"", transport_error="x").json() is None


def test_response_json_none_on_empty_body():
    assert AirflowResponse(http_status=204, headers={}, body=b"").json() is None


def test_response_json_none_on_garbage_body():
    assert AirflowResponse(http_status=200, headers={}, body=b"{bad").json() is None


# --- transport scheme resolution -------------------------------------------


class _SchemePool:
    def __init__(self, *, error=None, status=200, body=b'{"version":"2.10.5"}') -> None:
        self.error = error
        self.status = status
        self.body = body
        self.calls: list = []

    def request(self, method, url, *, headers=None, body=None, response_size_cap=None):
        self.calls.append(url)
        return SimpleNamespace(status=self.status, body=self.body, headers={}, error=self.error)

    def close(self) -> None:
        pass


def test_resolve_scheme_defaults_http_for_plaintext_port():
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    state.pool = _SchemePool(status=200)  # type: ignore[assignment]
    assert state.resolve_scheme() == "http"


def test_resolve_scheme_flips_to_http_on_tls_mismatch():
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8443)
    state.pool = _SchemePool(error="[SSL: WRONG_VERSION_NUMBER] wrong version number")  # type: ignore[assignment]
    assert state.resolve_scheme() == "http"


def test_resolve_scheme_is_cached_after_first_probe():
    pool = _SchemePool(status=200)
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    state.pool = pool  # type: ignore[assignment]
    first, second = state.resolve_scheme(), state.resolve_scheme()
    assert first == second == "http" and len(pool.calls) == 1
