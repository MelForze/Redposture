from __future__ import annotations

import json

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions


class _FakeClient:
    def __init__(self, statuses):
        self.statuses = statuses  # path -> status

    def get(self, path, *, authed=True):
        status = self.statuses.get(path, 404)
        if status == 0:
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error="refused")
        body = json.dumps({"dags": [], "total_entries": 0}).encode() if status == 200 else b"[]"
        return AirflowResponse(http_status=status, headers={}, body=body)


def test_generic_200_page_does_not_claim_anonymous_dag_access():
    class _LoginPageClient:
        def get(self, _path, *, authed=True):
            return AirflowResponse(http_status=200, headers={"Content-Type": "text/html"}, body=b"<html>login</html>")

    result = actions.classify_anonymous(_LoginPageClient(), "v1")
    assert result.auth_required is None
    assert result.dags_allowed is None


def test_malformed_dag_collection_does_not_claim_anonymous_access():
    class _MalformedClient:
        def get(self, _path, *, authed=True):
            return AirflowResponse(
                http_status=200,
                headers={"Content-Type": "application/json"},
                body=b'{"dags":["not-an-object"],"total_entries":1}',
            )

    result = actions.classify_anonymous(_MalformedClient(), "v1")
    assert result.auth_required is None
    assert result.dags_allowed is None


def test_keycloak_redirect_page_is_sso_not_unknown():
    class _SsoClient:
        def get(self, _path, *, authed=True):
            return AirflowResponse(
                http_status=200,
                headers={"Content-Type": "text/html"},
                body=b'<html><form id="kc-form-login"></form></html>',
                final_url="https://sso.example/realms/company/protocol/openid-connect/auth?client_id=airflow",
                redirect_history=("http://airflow.example/api/v1/dags",),
            )

    result = actions.classify_anonymous(_SsoClient(), "v1")
    assert result.auth_required is True
    assert result.auth_method == "sso"
    assert result.dags_allowed is False
    assert result.sso_provider == "keycloak"


def test_slow_identity_provider_is_sso_from_redirect_even_when_page_times_out():
    class _SlowSsoClient:
        def get(self, _path, *, authed=True):
            return AirflowResponse(
                http_status=0,
                headers={},
                body=b"",
                transport_error="timed out while loading identity provider",
                final_url="https://sso.example/realms/company/protocol/openid-connect/auth?client_id=airflow",
                redirect_history=("http://airflow.example/api/v1/dags",),
            )

    result = actions.classify_anonymous(_SlowSsoClient(), "v1")
    assert result.reachable is True
    assert result.auth_required is True
    assert result.auth_method == "sso"
    assert result.dags_allowed is False
    assert result.sso_provider == "keycloak"


def test_anonymous_dag_access_is_flagged_without_role_inference():
    c = _FakeClient({"/api/v1/dags": 200, "/api/v1/pools": 200, "/api/v1/eventLogs": 200})
    r = actions.classify_anonymous(c, "v1")
    assert r.auth_required is False and r.dags_allowed is True


def test_anonymous_dag_access_works_for_v2():
    c = _FakeClient({"/api/v2/dags": 200, "/api/v2/pools": 200, "/api/v2/eventLogs": 403})
    r = actions.classify_anonymous(c, "v2")
    assert r.auth_required is False and r.dags_allowed is True


def test_auth_enforced_when_viewer_401():
    c = _FakeClient({"/api/v1/dags": 401})
    r = actions.classify_anonymous(c, "v1")
    assert r.auth_required is True and r.dags_allowed is False


def test_unreachable_on_transport_error():
    c = _FakeClient({"/api/v1/dags": 0})
    r = actions.classify_anonymous(c, "v1")
    assert r.reachable is False
    assert r.dags_allowed is None
