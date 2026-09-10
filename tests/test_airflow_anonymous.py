from __future__ import annotations

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions


class _FakeClient:
    def __init__(self, statuses):
        self.statuses = statuses  # path -> status

    def get(self, path, *, authed=True):
        status = self.statuses.get(path, 404)
        if status == 0:
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error="refused")
        return AirflowResponse(http_status=status, headers={}, body=b"[]")


def test_anonymous_admin_is_flagged():
    c = _FakeClient({"/api/v1/dags": 200, "/api/v1/pools": 200, "/api/v1/eventLogs": 200})
    r = actions.classify_anonymous(c, "v1")
    assert r.auth_required is False and r.role == "admin"


def test_anonymous_viewer_only():
    c = _FakeClient({"/api/v1/dags": 200, "/api/v1/pools": 403, "/api/v1/eventLogs": 403})
    r = actions.classify_anonymous(c, "v1")
    assert r.auth_required is False and r.role == "viewer"


def test_anonymous_op():
    c = _FakeClient({"/api/v2/dags": 200, "/api/v2/pools": 200, "/api/v2/eventLogs": 403})
    r = actions.classify_anonymous(c, "v2")
    assert r.auth_required is False and r.role == "op"


def test_auth_enforced_when_viewer_401():
    c = _FakeClient({"/api/v1/dags": 401})
    r = actions.classify_anonymous(c, "v1")
    assert r.auth_required is True and r.role == "none"


def test_unreachable_on_transport_error():
    c = _FakeClient({"/api/v1/dags": 0})
    r = actions.classify_anonymous(c, "v1")
    assert r.reachable is False
