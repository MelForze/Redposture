from __future__ import annotations

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions


class _FakeClient:
    base_url = "http://h:8080"

    def __init__(self, responses):
        self.responses = responses
        self.calls: list = []

    def get(self, path, *, authed=True):
        self.calls.append(("GET", path, authed))
        v = self.responses.get(path, (404, b""))
        if v == "TRANSPORT":
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error="connection refused")
        status, body = v
        return AirflowResponse(http_status=status, headers={}, body=body)

    def post_json(self, path, payload, *, authed=False):
        self.calls.append(("POST", path, payload))
        status, body = self.responses.get(path, (404, b""))
        return AirflowResponse(http_status=status, headers={}, body=body)


def test_detect_confirmed_v2_captures_version_and_generation():
    c = _FakeClient({"/api/v2/version": (200, b'{"version":"3.0.2","git_version":"abc"}')})
    d = actions.detect_airflow(c)
    assert d.status == "confirmed"
    assert d.api_generation == "v2"
    assert d.version == "3.0.2"


def test_detect_confirmed_v1_when_v2_absent():
    c = _FakeClient({"/api/v2/version": (404, b""), "/api/v1/version": (200, b'{"version":"2.9.3"}')})
    d = actions.detect_airflow(c)
    assert d.status == "confirmed"
    assert d.api_generation == "v1"
    assert d.version == "2.9.3"


def test_detect_probable_from_health_when_version_gated():
    c = _FakeClient(
        {
            "/api/v2/version": (403, b""),
            "/api/v1/version": (403, b""),
            "/api/v2/monitor/health": (200, b'{"metadatabase":{"status":"healthy"},"scheduler":{}}'),
        }
    )
    d = actions.detect_airflow(c)
    assert d.status == "probable"
    assert d.api_generation == "v2"


def test_detect_not_airflow_when_nothing_matches():
    c = _FakeClient({})  # everything 404
    d = actions.detect_airflow(c)
    assert d.status == "not_airflow"


def test_detect_transport_failure_when_both_version_probes_fail():
    c = _FakeClient({"/api/v2/version": "TRANSPORT", "/api/v1/version": "TRANSPORT"})
    d = actions.detect_airflow(c)
    assert d.status == "transport_failure"
