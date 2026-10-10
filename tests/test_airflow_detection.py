from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.airflow import actions
from redposture_core.targeting import ScanTargetSpec


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


def test_scheme_probe_response_is_reused_for_same_airflow_api_url() -> None:
    class Pool:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def request(self, _method: str, url: str, **_kwargs: object) -> HttpResponse:
            self.paths.append(url)
            if url.endswith("/api/v2/version"):
                return HttpResponse(200, b'{"version":"3.0.2","git_version":"abc"}', {}, final_url=url)
            return HttpResponse(403, b"", {}, final_url=url)

    args = SimpleNamespace(timeout=1.0, retries=0)
    state = actions.AirflowLifecycleState(args, "airflow.test", 8080, scheme="http")
    pool = Pool()
    state.pool = pool  # type: ignore[assignment]
    ctx = SimpleNamespace(
        args=args,
        host="airflow.test",
        port=8080,
        target=ScanTargetSpec("airflow.test", scheme="http", explicit_port=8080),
        lifecycle_state=state,
    )
    assert actions.detect_record(ctx)["detection_status"] == "confirmed"
    assert sum(path.endswith("/api/v2/version") for path in pool.paths) == 1


def test_detect_confirmed_v1_when_v2_absent():
    c = _FakeClient(
        {
            "/api/v2/version": (404, b""),
            "/api/v1/version": (200, b'{"version":"2.9.3"}'),
            "/api/v1/health": (
                200,
                b'{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"}}',
            ),
        }
    )
    d = actions.detect_airflow(c)
    assert d.status == "confirmed"
    assert d.api_generation == "v1"
    assert d.version == "2.9.3"


def test_detect_probable_from_health_when_version_gated():
    c = _FakeClient(
        {
            "/api/v2/version": (403, b""),
            "/api/v1/version": (403, b""),
            "/api/v2/monitor/health": (
                200,
                b'{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"}}',
            ),
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


def test_real_airflow_211_problem_with_null_detail_confirms_version_only_endpoint() -> None:
    problem = (
        b'{"detail":null,"status":403,"title":"Forbidden",'
        b'"type":"https://airflow.apache.org/docs/apache-airflow/2.11.2/'
        b'stable-rest-api-ref.html#section/Errors/PermissionDenied"}'
    )
    client = _FakeClient(
        {
            "/api/v2/version": (404, b""),
            "/api/v1/version": (200, b'{"git_version":"","version":"2.11.2"}'),
            "/api/v1/dags": (403, problem),
        }
    )
    result = actions.detect_airflow(client)
    assert result.status == "confirmed"
    assert result.api_generation == "v1" and result.version == "2.11.2"


def test_generic_problem_with_null_detail_does_not_confirm_airflow() -> None:
    client = _FakeClient(
        {
            "/api/v1/version": (200, b'{"version":"2.11.2"}'),
            "/api/v1/dags": (
                403,
                b'{"detail":null,"status":403,"title":"Forbidden",'
                b'"type":"https://example.invalid/docs/Errors/PermissionDenied"}',
            ),
        }
    )
    assert actions.detect_airflow(client).status == "not_airflow"


def test_generic_problem_with_detail_does_not_confirm_version_only_airflow() -> None:
    client = _FakeClient(
        {
            "/api/v1/version": (200, b'{"version":"2.11.2"}'),
            "/api/v1/dags": (403, b'{"detail":"Access denied","status":403,"title":"Forbidden"}'),
        }
    )
    assert actions.detect_airflow(client).status == "not_airflow"


@given(st.text(max_size=512))
def test_untrusted_problem_type_cannot_crash_detection_or_confirm_foreign_service(problem_type: str) -> None:
    problem = json.dumps(
        {
            "detail": None,
            "status": 403,
            "title": "Forbidden",
            "type": problem_type,
        }
    ).encode()
    client = _FakeClient(
        {
            "/api/v1/version": (200, b'{"version":"2.11.2"}'),
            "/api/v1/dags": (403, problem),
        }
    )
    result = actions.detect_airflow(client)
    assert result.status == "not_airflow"


@pytest.mark.parametrize("problem_type", ["http://[", "https://[x", "http://[::1", "//[bad"])
def test_malformed_problem_uri_never_crashes_detection(problem_type: str) -> None:
    problem = json.dumps({"detail": None, "status": 403, "title": "Forbidden", "type": problem_type}).encode()
    client = _FakeClient({"/api/v1/version": (200, b'{"version":"2.11.2"}'), "/api/v1/dags": (403, problem)})
    assert actions.detect_airflow(client).status == "not_airflow"
