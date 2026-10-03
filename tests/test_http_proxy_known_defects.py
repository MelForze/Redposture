"""Opt-in reproductions from the real Airflow reverse-proxy QA stand."""

from __future__ import annotations

import gzip
import json

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.actions import detect_airflow, verify_credential


@pytest.mark.known_defect_audit
def test_airflow_identical_anonymous_and_bad_basic_403_cannot_verify_identity() -> None:
    problem = json.dumps(
        {
            "detail": None,
            "status": 403,
            "title": "Forbidden",
            "type": "https://airflow.apache.org/docs/apache-airflow/2.9.2/"
            "stable-rest-api-ref.html#section/Errors/PermissionDenied",
        }
    ).encode()

    class Client:
        def get(self, path: str, *, authed: bool = True) -> AirflowResponse:
            return AirflowResponse(http_status=403, headers={"Content-Type": "application/problem+json"}, body=problem)

    anonymous = Client().get("/api/v1/dags", authed=False)
    result = verify_credential(lambda **kwargs: Client(), "v1", "airflow", "wrong")
    assert anonymous.http_status == 403
    assert result.state == "verification_unavailable"


@pytest.mark.known_defect_audit
def test_airflow_gzipped_version_with_valid_health_confirms_service() -> None:
    version = gzip.compress(b'{"version":"2.9.2","git_version":""}')
    health = b'{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"}}'

    class Client:
        base_url = "https://127.0.0.1:28443"
        base_path = "/gzip"

        def get(self, path: str, *, authed: bool = False) -> AirflowResponse:
            if path == "/api/v2/version":
                return AirflowResponse(http_status=404, headers={}, body=b"")
            if path == "/api/v1/version":
                return AirflowResponse(
                    http_status=200,
                    headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
                    body=version,
                )
            if path == "/api/v1/health":
                return AirflowResponse(http_status=200, headers={"Content-Type": "application/json"}, body=health)
            return AirflowResponse(http_status=404, headers={}, body=b"")

    detection = detect_airflow(Client())
    assert detection.status == "confirmed"
    assert detection.version == "2.9.2"
