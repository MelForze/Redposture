"""Airflow reverse-proxy regression cases."""

from __future__ import annotations

import gzip
import json

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.actions import detect_airflow, verify_credential


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


def test_airflow_403_requires_private_resource_proof_for_restricted_identity() -> None:
    problem = b'{"status":403,"title":"Forbidden","detail":"Permission denied"}'
    variables = b'{"variables":[],"total_entries":0}'

    class Client:
        def __init__(self, authenticated: bool, public_variables: bool) -> None:
            self.authenticated = authenticated
            self.public_variables = public_variables

        def get(self, path: str, *, authed: bool = True) -> AirflowResponse:
            if path.startswith("/api/v1/variables") and ((self.authenticated and authed) or self.public_variables):
                return AirflowResponse(http_status=200, headers={}, body=variables)
            return AirflowResponse(http_status=403, headers={}, body=problem)

    private = verify_credential(lambda **kwargs: Client(bool(kwargs), False), "v1", "viewer", "secret")
    public = verify_credential(lambda **kwargs: Client(bool(kwargs), True), "v1", "viewer", "secret")
    assert private.state == "valid_but_restricted"
    assert public.state == "verification_unavailable"


def test_airflow_gzip_json_rejects_corrupt_and_oversized_payloads() -> None:
    from redposture_core.clients.airflow_api import AirflowResponse

    headers = {"content-encoding": "GZip"}
    assert AirflowResponse(200, headers, b"not gzip").json() is None
    oversized = gzip.compress(b'{"data":"' + b"x" * (2 * 1024 * 1024) + b'"}')
    assert AirflowResponse(200, headers, oversized).json() is None
