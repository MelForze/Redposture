from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, response, access_key="AKID"):
        self._response = response
        self.access_key = access_key
        self.scheme, self.host, self.port = "http", "h", 9000

    @property
    def base_url(self):
        return "http://h:9000"

    def get_service_root(self, *, signed):
        assert signed is True
        return self._response


def _resp(status, error=None, transport_error=None):
    return MinioResponse(http_status=status, headers={}, body=b"", error=error, transport_error=transport_error)


def test_valid_credentials_on_2xx():
    result = actions.verify_credential(_StubClient(_resp(200)))
    assert result.state == "valid"
    assert result.access_key == "AKID"


def test_invalid_on_signature_mismatch():
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "SignatureDoesNotMatch", ""))))
    assert result.state == "invalid"
    assert result.error_code == "SignatureDoesNotMatch"


def test_invalid_on_unknown_access_key():
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "InvalidAccessKeyId", ""))))
    assert result.state == "invalid"


def test_valid_but_restricted_on_access_denied():
    # Валидная подпись, но нет прав на ListBuckets -> креды валидны, ограничены.
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "AccessDenied", ""))))
    assert result.state == "valid_but_restricted"


def test_transient_on_transport_error():
    result = actions.verify_credential(_StubClient(_resp(0, transport_error="connection reset")))
    assert result.state == "transient_failure"


def test_verification_unavailable_on_unparseable():
    result = actions.verify_credential(_StubClient(_resp(500)))
    assert result.state == "verification_unavailable"
