from __future__ import annotations

from types import SimpleNamespace

import pytest

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


def _resp(status, error=None, transport_error=None, body=b""):
    return MinioResponse(http_status=status, headers={}, body=body, error=error, transport_error=transport_error)


@pytest.mark.parametrize(
    "body",
    [
        b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>",
        b"<ListAllMyBucketsResult><Buckets><Bucket><Name>backups</Name></Bucket></Buckets></ListAllMyBucketsResult>",
        b'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>',
        b'<s3:ListAllMyBucketsResult xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/">'
        b"<s3:Buckets/></s3:ListAllMyBucketsResult>",
    ],
)
def test_valid_credentials_on_s3_bucket_listing(body):
    result = actions.verify_credential(_StubClient(_resp(200, body=body)))
    assert result.state == "valid"
    assert result.access_key == "AKID"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<html><body><form action='/login'>Sign in</form></body></html>",
        b'{"ListAllMyBucketsResult": {"Buckets": []}}',
        b"<ListAllMyBucketsResult><Buckets>",
        b"<ListAllMyBucketsResult/>",
        b"<ListAllMyBucketsResult><Wrapper><Buckets/></Wrapper></ListAllMyBucketsResult>",
        b"<html><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult></html>",
        b"<ListBucketResult><Buckets/></ListBucketResult>",
        b'<ListAllMyBucketsResult xmlns="urn:unrelated"><Buckets/></ListAllMyBucketsResult>',
        b'<?xml version="1.0" encoding="unknown-encoding"?><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>',
    ],
)
def test_unrelated_or_incomplete_response_cannot_verify_credentials(body):
    result = actions.verify_credential(_StubClient(_resp(200, body=body)))
    assert result.state == "verification_unavailable"
    assert result.access_key == "AKID"


@pytest.mark.parametrize("status", [201, 202, 204, 206, 299])
def test_other_success_status_cannot_verify_credentials(status):
    response = _resp(status, body=b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
    assert actions.verify_credential(_StubClient(response)).state == "verification_unavailable"


@pytest.mark.parametrize("source", ["cli", "default"])
def test_html_response_leaves_credential_verdict_unknown(monkeypatch, source):
    client = _StubClient(_resp(200, body=b"<html>Sign in</html>"))
    monkeypatch.setattr(actions, "_client_for", lambda ctx, credential: client)
    ctx = SimpleNamespace(
        args=SimpleNamespace(session_token=None),
        credential=SimpleNamespace(username="AKID", password="wrong", source=source),
    )
    record = actions.auth_record(ctx, {"detection_status": "confirmed"})
    assert record["credential_state"] == "verification_unavailable"
    assert record["provided_credentials_ok"] is None
    assert record["default_credentials"] is False
    assert "credential_secret" not in record


def test_unavailable_credential_does_not_run_followup_requests(monkeypatch):
    def unexpected_client(*args):
        pytest.fail("Unverified credentials must not run follow-up operations")

    monkeypatch.setattr(actions, "_client_for", unexpected_client)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            show_buckets=True,
            show_objects=True,
            discover=True,
            probe_write=True,
            dump=True,
            download="unused",
        ),
    )
    prior = {"detection_status": "confirmed", "credential_state": "verification_unavailable"}
    assert actions.capabilities_record(ctx, prior) == prior
    assert actions.data_record(ctx, prior) == prior


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
