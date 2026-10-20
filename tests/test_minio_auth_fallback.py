"""Credential fallbacks must prove a signed response, not just reach a proxy."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.minio_api import MinioClient
from redposture_core.clients.s3_sigv4 import EMPTY_PAYLOAD_HASH, sign_request
from redposture_core.modules.minio import actions


class Gateway:
    """HTTP transport boundary; the actual MinIO client signs every request."""

    def __init__(self, *, account: bytes | None = None, location: bool = False, ignores_auth: bool = False):
        self.account = account
        self.location = location
        self.ignores_auth = ignores_auth
        self.calls: list[tuple[str, str, bool]] = []

    def request(self, method, url, *, headers, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path
        signed = bool(headers.get("Authorization"))
        self.calls.append((method, url, signed))
        status, body = 403, b"<html>gateway blocked</html>"
        if path.endswith("/accountinfo") and self.account is not None:
            status, body = 200, self.account
        if path == "/edge/storage/private" and self.location:
            status, body = 200, b'<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>'
        if status == 200 and not self.ignores_auth:
            if not signed:
                status, body = 403, b"<Error><Code>AccessDenied</Code></Error>"
            else:
                expected = sign_request(
                    method=method,
                    host="localhost:9000",
                    path=path,
                    query=parsed.query,
                    payload_hash=EMPTY_PAYLOAD_HASH,
                    access_key="reader",
                    secret_key="reader-secret",
                    timestamp=datetime.strptime(headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc),
                )
                if headers["Authorization"] != expected["Authorization"]:
                    status, body = 403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>"
        return SimpleNamespace(status=status, body=body, headers={"Content-Type": "application/xml"}, error=None)


def client(pool: Gateway) -> MinioClient:
    return MinioClient(
        pool,
        scheme="http",
        host="localhost",
        port=9000,
        base_path="/edge/storage",
        access_key="reader",
        secret_key="reader-secret",
    )


ACCOUNT = b'{"accountName":"reader","server":{"backendType":"Erasure"},"policy":{"Version":"2012-10-17","Statement":[]},"buckets":[]}'


@pytest.mark.parametrize(
    "account",
    [
        ACCOUNT,
        b'{"AccountName":"reader","Server":{"Type":2},"Policy":{"Version":"2012-10-17","Statement":[]},"Buckets":[]}',
    ],
)
def test_account_info_recovers_valid_pair_when_root_and_admin_info_are_blocked(account):
    pool = Gateway(account=account)
    result = actions.verify_credential(client(pool))
    assert result.state == "valid_but_restricted"
    assert all(method == "GET" for method, _, _ in pool.calls)
    assert len(pool.calls) == 5  # root, info, accountinfo, anonymous + bad signature


def test_bucket_location_recovers_pair_without_listing_or_admin_permissions():
    pool = Gateway(location=True)
    result = actions.verify_credential(client(pool), known_bucket="private")
    assert result.state == "valid_but_restricted"
    assert ("GET", "http://localhost:9000/edge/storage/private?location=", True) in pool.calls
    assert len(pool.calls) == 6


@pytest.mark.parametrize("known_bucket", [None, "private"])
def test_public_or_cached_fallback_cannot_validate_arbitrary_credentials(known_bucket):
    pool = Gateway(account=ACCOUNT, location=True, ignores_auth=True)
    result = actions.verify_credential(client(pool), known_bucket=known_bucket)
    assert result.state == "verification_unavailable"


@pytest.mark.parametrize(
    "body", [b"{}", b'{"buckets":[]}', b'{"policy":{}}', b'{"accountName":"reader"}', b"<html>Login</html>"]
)
def test_generic_account_response_does_not_prove_authentication(body):
    result = actions.verify_credential(client(Gateway(account=body)))
    assert result.state == "verification_unavailable"


def test_bucket_probe_is_not_sent_without_explicit_bucket():
    pool = Gateway(location=True)
    assert actions.verify_credential(client(pool)).state == "verification_unavailable"
    assert len(pool.calls) == 3


def test_debug_explains_every_probe_without_echoing_secrets_or_control_sequences():
    pool = Gateway(account=b"<html>reader-secret\n\x1b[31m upstream failure</html>" + b"x" * 3000)
    messages: list[str] = []
    result = actions.verify_credential(client(pool), debug_emit=messages.append)
    assert result.state == "verification_unavailable"
    assert len(messages) == 3
    assert all("HTTP=403" in line or "HTTP=200" in line for line in messages)
    assert all("verdict=verification_unavailable" in line for line in messages)
    assert any("probe=account_info" in line and "body=" in line for line in messages)
    assert all("reader-secret" not in line and "\n" not in line and "\x1b" not in line for line in messages)
    assert max(map(len, messages)) < 1000


def test_auth_hook_passes_bucket_and_debug_callback(monkeypatch):
    pool = Gateway(location=True)
    monkeypatch.setattr(actions, "_client_for", lambda ctx, credential: client(pool))
    messages: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(bucket="private", debug=True, session_token=None),
        credential=SimpleNamespace(username="reader", password="reader-secret"),
        debug_emit=messages.append,
    )
    record = actions.auth_record(ctx, {"auth_required": True})
    assert record["provided_credentials_ok"] is True
    assert record["credential_state"] == "valid_but_restricted"
    assert any("probe=bucket_location" in line for line in messages)
    assert "probe=" not in json.dumps(record)


def test_fallback_success_does_not_claim_anonymous_denial_validates_credentials():
    messages: list[str] = []
    assert (
        actions.verify_credential(client(Gateway(account=ACCOUNT)), debug_emit=messages.append).state
        == "valid_but_restricted"
    )
    anonymous = next(line for line in messages if "probe=account_info_anonymous_control" in line)
    assert "verdict=anonymous_denied" in anonymous


def test_debug_callback_is_silent_without_debug_flag(monkeypatch):
    pool = Gateway(account=ACCOUNT)
    monkeypatch.setattr(actions, "_client_for", lambda ctx, credential: client(pool))
    messages: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(debug=False, session_token=None),
        credential=SimpleNamespace(username="reader", password="reader-secret"),
        debug_emit=messages.append,
    )
    assert actions.auth_record(ctx, {"auth_required": True})["provided_credentials_ok"] is True
    assert messages == []


@pytest.mark.parametrize("failure", ["transport", "truncated", "generic_denial"])
def test_failing_signature_control_never_turns_public_data_into_verified_pair(failure):
    class FaultGateway(Gateway):
        def request(self, method, url, *, headers, **kwargs):
            response = super().request(method, url, headers=headers, **kwargs)
            if b"SignatureDoesNotMatch" in response.body:
                if failure == "transport":
                    response.error = "control request timed out"
                elif failure == "truncated":
                    response.status = 200
                    response.body = ACCOUNT
                    response.truncated = True
                else:
                    response.body = b"<html>denied by proxy</html>"
            return response

    result = actions.verify_credential(client(FaultGateway(account=ACCOUNT)))
    assert result.state == "verification_unavailable"


def test_no_extra_verifier_requests_after_decisive_s3_response():
    class SignedS3Gateway(Gateway):
        def request(self, method, url, *, headers, **kwargs):
            response = super().request(method, url, headers=headers, **kwargs)
            response.status = 200
            response.body = b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"
            return response

    pool = SignedS3Gateway(account=ACCOUNT, location=True)
    assert actions.verify_credential(client(pool), known_bucket="private").state == "valid"
    assert len(pool.calls) == 1
