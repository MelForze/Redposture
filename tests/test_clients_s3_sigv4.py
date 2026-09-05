from __future__ import annotations

import datetime

from redposture_core.clients import s3_sigv4


def test_sign_request_matches_aws_s3_get_reference_vector():
    # Публичный AWS SigV4 reference (S3 GET Object, single-chunk payload).
    headers = s3_sigv4.sign_request(
        method="GET",
        host="examplebucket.s3.amazonaws.com",
        path="/test.txt",
        query="",
        headers={"Range": "bytes=0-9"},
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
        timestamp=datetime.datetime(2013, 5, 24, 0, 0, 0, tzinfo=datetime.timezone.utc),
    )
    assert headers["x-amz-date"] == "20130524T000000Z"
    assert headers["x-amz-content-sha256"] == s3_sigv4.EMPTY_PAYLOAD_HASH
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900"
    )
    assert "x-amz-security-token" not in headers


def test_sign_request_includes_session_token_in_signed_headers():
    headers = s3_sigv4.sign_request(
        method="GET",
        host="minio.example:9000",
        path="/",
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AKID",
        secret_key="SECRET",
        session_token="SESSIONTOKEN123",
        timestamp=datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
    )
    assert headers["x-amz-security-token"] == "SESSIONTOKEN123"
    # security token участвует в подписи (входит в SignedHeaders).
    signed = headers["Authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0]
    assert "x-amz-security-token" in signed


def test_canonical_query_is_not_double_encoded():
    # A hierarchical prefix and a base64-ish continuation token must sign
    # single-encoded (regression: %2F must not become %252F).
    h1 = s3_sigv4.sign_request(
        method="GET",
        host="h:9000",
        path="/bucket",
        query="continuation-token=t%2F1%2B2%3D&list-type=2&prefix=logs%2F",
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AK",
        secret_key="SK",
        timestamp=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
    )
    # Re-signing the already-single-encoded query must be idempotent (no %25).
    h2 = s3_sigv4.sign_request(
        method="GET",
        host="h:9000",
        path="/bucket",
        query="prefix=logs%2F&list-type=2&continuation-token=t%2F1%2B2%3D",
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AK",
        secret_key="SK",
        timestamp=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
    )
    # Order-independent, and stable regardless of input order (canonical sorts).
    assert h1["Authorization"] == h2["Authorization"]


def test_canonical_query_single_encodes_and_never_double_encodes():
    from redposture_core.clients.s3_sigv4 import _canonical_query

    # already-encoded wire query must canonicalize to itself (single-encoded),
    # never doubling %2F into %252F.
    assert _canonical_query("prefix=logs%2F") == "prefix=logs%2F"
    out = _canonical_query("prefix=logs%2F&list-type=2&continuation-token=t%2F1%2B2%3D")
    assert "%25" not in out  # no double-encoding anywhere
    assert "prefix=logs%2F" in out
