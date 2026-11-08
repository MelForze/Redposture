"""The S3 QA peer must verify the secret's signature, not just an access key."""

from __future__ import annotations

import datetime
import xml.etree.ElementTree as ET

import pytest

from redposture_core.clients.s3_sigv4 import EMPTY_PAYLOAD_HASH, sign_request
from scripts import performance_http_fixtures as peers


def signed(access="reader", secret="correct", path="/"):
    headers = {
        "Host": "qa.local:9000",
        **sign_request(
            method="GET",
            host="qa.local:9000",
            path=path,
            payload_hash=EMPTY_PAYLOAD_HASH,
            access_key=access,
            secret_key=secret,
            timestamp=datetime.datetime(2026, 11, 7, tzinfo=datetime.timezone.utc),
        ),
    }
    return {k.lower().encode(): v.encode() for k, v in headers.items()}


def request(headers, *, path="/", limited=False, method="GET", body=b""):
    wire = peers.minio_reply(method, path, headers, body, valid_pair=("reader", "correct"), limited=limited)
    head, _, payload = wire.partition(b"\r\n\r\n")
    return int(head.split()[1]), payload


@pytest.mark.parametrize(
    "access,secret,code",
    [
        ("unknown", "correct", "InvalidAccessKeyId"),
        ("reader", "wrong", "SignatureDoesNotMatch"),
    ],
)
def test_key_and_secret_failures_are_distinct_auth_errors(access, secret, code):
    status, payload = request(signed(access, secret))
    assert status == 403 and ET.fromstring(payload).findtext("Code") == code


def test_correct_signature_can_list_buckets_and_unsigned_request_cannot():
    status, body = request(signed())
    assert status == 200
    root = ET.fromstring(body)
    namespace = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    assert root.tag == namespace + "ListAllMyBucketsResult"
    assert [
        row.findtext(namespace + "Name") for row in root.findall(namespace + "Buckets/" + namespace + "Bucket")
    ] == [
        "analytics-reports",
        "pipeline-artifacts",
        "audit-backups",
    ]
    assert request({})[0] == 403


@pytest.mark.parametrize(
    "change",
    [
        {b"host": b"another.local"},
        {b"x-amz-date": b"20260101T000000Z"},
        {b"x-amz-content-sha256": b"0" * 64},
        {b"authorization": b"AWS4-HMAC-SHA256 broken"},
    ],
)
def test_tampering_does_not_pass_when_the_access_key_is_still_correct(change):
    assert request({**signed(), **change})[0] in {400, 403}


def test_request_path_and_body_are_part_of_the_verified_signature():
    assert request(signed(), path="/changed")[0] == 403
    assert request(signed(), body=b"changed")[0] == 403


def test_limited_acl_denies_only_after_a_real_signature_check_and_writes_stay_disabled():
    code, payload = request(signed(), limited=True)
    assert code == 403 and ET.fromstring(payload).findtext("Code") == "AccessDenied"
    code, payload = request(signed(secret="wrong"), limited=True)
    assert code == 403 and ET.fromstring(payload).findtext("Code") == "SignatureDoesNotMatch"
    assert request(signed(), method="POST")[0] == 403


def test_health_is_public_but_unknown_routes_are_not_successful():
    assert request({}, path="/minio/health/live")[0] == 200
    assert request(signed(path="/unsupported"), path="/unsupported")[0] == 404


def test_official_aws_signature_vector_is_verified_without_using_the_product_signer():
    # AWS S3 header-based authentication, GET /test.txt, 2013-05-24.
    headers = {
        b"host": b"examplebucket.s3.amazonaws.com",
        b"range": b"bytes=0-9",
        b"x-amz-date": b"20130524T000000Z",
        b"x-amz-content-sha256": EMPTY_PAYLOAD_HASH.encode(),
        b"authorization": b"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        b"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        b"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    }
    secret = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert peers.verified_s3_access_key("GET", "/test.txt", headers, b"", secret_key=secret) == "AKIAIOSFODNN7EXAMPLE"
    assert (
        peers.verified_s3_access_key("GET", "/test.txt", {**headers, b"range": b"bytes=0-8"}, b"", secret_key=secret)
        is None
    )


@pytest.mark.parametrize("query", ["acl", "b=2&a=1&a=0", "prefix=a%2Fb&token=a%2Bb", "prefix=a+b"])
def test_encoded_query_and_empty_subresource_are_verified_and_tampering_is_rejected(query):
    fields = sign_request(
        method="GET",
        host="qa.local:9000",
        path="/bucket//object%20name",
        query=query,
        payload_hash=EMPTY_PAYLOAD_HASH,
        access_key="reader",
        secret_key="correct",
    )
    headers = {b"host": b"qa.local:9000", **{k.lower().encode(): v.encode() for k, v in fields.items()}}
    path = "/bucket//object%20name?" + query
    assert peers.verified_s3_access_key("GET", path, headers, b"", secret_key="correct") == "reader"
    assert peers.verified_s3_access_key("GET", path + "&extra=1", headers, b"", secret_key="correct") is None
