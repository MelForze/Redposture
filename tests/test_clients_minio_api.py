from __future__ import annotations

from redposture_core.clients import minio_api


class _FakePool:
    def __init__(self, status, body, headers=None):
        self._status = status
        self._body = body
        self._headers = headers or {}
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, timeout=None, response_size_cap=10 * 1024 * 1024):
        self.calls.append({"method": method, "url": url, "headers": headers or {}})
        return _FakeResponse(self._status, self._body, self._headers)


class _FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers
        self.error = None


_ACCESS_DENIED_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>'
)


def test_get_service_root_parses_s3_error_code():
    pool = _FakePool(403, _ACCESS_DENIED_XML, {"Server": "MinIO"})
    client = minio_api.MinioClient(pool, scheme="http", host="10.0.0.5", port=9000)
    resp = client.get_service_root(signed=False)
    assert resp.http_status == 403
    assert resp.error is not None
    assert resp.error.code == "AccessDenied"
    assert pool.calls[0]["url"] == "http://10.0.0.5:9000/"


def test_signed_request_attaches_authorization_header():
    pool = _FakePool(200, b"<ListAllMyBucketsResult></ListAllMyBucketsResult>")
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AKID", secret_key="SECRET")
    client.get_service_root(signed=True)
    sent = pool.calls[0]["headers"]
    assert "Authorization" in sent
    assert sent["Authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert "x-amz-date" in sent


def test_list_objects_v2_builds_bounded_query():
    pool = _FakePool(200, b"<ListBucketResult></ListBucketResult>")
    client = minio_api.MinioClient(pool, scheme="https", host="h", port=443)
    client.list_objects_v2("mybucket", max_keys=1, prefix="a/", signed=False)
    url = pool.calls[0]["url"]
    assert url.startswith("https://h:443/mybucket?")
    assert "list-type=2" in url
    assert "max-keys=1" in url
    assert "prefix=a%2F" in url


def test_host_header_omits_scheme_default_port():
    http_client = minio_api.MinioClient(_FakePool(200, b""), scheme="http", host="h", port=80)
    https_client = minio_api.MinioClient(_FakePool(200, b""), scheme="https", host="h", port=443)
    assert http_client._host_header == "h"
    assert https_client._host_header == "h"


def test_host_header_keeps_non_default_port():
    http_client = minio_api.MinioClient(_FakePool(200, b""), scheme="http", host="h", port=9000)
    https_client = minio_api.MinioClient(_FakePool(200, b""), scheme="https", host="h", port=10443)
    assert http_client._host_header == "h:9000"
    assert https_client._host_header == "h:10443"


def test_transport_exception_becomes_transport_error():
    class _BoomPool:
        def request(self, *a, **k):
            raise OSError("connection refused")

    client = minio_api.MinioClient(_BoomPool(), scheme="http", host="h", port=9000)
    resp = client.health("live")
    assert resp.transport_error is not None
    assert resp.http_status == 0


def test_admin_probes_are_get_and_signed():
    pool = _FakePool(200, b"{}")
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    for call, path in (
        (client.account_info, "/minio/admin/v3/accountinfo"),
        (client.list_users, "/minio/admin/v3/list-users"),
        (client.list_canned_policies, "/minio/admin/v3/list-canned-policies"),
    ):
        pool.calls.clear()
        call(signed=True)
        assert pool.calls[0]["method"] == "GET"
        assert pool.calls[0]["url"].endswith(path)
        assert "Authorization" in pool.calls[0]["headers"]


class _BodyCapturingPool:
    def __init__(self, status, body=b"", headers=None):
        self._status = status
        self._body = body
        self._headers = headers or {}
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, timeout=None, response_size_cap=10 * 1024 * 1024):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        return _FakeResponse(self._status, self._body, self._headers)


def test_put_object_sends_body_and_signs_with_body_hash():
    import hashlib

    pool = _BodyCapturingPool(200)
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    payload = b"redposture-probe"
    resp = client.put_object("mybucket", ".redposture-probe-abc", payload, signed=True)
    assert resp.http_status == 200
    call = pool.calls[0]
    assert call["method"] == "PUT"
    assert call["url"] == "http://h:9000/mybucket/.redposture-probe-abc"
    assert call["body"] == payload
    # SigV4 must bind the actual body hash, not the empty-payload hash
    assert call["headers"]["x-amz-content-sha256"] == hashlib.sha256(payload).hexdigest()
    assert call["headers"]["Authorization"].startswith("AWS4-HMAC-SHA256 ")


def test_delete_object_sends_delete_and_empty_payload_hash():
    from redposture_core.clients import s3_sigv4

    pool = _BodyCapturingPool(204)
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    resp = client.delete_object("mybucket", ".redposture-probe-abc", signed=True)
    assert resp.http_status == 204
    call = pool.calls[0]
    assert call["method"] == "DELETE"
    assert call["body"] in (None, b"")
    assert call["headers"]["x-amz-content-sha256"] == s3_sigv4.EMPTY_PAYLOAD_HASH


def test_put_object_percent_encodes_key():
    pool = _BodyCapturingPool(200)
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    client.put_object("b", "dir/probe file.txt", b"x", signed=True)
    assert "dir/probe%20file.txt" in pool.calls[0]["url"]
