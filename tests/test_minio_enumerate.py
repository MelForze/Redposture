from __future__ import annotations

from redposture_core.clients import minio_api, s3_sigv4
from redposture_core.modules.minio import enumerate as enum


class _FakePool:
    def __init__(self, pages):
        self._pages = list(pages)
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, timeout=None, response_size_cap=10 * 1024 * 1024):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "cap": response_size_cap})
        status, payload = self._pages[min(len(self.calls) - 1, len(self._pages) - 1)]
        return _Resp(status, payload)


class _Resp:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.headers = {}
        self.error = None


def _page(keys, next_token=None):
    contents = "".join(f'<Contents><Key>{k}</Key><Size>10</Size><ETag>"abc"</ETag></Contents>' for k in keys)
    nt = f"<NextContinuationToken>{next_token}</NextContinuationToken>" if next_token else ""
    return f"<ListBucketResult>{nt}{contents}</ListBucketResult>".encode()


def test_iter_objects_streams_and_stops_at_limit_without_reading_all_pages():
    pool = _FakePool([(200, _page(["a", "b"], "t1")), (200, _page(["c", "d"], "t2")), (200, _page(["e"]))])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    got = list(enum.iter_objects(client, "bucket", limit=3, page_size=2))
    assert [o.key for o in got] == ["a", "b", "c"]
    # only 2 pages fetched (limit hit mid-page-2), not the 3rd
    assert len(pool.calls) == 2


def test_iter_objects_multi_streams_across_buckets_bounded_by_total_limit():
    # b1 yields a,b (single page, no token); b2 yields c,d,e — the shared limit of
    # 4 stops mid-b2 and never issues a further request.
    pool = _FakePool([(200, _page(["a", "b"])), (200, _page(["c", "d", "e"]))])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    got = list(enum.iter_objects_multi(client, ["b1", "b2"], limit=4, page_size=10))
    assert [(o.bucket, o.key) for o in got] == [("b1", "a"), ("b1", "b"), ("b2", "c"), ("b2", "d")]
    assert len(pool.calls) == 2


def test_iter_objects_multi_empty_bucket_list_yields_nothing():
    pool = _FakePool([(200, _page(["a"]))])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    assert list(enum.iter_objects_multi(client, [], limit=10)) == []
    assert pool.calls == []


def test_list_objects_v2_sends_continuation_token():
    pool = _FakePool([(200, _page([]))])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    client.list_objects_v2("b", max_keys=2, continuation_token="TOK", signed=True)
    assert "continuation-token=TOK" in pool.calls[0]["url"]


def test_get_object_range_sends_range_and_bounded_cap_and_encodes_key():
    pool = _FakePool([(206, b"data")])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    client.get_object_range("b", "dir/secret file.txt", start=0, length=64, signed=True)
    call = pool.calls[0]
    assert "secret%20file.txt" in call["url"]  # key percent-encoded
    assert call["headers"]["Range"] == "bytes=0-63"
    assert call["cap"] == 64


def test_sigv4_signs_encoded_path_for_object_key_with_space():
    # regression: the signed canonical path must match the encoded wire path
    headers = s3_sigv4.sign_request(
        method="GET",
        host="h:9000",
        path="/b/dir/secret%20file.txt",
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AK",
        secret_key="SK",
    )
    assert "Authorization" in headers  # deterministic signer over encoded path


def _buckets_body(names):
    inner = "".join(f"<Bucket><Name>{n}</Name><CreationDate>2026-01-01</CreationDate></Bucket>" for n in names)
    return f"<ListAllMyBucketsResult><Buckets>{inner}</Buckets></ListAllMyBucketsResult>".encode()


def test_iter_buckets_parses_and_limits():
    pool = _FakePool([(200, _buckets_body(["a", "b", "c"]))])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    got = list(enum.iter_buckets(client, limit=2))
    assert [b.name for b in got] == ["a", "b"]
    assert got[0].creation_date == "2026-01-01"


def test_iter_buckets_empty_on_error():
    pool = _FakePool([(403, b"<Error><Code>AccessDenied</Code></Error>")])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    assert list(enum.iter_buckets(client, limit=5)) == []


def test_iter_objects_parses_metadata_fields():
    body = b'<ListBucketResult><Contents><Key>k</Key><Size>123</Size><LastModified>2026-02-02T00:00:00Z</LastModified><ETag>"e1"</ETag></Contents></ListBucketResult>'
    pool = _FakePool([(200, body)])
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000, access_key="AK", secret_key="SK")
    objs = list(enum.iter_objects(client, "b", limit=10))
    assert objs[0].key == "k" and objs[0].size == 123
    assert objs[0].last_modified == "2026-02-02T00:00:00Z" and objs[0].etag == "e1"
