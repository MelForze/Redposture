from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, *, root=None, listing=None):
        self._root = root
        self._listing = listing
        self.scheme, self.host, self.port = "http", "h", 9000

    @property
    def base_url(self):
        return "http://h:9000"

    def get_service_root(self, *, signed):
        return self._root

    def list_objects_v2(self, bucket, *, max_keys=1, prefix="", signed):
        return self._listing


def _resp(status, body=b"", error=None):
    return MinioResponse(http_status=status, headers={}, body=body, error=error)


def test_authentication_required_on_access_denied_root():
    client = _StubClient(root=_resp(403, error=S3Error(403, "AccessDenied", "")))
    result = actions.classify_anonymous(client)
    assert result.classification == "authentication_required"
    assert result.api_reachable is True


def test_anonymous_list_ok_lists_buckets():
    body = (
        b"<ListAllMyBucketsResult><Buckets>"
        b"<Bucket><Name>public</Name></Bucket><Bucket><Name>logs</Name></Bucket>"
        b"</Buckets></ListAllMyBucketsResult>"
    )
    client = _StubClient(root=_resp(200, body))
    result = actions.classify_anonymous(client)
    assert result.classification == "anonymous_list_ok"
    assert result.buckets == ("public", "logs")


def test_known_bucket_anonymous_read_probe():
    client = _StubClient(
        root=_resp(403, error=S3Error(403, "AccessDenied", "")),
        listing=_resp(200, b"<ListBucketResult></ListBucketResult>"),
    )
    result = actions.classify_anonymous(client, known_bucket="reports")
    assert result.read_probe == "anonymous_read_ok"


def test_verification_unavailable_on_transport_error():
    boom = MinioResponse(http_status=0, headers={}, body=b"", transport_error="timeout")
    client = _StubClient(root=boom)
    result = actions.classify_anonymous(client)
    assert result.classification == "verification_unavailable"
    assert result.api_reachable is False
