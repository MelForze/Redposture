from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    """Client double returning canned responses per method."""

    def __init__(self, *, root=None, health=None, admin=None):
        self._root = root
        self._health = health
        self._admin = admin
        self.scheme = "http"
        self.host = "10.0.0.5"
        self.port = 9000

    @property
    def base_url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    def get_service_root(self, *, signed):
        return self._root

    def health(self, kind):
        return self._health

    def admin_info(self, *, signed=True):
        return self._admin


def _resp(status, body=b"", headers=None, error=None):
    return MinioResponse(http_status=status, headers=headers or {}, body=body, error=error)


def test_confirmed_when_health_live_and_s3_shape():
    client = _StubClient(
        root=_resp(
            403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"}, S3Error(403, "AccessDenied", "")
        ),
        health=_resp(200, b""),
        admin=_resp(403, b"<Error><Code>AccessDenied</Code></Error>", error=S3Error(403, "AccessDenied", "")),
    )
    det = actions.detect_minio(client)
    assert det.status == "confirmed"
    assert det.api_endpoint == "http://10.0.0.5:9000"
    assert det.evidence["health_live"] is True
    assert det.evidence["s3_shape"] is True


def test_probable_when_only_s3_shape_no_minio_specific_signals():
    # Generic S3-совместимый (не MinIO): S3 XML есть, но health/admin/Server отсутствуют.
    client = _StubClient(
        root=_resp(200, b"<ListAllMyBucketsResult></ListAllMyBucketsResult>"),
        health=_resp(404, b""),
        admin=_resp(404, b""),
    )
    det = actions.detect_minio(client)
    assert det.status == "probable"


def test_not_minio_when_no_s3_shape():
    client = _StubClient(
        root=_resp(200, b"<html><title>nginx</title></html>"),
        health=_resp(404, b""),
        admin=_resp(404, b""),
    )
    det = actions.detect_minio(client)
    assert det.status == "not_minio"


def test_transport_failure_bubbles_up():
    boom = MinioResponse(http_status=0, headers={}, body=b"", transport_error="connection refused")
    client = _StubClient(root=boom, health=boom, admin=boom)
    det = actions.detect_minio(client)
    assert det.status == "transport_failure"
    assert "refused" in det.evidence.get("transport_error", "")


def test_server_header_version_extracts_release_token():
    from redposture_core.clients.minio_api import MinioResponse
    from redposture_core.modules.minio import actions

    with_ver = MinioResponse(http_status=200, headers={"Server": "MinIO/RELEASE.2021-06-17T00-10-46Z"}, body=b"")
    assert actions._server_header_version(with_ver) == "RELEASE.2021-06-17T00-10-46Z"
    plain = MinioResponse(http_status=200, headers={"Server": "MinIO"}, body=b"")
    assert actions._server_header_version(plain) is None


def test_admin_info_version_parses_json():
    from redposture_core.clients.minio_api import MinioResponse
    from redposture_core.modules.minio import actions

    ok = MinioResponse(http_status=200, headers={}, body=b'{"mode":"online","version":"2025-09-07T16:13:09Z"}')
    assert actions._admin_info_version(ok) == "2025-09-07T16:13:09Z"
    denied = MinioResponse(http_status=403, headers={}, body=b"")
    assert actions._admin_info_version(denied) is None
    bad = MinioResponse(http_status=200, headers={}, body=b"not-json")
    assert actions._admin_info_version(bad) is None


def test_admin_info_version_reads_nested_servers_version():
    from redposture_core.clients.minio_api import MinioResponse
    from redposture_core.modules.minio import actions

    body = b'{"mode":"online","servers":[{"endpoint":"h:9000","version":"2025-09-07T16:13:09Z"}]}'
    resp = MinioResponse(http_status=200, headers={}, body=body)
    assert actions._admin_info_version(resp) == "2025-09-07T16:13:09Z"
