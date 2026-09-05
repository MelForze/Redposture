from __future__ import annotations

from types import SimpleNamespace

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions, render


class _FakeClient:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def get_object(self, bucket, key, *, max_bytes, signed=True):
        self.calls.append((bucket, key, max_bytes))
        return self._resp


def _ctx(**args_over):
    base = dict(
        show_buckets=False,
        show_objects=False,
        discover=False,
        probe_write=False,
        object=None,
        dump=False,
        download=None,
        prefix="",
        max_object_size=10 * 1024 * 1024,
        timeout=1.0,
        session_token=None,
        output_format="txt",
    )
    base.update(args_over)
    return SimpleNamespace(
        args=SimpleNamespace(**base),
        host="h",
        port=9000,
        lifecycle_state=None,
        credential=SimpleNamespace(username="AK", password="SK"),
    )


def _install_client(monkeypatch, resp):
    client = _FakeClient(resp)
    monkeypatch.setattr(actions, "_client_for", lambda ctx, cred: client)
    return client


def test_data_record_dump_object(monkeypatch):
    client = _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"hello\nworld"))
    out = actions.data_record(_ctx(object="bulk/creds.env", dump=True), {"detection_status": "confirmed"})
    assert client.calls == [("bulk", "creds.env", 10 * 1024 * 1024)]
    assert out["object_dump"] == {"bucket": "bulk", "key": "creds.env", "size": 11, "content": "hello\nworld"}


def test_data_record_download_object(monkeypatch, tmp_path):
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"BODYDATA"))
    out = actions.data_record(_ctx(object="bulk/a/b.bin", download=str(tmp_path)), {"detection_status": "confirmed"})
    dest = tmp_path / "bulk" / "a" / "b.bin"
    assert dest.read_bytes() == b"BODYDATA"
    assert out["object_download"] == {"bucket": "bulk", "key": "a/b.bin", "path": str(dest), "size": 8}


def test_data_record_object_invalid_ref(monkeypatch):
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"x"))
    out = actions.data_record(_ctx(object="no-slash", dump=True), {"detection_status": "confirmed"})
    assert "invalid --object" in out["object_op_error"]


def test_data_record_object_access_denied(monkeypatch):
    resp = MinioResponse(http_status=403, headers={}, body=b"", error=S3Error(403, "AccessDenied", "denied"))
    _install_client(monkeypatch, resp)
    out = actions.data_record(_ctx(object="bulk/secret", dump=True), {"detection_status": "confirmed"})
    assert "AccessDenied" in out["object_op_error"]
    assert "object_dump" not in out


def test_data_record_dump_download_without_object_errors(monkeypatch):
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"x"))
    out = actions.data_record(_ctx(dump=True), {"detection_status": "confirmed"})
    assert "--object" in out["object_op_error"]


def test_render_dump_download_and_error_lines():
    pfx = "MINIO\th\t9000\t"
    rec = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_dump": {"bucket": "bulk", "key": "creds.env", "size": 11, "content": "hello\nworld"},
    }
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{pfx} [*] Dump bulk/creds.env (size:11)" in lines
    assert "hello" in lines and "world" in lines  # raw content lines, unprefixed

    rec2 = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_download": {"bucket": "bulk", "key": "a/b.bin", "path": "/tmp/out/bulk/a/b.bin", "size": 8},
    }
    lines2 = render._format_minio_detail_records(rec2, "txt")
    assert f"{pfx} [+] downloaded bulk/a/b.bin -> /tmp/out/bulk/a/b.bin (size:8)" in lines2

    rec3 = {"host": "h", "port": 9000, "detection_status": "confirmed", "object_op_error": "bulk/x: AccessDenied"}
    lines3 = render._format_minio_detail_records(rec3, "txt")
    assert f"{pfx} [!] object error: bulk/x: AccessDenied" in lines3
