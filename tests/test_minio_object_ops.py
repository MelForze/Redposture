from __future__ import annotations

from types import SimpleNamespace

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions, render
from redposture_core.modules.minio import enumerate as minio_enum


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
        bucket=None,
        dump=False,
        download=False,
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


def _fake_bucket_objects(monkeypatch, *keys):
    def _iter(_client, bucket, **_kw):
        for key in keys:
            yield minio_enum.ObjectInfo(bucket=bucket, key=key, size=0)

    monkeypatch.setattr(minio_enum, "iter_objects", _iter)


# --- dump --------------------------------------------------------------------


def test_data_record_dump_single_object(monkeypatch):
    client = _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"hello\nworld"))
    out = actions.data_record(_ctx(object="bulk/creds.env", dump=True), {"detection_status": "confirmed"})
    assert client.calls == [("bulk", "creds.env", 10 * 1024 * 1024)]
    assert out["object_dumps"] == [{"bucket": "bulk", "key": "creds.env", "size": 11, "content": "hello\nworld"}]
    assert out["object_dumps_labeled"] is False  # single object -> no === header


def test_data_record_dump_whole_bucket(monkeypatch):
    _fake_bucket_objects(monkeypatch, "a.txt", "sub/b.txt")
    client = _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"data"))
    out = actions.data_record(_ctx(bucket="bulk", dump=True), {"detection_status": "confirmed"})
    assert [(b, k) for b, k, _ in client.calls] == [("bulk", "a.txt"), ("bulk", "sub/b.txt")]
    assert [d["key"] for d in out["object_dumps"]] == ["a.txt", "sub/b.txt"]
    assert out["object_dumps_labeled"] is True  # bucket-wide dump -> === headers


# --- download ----------------------------------------------------------------


def test_data_record_download_single_object(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # download writes to ./<bucket>/<key>
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"BODYDATA"))
    out = actions.data_record(_ctx(object="bulk/a/b.bin", download=True), {"detection_status": "confirmed"})
    dest = tmp_path / "bulk" / "a" / "b.bin"
    assert dest.read_bytes() == b"BODYDATA"
    assert out["object_downloads"] == [{"bucket": "bulk", "key": "a/b.bin", "path": "bulk/a/b.bin", "size": 8}]


def test_data_record_download_whole_bucket(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _fake_bucket_objects(monkeypatch, "one.bin", "d/two.bin")
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"XX"))
    out = actions.data_record(_ctx(bucket="bulk", download=True), {"detection_status": "confirmed"})
    assert (tmp_path / "bulk" / "one.bin").read_bytes() == b"XX"
    assert (tmp_path / "bulk" / "d" / "two.bin").read_bytes() == b"XX"
    assert [d["key"] for d in out["object_downloads"]] == ["one.bin", "d/two.bin"]


# --- errors ------------------------------------------------------------------


def test_data_record_object_invalid_ref(monkeypatch):
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"x"))
    out = actions.data_record(_ctx(object="no-slash", dump=True), {"detection_status": "confirmed"})
    assert "invalid --object" in out["object_op_error"]


def test_data_record_object_access_denied(monkeypatch):
    resp = MinioResponse(http_status=403, headers={}, body=b"", error=S3Error(403, "AccessDenied", "denied"))
    _install_client(monkeypatch, resp)
    out = actions.data_record(_ctx(object="bulk/secret", dump=True), {"detection_status": "confirmed"})
    assert "AccessDenied" in out["object_op_error"]
    assert "object_dumps" not in out


def test_data_record_dump_without_target_errors(monkeypatch):
    _install_client(monkeypatch, MinioResponse(http_status=200, headers={}, body=b"x"))
    out = actions.data_record(_ctx(dump=True), {"detection_status": "confirmed"})
    assert "--object" in out["object_op_error"] or "--bucket" in out["object_op_error"]


# --- render ------------------------------------------------------------------


def test_render_single_object_dump():
    pfx = "MINIO\th\t9000\t"
    rec = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_dumps": [{"bucket": "bulk", "key": "creds.env", "size": 11, "content": "hello\nworld"}],
        "object_dumps_labeled": False,
    }
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{pfx} [*] Dump bulk/creds.env (size:11)" in lines
    assert "hello" in lines and "world" in lines  # raw content lines, unprefixed


def test_render_bucket_dump_uses_headers():
    rec = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_dumps": [
            {"bucket": "bulk", "key": "a.txt", "size": 1, "content": "A"},
            {"bucket": "bulk", "key": "b.txt", "size": 1, "content": "B"},
        ],
        "object_dumps_labeled": True,
    }
    lines = render._format_minio_detail_records(rec, "txt")
    assert "=== bulk/a.txt (1) ===" in lines
    assert "=== bulk/b.txt (1) ===" in lines
    assert "A" in lines and "B" in lines


def test_render_download_lines_and_errors():
    pfx = "MINIO\th\t9000\t"
    rec = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_downloads": [{"bucket": "bulk", "key": "a/b.bin", "path": "bulk/a/b.bin", "size": 8}],
        "object_op_error": "bulk/x: AccessDenied",
        "object_op_errors": ["bulk/x: AccessDenied", "bulk/y: transport error"],
    }
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{pfx} [+] downloaded bulk/a/b.bin -> bulk/a/b.bin (size:8)" in lines
    assert f"{pfx} [!] object error: bulk/x: AccessDenied" in lines
    assert f"{pfx} [!] object error: bulk/y: transport error" in lines


def test_render_bucket_dump_header_sanitises_the_key():
    # The key is target-controlled; a newline must not forge a header line.
    rec = {
        "host": "h",
        "port": 9000,
        "detection_status": "confirmed",
        "object_dumps": [{"bucket": "bulk", "key": "loot\nMINIO\t1.2.3.4\t9000\t x", "size": 1, "content": "A"}],
        "object_dumps_labeled": True,
    }
    lines = render._format_minio_detail_records(rec, "txt")
    header = next(line for line in lines if line.startswith("==="))
    assert "\n" not in header and "\t" not in header
