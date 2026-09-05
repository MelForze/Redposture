from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _FakeClient:
    """Records PUT/DELETE calls and replays canned responses per method."""

    def __init__(self, put_resp, delete_resp=None):
        self._put = put_resp
        self._delete = delete_resp
        self.puts = []
        self.deletes = []

    def put_object(self, bucket, key, body, *, signed=True):
        self.puts.append((bucket, key, body))
        return self._put(bucket, key) if callable(self._put) else self._put

    def delete_object(self, bucket, key, *, signed=True):
        self.deletes.append((bucket, key))
        return self._delete(bucket, key) if callable(self._delete) else self._delete


def _ok(status):
    return MinioResponse(http_status=status, headers={}, body=b"")


def _denied():
    return MinioResponse(http_status=403, headers={}, body=b"", error=S3Error(403, "AccessDenied", "Access Denied."))


def test_write_probe_true_with_cleanup_ok():
    client = _FakeClient(put_resp=_ok(200), delete_resp=_ok(204))
    per_bucket, leftovers = actions.probe_write_capability(client, ["b1"])
    assert per_bucket["b1"]["write"] is True
    assert per_bucket["b1"]["cleanup"] == "ok"
    assert leftovers == []
    # canary key looks like the reserved probe prefix, and DELETE targets the same key
    assert client.puts[0][1].startswith(".redposture-probe-")
    assert client.deletes[0][1] == client.puts[0][1]


def test_write_probe_false_on_access_denied_no_delete():
    client = _FakeClient(put_resp=_denied())
    per_bucket, leftovers = actions.probe_write_capability(client, ["b1"])
    assert per_bucket["b1"]["write"] is False
    assert client.deletes == []  # nothing was written, nothing to roll back
    assert leftovers == []


def test_write_probe_leftover_when_cleanup_fails():
    client = _FakeClient(put_resp=_ok(200), delete_resp=_denied())
    per_bucket, leftovers = actions.probe_write_capability(client, ["b1"])
    assert per_bucket["b1"]["write"] is True
    assert per_bucket["b1"]["cleanup"] == "failed"
    assert per_bucket["b1"]["leftover"] == client.puts[0][1]
    assert leftovers == [{"bucket": "b1", "key": client.puts[0][1]}]


def test_write_probe_unknown_on_transport_error():
    client = _FakeClient(put_resp=MinioResponse(http_status=0, headers={}, body=b"", transport_error="boom"))
    per_bucket, _ = actions.probe_write_capability(client, ["b1"])
    assert per_bucket["b1"]["write"] == "unknown"


def test_write_probe_iterates_all_buckets_with_distinct_canaries():
    client = _FakeClient(put_resp=_ok(200), delete_resp=_ok(204))
    per_bucket, _ = actions.probe_write_capability(client, ["b1", "b2", "b3"])
    assert set(per_bucket) == {"b1", "b2", "b3"}
    keys = [k for _, k in client.deletes]
    assert len(set(keys)) == 3  # a fresh random canary per bucket
