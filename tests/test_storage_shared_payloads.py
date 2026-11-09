"""Existing storage blob routes share bounded format readers and full values."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.scheduler import NestedSchedulerCancelled
from redposture_core.storage_discovery import DiscoveryCollector, _scan_spooled_blob

PASSWORD = "inactive-storage-format-password"
BODY = f'password="{PASSWORD}"\n'.encode()


def pack(kind, body):
    output = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("config/app.env", body)
    else:
        with tarfile.open(fileobj=output, mode="w") as archive:
            info = tarfile.TarInfo("config/app.env")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def values(result):
    return {
        "".join(row["value"].iter_text_chunks()) if isinstance(row["value"], DiskBackedText) else row["value"]
        for row in result["findings"]
    }


def collector(module):
    context = SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=443)
    return DiscoveryCollector(module, context, {"status": "open_no_auth"})


def test_legacy_minio_payload_import_reads_full_archive_and_member_locator():
    # Keep the old import usable by existing adapters/tools after the reader
    # moves to the shared package. Exercise behavior rather than only identity.
    from redposture_core.modules.minio.payloads import needs_payload_reader, scan_payload_file

    raw = pack("zip", BODY.decode().encode("utf-16"))
    assert needs_payload_reader(raw[:512], "artifact.zip")
    assert not needs_payload_reader(b"ordinary log message", "output.txt")
    target = collector("minio")
    scan_payload_file(
        io.BytesIO(raw),
        "legacy/artifact.zip",
        publish=lambda item, path: target.add(path, item, charge=False),
        partial=lambda reason: target.partial("legacy/artifact.zip", reason),
        check=lambda: None,
    )
    result = target.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert values(result) == {PASSWORD}
    assert len(result["findings"]) == 1
    assert "legacy/artifact.zip/member/0/file/config/app.env" in result["findings"][0]["object_path"]


@pytest.mark.parametrize(
    "media",
    [
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    ],
)
@pytest.mark.parametrize("broken", [False, True])
def test_declared_empty_tar_layer_is_complete_only_after_gzip_trailer_validation(media, broken):
    raw = gzip.compress(bytes(10240), mtime=0)
    target = collector("harbor")
    _scan_spooled_blob(target, io.BytesIO(raw[:-6] if broken else raw), "image/layer/sha256:empty", media)
    result = target.result()
    assert result["status"] == ("partial" if broken else "complete"), result["partial_reasons"]
    assert not result["findings"]
    if broken:
        assert any("invalid_archive_or_payload" in reason for reason in result["partial_reasons"])


def test_untyped_zero_bytes_are_not_guessed_to_be_an_empty_tar():
    target = collector("nexus")
    _scan_spooled_blob(target, io.BytesIO(bytes(10240)), "asset/hash", "application/octet-stream")
    assert target.result()["status"] == "partial"


@pytest.mark.parametrize("kind", ["utf16", "gzip", "zip", "binary"])
def test_portainer_swarm_config_bytes_use_shared_payload_reader(monkeypatch, kind):
    import base64
    import json

    from redposture_core import web_panels
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import discover_portainer_sources

    payload = {
        "utf16": BODY.decode().encode("utf-16"),
        "gzip": gzip.compress(BODY),
        "zip": pack("zip", BODY),
        "binary": b'password="interrupted\x00\xff',
    }[kind]
    responses = {
        "/api/stacks": [],
        "/api/endpoints/2/docker/configs": [{"ID": "cfg"}],
        "/api/endpoints/2/docker/configs/cfg": {"Spec": {"Data": base64.b64encode(payload).decode()}},
        "/api/endpoints/2/docker/secrets": [],
    }

    def get(_pool, _base, path, **_kwargs):
        assert path in responses, path
        return HttpResponse(200, json.dumps(responses[path]).encode(), {})

    monkeypatch.setattr(web_panels, "_get", get)
    context = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1, endpoint="2", secure=False), host="qa", port=9000
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "qa"}}
    target = DiscoveryCollector("portainer", context, record)
    discover_portainer_sources(
        context,
        record,
        {"environments": {"records": [{"Id": 2}]}, "containers": {"records": []}, "images": {"records": []}},
        target,
    )
    result = target.result()
    if kind == "binary":
        assert result["status"] == "partial"
        assert not result["findings"]
    else:
        assert result["status"] == "complete", result["partial_reasons"]
        assert values(result) == {PASSWORD}


def test_declared_csv_file_emits_completed_row_before_source_end():
    source = io.BytesIO(b'user,password\nqa,first-completed-password\nqa,"' + b"a" * 2_000_000 + b'"\n')
    positions = []
    context = SimpleNamespace(
        args=SimpleNamespace(discover_time=900),
        host="qa",
        port=443,
        live_emit=lambda _line: positions.append(source.tell()),
    )
    target = DiscoveryCollector("gitlab", context, {"status": "open_no_auth"})
    target._scan_member_stream("qa", "source.csv", source)
    assert target.result()["status"] == "complete"
    assert positions and positions[0] < 100_000, positions


def test_late_binary_control_in_declared_text_is_partial_and_preserves_only_complete_values():
    body = b'password="first-completed-password"\n' + b"ordinary\n" * 200
    body += b'password="interrupted-before-binary' + b"\0\x01" + b"-not-a-complete-value"
    target = collector("gitlab")
    target._scan_member_stream("qa", "config.env", io.BytesIO(body))
    result = target.result()
    assert result["status"] == "partial"
    assert values(result) == {"first-completed-password"}
    assert any("binary_or_unsupported_encoding" in reason for reason in result["partial_reasons"])


@pytest.mark.parametrize("module", ["gitlab", "portainer", "harbor", "nexus", "docker-registry"])
@pytest.mark.parametrize("kind", ["utf8", "utf16", "gzip-text", "zip-utf16", "tar-utf16"])
def test_storage_blob_routes_parse_the_same_sources(module, kind):
    utf16 = BODY.decode().encode("utf-16")
    payload = {
        "utf8": BODY,
        "utf16": utf16,
        "gzip-text": gzip.compress(BODY),
        "zip-utf16": pack("zip", utf16),
        "tar-utf16": pack("tar", utf16),
    }[kind]
    target = collector(module)
    source = io.BytesIO(payload)
    source.seek(0, 2)
    _scan_spooled_blob(target, source, "source/config", "application/octet-stream")
    result = target.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert values(result) == {PASSWORD}
    assert all("source/config" in str(row["object_path"]) for row in result["findings"])
    if kind.endswith("utf16") and kind != "utf16":
        assert all("config/app.env" in str(row["object_path"]) for row in result["findings"])


def test_retained_blob_cursor_position_does_not_turn_nonempty_source_into_empty():
    target = collector("nexus")
    _scan_spooled_blob(target, io.BytesIO(BODY), "asset/config", "application/octet-stream")
    assert values(target.result()) == {PASSWORD}


def test_member_cancellation_propagates_instead_of_becoming_archive_error():
    target = collector("gitlab")
    target.ctx.cancelled = lambda: True
    with pytest.raises(NestedSchedulerCancelled):
        target.scan_archive_file("artifact/one", io.BytesIO(pack("zip", BODY)), "zip")


@pytest.mark.parametrize("module", ["gitlab", "portainer", "harbor", "nexus", "docker-registry"])
@pytest.mark.parametrize("encoding", ["text", "gzip", "zip"])
def test_cancel_and_two_fresh_walks_keep_exact_values_and_locations(module, encoding):
    first, last = "inactive-first!42", "inactive-last!42"
    body = (f'password="{first}"\n' + "ordinary data\n" * 10000 + f'password="{last}"\n').encode()
    raw = gzip.compress(body) if encoding == "gzip" else pack("zip", body) if encoding == "zip" else body

    def attempt(cancel):
        emitted = []
        target = collector(module)
        target.ctx.live_emit = emitted.extend
        target.ctx.cancelled = lambda: cancel and bool(emitted)
        if cancel:
            with pytest.raises(NestedSchedulerCancelled):
                _scan_spooled_blob(target, io.BytesIO(raw), "source/config", "application/octet-stream")
        else:
            _scan_spooled_blob(target, io.BytesIO(raw), "source/config", "application/octet-stream")
        return target.result(), emitted

    report, emitted = attempt(True)
    assert report["status"] == "partial" and values(report) == {first}
    assert len(emitted) == 1
    places = []
    for _ in range(2):
        report, emitted = attempt(False)
        assert report["status"] == "complete" and values(report) == {first, last}
        assert len(emitted) == len(report["findings"]) == 2
        places.append({(f["value"], str(f["object_path"])) for f in report["findings"]})
    assert places[0] == places[1]


def test_cancellation_prevents_the_next_http_read_and_keeps_previous_findings():
    target = collector("gitlab")
    target.add("project/config", {"password": PASSWORD})
    target.ctx.cancelled = lambda: True
    requests = []

    def getter(*args):
        requests.append(args)
        return 200, BODY, {}, None

    with pytest.raises(NestedSchedulerCancelled):
        target.read(getter, "/next-file", "project/next")
    assert requests == []
    assert values(target.result()) == {PASSWORD}


def test_cancellation_interrupts_plain_member_before_eof():
    target = collector("nexus")
    interrupted = [False]
    target.ctx.cancelled = lambda: interrupted[0]

    class Interrupted(io.BytesIO):
        def read(self, size=-1):
            piece = super().read(size)
            interrupted[0] = True
            return piece

    source = Interrupted(BODY + b"a" * 100000)
    with pytest.raises(NestedSchedulerCancelled):
        target._scan_member_stream("asset/archive", "config.env", source)
    assert source.tell() < len(source.getvalue())
