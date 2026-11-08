"""Ready inventory precedes discover; finding callbacks stay genuinely live."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio import actions, discover, stage
from redposture_core.modules.minio import enumerate as enumeration
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, LineOutputSink


def run_minio(
    monkeypatch,
    tmp_path,
    *,
    show_buckets=True,
    show_objects=False,
    output_format="txt",
    listing_error=False,
    long_key=False,
    stream_failure=False,
):
    argv = ["minio", "-t", "127.0.0.1:19000", "-u", "minioadmin", "-p", "minioadmin", "--discover", "-f", output_format]
    if show_buckets:
        argv.append("--show-buckets")
    if show_objects:
        argv.append("--show-objects")
    args = parse_args(argv)
    args.output_format = output_format
    output = tmp_path / ("result.jsonl" if output_format == "json" else "result.txt")
    console = []
    stream_paths = []
    calls = {"buckets": 0, "objects": 0, "discover": 0}
    objects = [
        enumeration.ObjectInfo("app", "config.env", 40),
        enumeration.ObjectInfo("backup", "last-λ.env" if not long_key else "λ" * 70000, 40),
    ]
    secret = "inactive-enumeration-order-password"
    finding = {
        "type": "password",
        "confidence": "high",
        "value": secret,
        "bucket": "app",
        "key": "config.env",
        "object_path": "$",
    }

    monkeypatch.setattr(actions, "minio_lifecycle_state_factory", lambda ctx: None)
    monkeypatch.setattr(actions, "_client_for", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        actions,
        "detect_record",
        lambda ctx: {
            "host": ctx.host,
            "port": ctx.port,
            "is_minio": True,
            "detection_status": "confirmed",
            "status": "auth_required",
            "auth_required": True,
        },
    )
    monkeypatch.setattr(
        actions,
        "auth_record",
        lambda ctx, prior: {
            **prior,
            "status": "valid_credentials",
            "credential_state": "valid",
            "provided_credentials_ok": True,
            "credential_results": [{"access_key": "minioadmin", "state": "valid"}],
            "credential_secret": "minioadmin",
        },
    )
    monkeypatch.setattr(actions, "capabilities_record", lambda ctx, prior: {**prior, "admin_capability": "confirmed"})

    def buckets(client, *, on_error=None):
        calls["buckets"] += 1
        if listing_error:
            on_error("partial bucket list")
        yield enumeration.BucketInfo("app")
        yield enumeration.BucketInfo("backup")

    def list_objects(client, names, *, on_error=None):
        calls["objects"] += 1
        assert list(names) == ["app", "backup"]
        yield from objects

    original_stream = LineOutputSink.emit_stream_file

    def stream(self, path, **kwargs):
        if output_format == "txt":
            assert calls["discover"] == 0, "inventory file emitted after discover"
            stream_paths.append(Path(path))
            if stream_failure:
                raise OSError("inventory output failed")
        return original_stream(self, path, **kwargs)

    def scan(client, sources, *, budget, on_finding=None, **kwargs):
        calls["discover"] += 1
        before = output.read_text()
        if output_format == "txt":
            assert "[+] minioadmin:minioadmin" in before
            assert ("Buckets Enumeration" in before) is show_buckets
            if show_buckets:
                assert " app" in before and " backup" in before
            if show_objects:
                assert "Objects Enumeration (Count:2)" in before
                assert "app/config.env" in before and objects[-1].key in before
                assert stream_paths and all(not p.exists() for p in stream_paths)
            assert on_finding is not None
            on_finding(finding)
            assert secret in output.read_text(), "finding buffered until scan returned"
        else:
            assert not before and on_finding is None
        assert len(list(sources)) == 2
        result = discover.DiscoverResult(
            findings=[finding], candidates=[{}, {}], objects_scanned=2, coverage_complete=True
        )
        result.source_manifest.request("minio.object_catalog")
        result.source_manifest.read("minio.object_catalog", 2)
        result.source_manifest.finish("minio.object_catalog", complete=True)
        return result

    monkeypatch.setattr(enumeration, "iter_buckets", buckets)
    monkeypatch.setattr(enumeration, "iter_objects_multi", list_objects)
    monkeypatch.setattr(discover, "discover_secrets", scan)
    monkeypatch.setattr(LineOutputSink, "emit_stream_file", stream)
    runner = AuditCommandRunner(args=args, spec=stage.build_minio_spec(args), emit_line=console.append)
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={19000: ("127.0.0.1",)},
            credential_runs=(AuditCredentialRun(username="minioadmin", password="minioadmin", source="provided"),),
            output_path=str(output),
            output_format=output_format,
            workers=1,
        )
    )
    return output.read_text(), result, calls, secret, stream_paths


@pytest.mark.parametrize("show_buckets,show_objects", [(True, False), (True, True), (False, True), (False, False)])
@pytest.mark.parametrize("listing_error", [False, True])
def test_inventory_is_ready_before_discovery_and_not_repeated(
    monkeypatch, tmp_path, capsys, show_buckets, show_objects, listing_error
):
    saved, result, calls, secret, paths = run_minio(
        monkeypatch, tmp_path, show_buckets=show_buckets, show_objects=show_objects, listing_error=listing_error
    )
    assert result.operational_failure_count == 0
    assert calls == {"buckets": 1, "objects": 2 if show_objects else 1, "discover": 1}
    assert saved.count("Buckets Enumeration") == int(show_buckets)
    assert saved.count("Objects Enumeration") == int(show_objects)
    assert saved.count(secret) == 1
    assert "Discover Secrets (status:" in saved.splitlines()[-1]
    assert ("status:partial" in saved) is listing_error
    assert all(not p.exists() for p in paths)
    assert "\x1b" not in saved
    capsys.readouterr()


@pytest.mark.parametrize("show_objects", [False, True])
def test_json_keeps_inventory_without_early_text(monkeypatch, tmp_path, capsys, show_objects):
    saved, result, calls, secret, paths = run_minio(
        monkeypatch, tmp_path, show_objects=show_objects, output_format="json"
    )
    assert result.operational_failure_count == 0
    rows = [json.loads(line) for line in saved.splitlines()]
    assert rows[0]["buckets"] == [{"name": "app", "creation_date": None}, {"name": "backup", "creation_date": None}]
    assert rows[0]["secret_findings"][0]["value"] == secret
    assert not paths
    capsys.readouterr()


def test_long_object_line_streams_before_discovery(monkeypatch, tmp_path, capsys):
    saved, result, _, _, paths = run_minio(monkeypatch, tmp_path, show_objects=True, long_key=True)
    assert result.operational_failure_count == 0
    assert saved.count("λ" * 70000) == 1
    assert paths and all(not p.exists() for p in paths)
    capsys.readouterr()


def test_failed_inventory_output_cleans_file_and_does_not_start_discovery(monkeypatch, tmp_path, capsys):
    saved, result, calls, secret, paths = run_minio(monkeypatch, tmp_path, show_objects=True, stream_failure=True)
    assert result.operational_failure_count == 1
    assert calls["discover"] == 0
    assert secret not in saved and "Discover Secrets (status:complete)" not in saved
    assert paths and all(not p.exists() for p in paths)
    capsys.readouterr()
