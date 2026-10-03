"""Offline checks for the local QA handoff command."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import run_qa_handoff as qa
from scripts.run_qa_handoff import LAB_TOKEN, _json_record, _safe_command, validate_gitlab_download


def test_gitlab_blob_handoff_requires_real_download_and_exact_digests(tmp_path: Path) -> None:
    image = tmp_path / "downloads" / "image"
    image.mkdir(parents=True)
    blobs = [b"config", b"layer"]
    expected = ["sha256:" + hashlib.sha256(blob).hexdigest() for blob in blobs]
    (image / "manifest.json").write_text(
        json.dumps({"config": {"digest": expected[0]}, "layers": [{"digest": expected[1]}]}),
        encoding="utf-8",
    )
    (image / "config.blob").write_bytes(blobs[0])
    (image / "image.layer").write_bytes(blobs[1])
    record = {"is_gitlab": True, "download_result": {"status": "ok", "path": str(image)}}

    assert validate_gitlab_download(record, tmp_path)[0] is True
    assert validate_gitlab_download({**record, "is_gitlab": False}, tmp_path)[0] is False
    (image / "image.layer").write_bytes(b"corrupt")
    assert validate_gitlab_download(record, tmp_path)[0] is False
    assert validate_gitlab_download({**record, "download_result": {"status": "fail"}}, tmp_path)[0] is False
    assert validate_gitlab_download(None, tmp_path)[0] is False


def test_gitlab_blob_handoff_rejects_paths_outside_artifact_dir(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-image"
    record = {"is_gitlab": True, "download_result": {"status": "ok", "path": str(outside)}}
    assert validate_gitlab_download(record, tmp_path)[0] is False


def test_gitlab_blob_handoff_reads_download_from_confirmed_registry_surface(tmp_path: Path) -> None:
    image = tmp_path / "downloads" / "image"
    image.mkdir(parents=True)
    config = b"config"
    layer = b"layer"
    descriptors = ["sha256:" + hashlib.sha256(blob).hexdigest() for blob in (config, layer)]
    (image / "manifest.json").write_text(
        json.dumps({"config": {"digest": descriptors[0]}, "layers": [{"digest": descriptors[1]}]}),
        encoding="utf-8",
    )
    (image / "config.blob").write_bytes(config)
    (image / "image.layer").write_bytes(layer)
    log = tmp_path / "download.log"
    log.write_text(
        json.dumps(
            {
                "is_gitlab": True,
                "detection_status": "confirmed",
                "download_result": None,
                "container_registry": {
                    "is_gitlab": True,
                    "download_result": {"status": "ok", "path": str(image)},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert validate_gitlab_download(_json_record(log), tmp_path)[0] is True


def test_qa_handoff_plan_is_read_only_and_redacts_lab_token(tmp_path: Path) -> None:
    command = [sys.executable, "scripts/run_qa_handoff.py", str(tmp_path / "new"), "--plan"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert all(stage in result.stdout for stage in ("full", "versions", "gitlab-blob", "python-matrix"))
    assert not (tmp_path / "new").exists()
    assert LAB_TOKEN not in _safe_command(["redposture", "-p", LAB_TOKEN])


@pytest.mark.parametrize("failing_step", [None, "seed"])
def test_real_gitlab_qa_cleans_up_its_project_even_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_step: str | None
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(qa, "_docker_project_is_empty", lambda _project: True)
    monkeypatch.setattr(qa, "_gitlab_ports_are_free", lambda _compose: (True, []))
    monkeypatch.setattr(qa, "compose_images", lambda _compose: ["gitlab/gitlab-ce:test"])
    monkeypatch.setattr(qa, "missing_images", lambda _refs: ["gitlab/gitlab-ce:test"])

    def remove_images(references: list[str]) -> list[str]:
        assert references == ["gitlab/gitlab-ce:test"]
        calls.append("remove-image")
        return []

    monkeypatch.setattr(qa, "remove_images", remove_images)
    monkeypatch.setattr(qa, "_json_record", lambda _log: {"is_gitlab": True, "download_result": {"status": "ok"}})
    monkeypatch.setattr(qa, "validate_gitlab_download", lambda _record, _root: (True, "hashes match"))

    def run(command: list[str], log: Path, *, timeout: int, env: dict[str, str] | None = None) -> tuple[int, float]:
        del command, timeout, env
        name = log.stem
        calls.append(name)
        return (1 if name == failing_step else 0), 0.1

    monkeypatch.setattr(qa, "_run_logged", run)
    result = qa._gitlab_blob_qa(tmp_path / "gitlab", "redposture-qa-owned", sys.executable)
    assert result["status"] == ("failed" if failing_step else "passed")
    assert calls == (
        ["up", "seed", "down", "remove-image"] if failing_step else ["up", "seed", "download", "down", "remove-image"]
    )


def test_handoff_report_contains_statuses_and_revision(tmp_path: Path) -> None:
    report = {
        "revision": "abc123",
        "started_utc": "2026-10-03T00:00:00+00:00",
        "status": "failed",
        "stages": {
            "full": {"status": "passed", "exit_code": 0},
            "gitlab-blob": {"status": "failed", "reason": "blob digest mismatch"},
        },
    }
    qa._write_report(tmp_path, report)
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8")) == report
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "abc123" in text
    assert "blob digest mismatch" in text
    assert "Send `report.md` and `report.json`" in text
