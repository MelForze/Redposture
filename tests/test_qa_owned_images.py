"""QA image cleanup never removes images that predate the current stand."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import qa_owned_images as images


def test_snapshot_only_records_absent_images(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[-2:] == ["config", "--images"]:
            return subprocess.CompletedProcess(command, 0, "keep:1\nnew:2\nnew:2\n", "")
        return subprocess.CompletedProcess(command, 0 if command[-1] == "keep:1" else 1, "", "")

    monkeypatch.setattr(images.subprocess, "run", run)
    monkeypatch.setattr(
        sys, "argv", ["qa_owned_images.py", "snapshot", str(tmp_path / "images.json"), "--", "docker", "compose"]
    )
    assert images.main() == 0
    assert json.loads((tmp_path / "images.json").read_text(encoding="utf-8")) == ["new:2"]
    assert ["docker", "image", "inspect", "keep:1"] in calls
    assert ["docker", "image", "inspect", "new:2"] in calls
    assert not any(command[:3] == ["docker", "image", "rm"] for command in calls)


def test_cleanup_removes_only_snapshot_references_and_reports_busy_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = tmp_path / "images.json"
    snapshot.write_text('["new:2", "busy:3"]', encoding="utf-8")
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[-1] == "busy:3":
            return subprocess.CompletedProcess(command, 1, "", "image is being used by a container")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(images.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["qa_owned_images.py", "cleanup", str(snapshot)])
    assert images.main() == 1
    assert calls == [["docker", "image", "rm", "busy:3"], ["docker", "image", "rm", "new:2"]]


def test_cleanup_accepts_image_missing_after_failed_pull(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        images.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "Error: No such image: new:2"),
    )
    assert images.remove_images(["new:2"]) == []


def test_handoff_stages_enable_scoped_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import run_qa_handoff as handoff

    seen: list[dict[str, str] | None] = []

    def run(_command: list[str], _log: Path, *, timeout: int, env: dict[str, str] | None = None) -> tuple[int, float]:
        del timeout
        seen.append(env)
        return 0, 0.1

    monkeypatch.setattr(handoff, "_run_logged", run)
    for stage in ("full", "versions"):
        assert handoff._run_stage(stage, tmp_path / stage, "qa-test", sys.executable)["status"] == "passed"
    assert all(env and env["REDPOSTURE_QA_CLEAN_IMAGES"] == "1" for env in seen)
