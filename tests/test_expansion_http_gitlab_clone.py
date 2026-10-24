"""GitLab clone failures clean unpublished temporary repositories atomically."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from redposture_core.modules.gitlab import actions as gitlab


@pytest.mark.parametrize(
    "failure", ["initial_oserror", "fallback_oserror", "fallback_timeout", "fallback_exit", "publish"]
)
def test_gitlab_failed_clone_cleans_only_its_temporary_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    commands = []
    sibling = tmp_path / "unrelated.txt"
    sibling.write_text("preserve", encoding="utf-8")
    project = {"id": 7, "path_with_namespace": "group/app", "http_url_to_repo": "https://qa/group/app.git"}
    monkeypatch.setattr(gitlab.shutil, "which", lambda name: "/fake/git")

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        temporary = Path(command[-1])
        temporary.mkdir(parents=True)
        (temporary / "partial-pack").write_bytes(b"incomplete")
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        if failure == "initial_oserror":
            raise OSError("spawn failure")
        if failure == "publish":
            return subprocess.CompletedProcess(command, 0, "", "")
        if len(commands) == 1:
            return subprocess.CompletedProcess(
                command, 1, "", "fatal: dumb http transport does not support shallow capabilities"
            )
        if failure == "fallback_oserror":
            raise OSError("fallback spawn failure")
        if failure == "fallback_timeout":
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 1, "", "repository unavailable")

    def replace(source: str, destination: str) -> None:
        raise OSError("publication denied")

    monkeypatch.setattr(gitlab.subprocess, "run", run)
    if failure == "publish":
        monkeypatch.setattr(gitlab.os, "replace", replace)
    result = gitlab._clone_project(project, "qa", 443, use_https=True, token=None, clone_dir=str(tmp_path))
    assert result["status"] == "failed" and result["error"]
    assert not Path(result["dest"]).exists() and sibling.read_text() == "preserve"
    assert all(not Path(command[-1]).exists() for command in commands)
    assert not list(tmp_path.rglob("*.tmp"))
    assert len(commands) == (1 if failure in {"initial_oserror", "publish"} else 2)
    if len(commands) == 2:
        assert "--depth" in commands[0] and "--depth" not in commands[1]
        assert commands[0][-1] == commands[1][-1]


def test_gitlab_existing_repository_origin_probe_failure_preserves_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = {"id": 7, "path_with_namespace": "group/app", "http_url_to_repo": "https://qa/group/app.git"}
    monkeypatch.setattr(gitlab.shutil, "which", lambda name: None)
    destination = gitlab._clone_project(project, "qa", 443, use_https=True, token=None, clone_dir=str(tmp_path))["dest"]
    repo = Path(destination)
    (repo / ".git").mkdir(parents=True)
    (repo / "keep").write_text("existing")
    monkeypatch.setattr(gitlab.shutil, "which", lambda name: "/fake/git")

    def run(*args: Any, **kwargs: Any) -> Any:
        raise OSError("cannot inspect origin")

    monkeypatch.setattr(gitlab.subprocess, "run", run)
    result = gitlab._clone_project(project, "qa", 443, use_https=True, token=None, clone_dir=str(tmp_path))
    assert result["status"] == "failed" and "does not match" in result["error"]
    assert (repo / "keep").read_text() == "existing" and (repo / ".git").is_dir()
