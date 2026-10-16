"""Durable full UI export contracts, including resume and private output."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from redposture_core.ui_export import UIExport


def test_ui_export_resume_is_idempotent_and_private(tmp_path: Path) -> None:
    directory = str(tmp_path)
    scope = {"username": "qa", "bucket": "one"}
    with UIExport(directory, "http://qa", "minio_console", resume=False, scope=scope) as writer:
        for index in range(10_050):
            assert writer.add(f"object:{index}", "objects", {"index": index})
        first = writer.finish(complete=False, reason="interrupted")
        assert first["count"] == 10_050
        assert first["partial"] is True
    with UIExport(directory, "http://qa", "minio_console", resume=True, scope=scope) as writer:
        assert writer.has("object:10049")
        assert writer.add("object:10049", "objects", {"index": -1}) is False
        assert writer.add("object:10050", "objects", {"index": 10_050})
        final = writer.finish(complete=True)
    rows = [json.loads(line) for line in Path(final["path"]).read_text().splitlines()]
    assert len(rows) == 10_051
    assert [row["value"]["index"] for row in rows] == list(range(10_051))
    assert final["partial"] is False
    assert os.stat(final["path"]).st_mode & 0o777 == 0o600
    assert os.stat(final["checkpoint"]).st_mode & 0o777 == 0o600
    assert "\x1b[" not in Path(final["path"]).read_text()


def test_ui_export_refuses_implicit_overwrite_and_different_scope(tmp_path: Path) -> None:
    with UIExport(str(tmp_path), "http://qa", "portainer", resume=False, scope={"username": "qa"}) as writer:
        writer.add("environment:1", "environments", {"Id": 1})
        writer.finish(complete=True)
    with pytest.raises(FileExistsError):
        UIExport(str(tmp_path), "http://qa", "portainer", resume=False, scope={"username": "qa"})
    with pytest.raises(FileNotFoundError):
        UIExport(str(tmp_path), "http://qa", "portainer", resume=True, scope={"username": "other"})


def test_ui_export_auto_resumes_partial_and_starts_new_run_after_completion(tmp_path: Path) -> None:
    with UIExport(str(tmp_path), "http://qa", "portainer", resume=None) as writer:
        writer.add("environment:1", "environments", {"Id": 1})
        partial = writer.finish(complete=False)
    with UIExport(str(tmp_path), "http://qa", "portainer", resume=None) as writer:
        assert writer.has("environment:1")
        writer.add("environment:2", "environments", {"Id": 2})
        complete = writer.finish(complete=True)
    with UIExport(str(tmp_path), "http://qa", "portainer", resume=None) as writer:
        assert not writer.has("environment:1")
        writer.add("environment:3", "environments", {"Id": 3})
        fresh = writer.finish(complete=False)
    with UIExport(str(tmp_path), "http://qa", "portainer", resume=None) as writer:
        assert writer.has("environment:3")
        writer.add("environment:4", "environments", {"Id": 4})
        resumed = writer.finish(complete=True)
    assert partial["path"] == complete["path"]
    assert fresh["path"] != complete["path"]
    assert resumed["path"] == fresh["path"]
    assert resumed["count"] == 2
    assert Path(complete["path"]).exists()
