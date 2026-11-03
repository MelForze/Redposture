from __future__ import annotations

from pathlib import Path

import pytest

from scripts.qa_memory_workload import run_memory_workload


def test_memory_child_runs_full_count_and_cleans_owned_disk(tmp_path: Path) -> None:
    trace = tmp_path / "location.txt"
    fixture = tmp_path / "workload.py"
    fixture.write_text(f"""import os, tempfile
from pathlib import Path
def work(count):
    location = Path(tempfile.gettempdir())
    Path({str(trace)!r}).write_text(str(location))
    (location / 'owned.txt').write_text('temporary')
    assert os.environ['SQLITE_TMPDIR'] == str(location)
    return {{'count': count, 'peak': 123}}
""")
    assert run_memory_workload(fixture, "work", 100_000) == {"count": 100_000, "peak": 123}
    assert not Path(trace.read_text()).exists()


def test_memory_child_failure_propagates_and_cleans_disk(tmp_path: Path) -> None:
    trace = tmp_path / "location.txt"
    fixture = tmp_path / "workload.py"
    fixture.write_text(f"""import tempfile
from pathlib import Path
def work(count):
    location = Path(tempfile.gettempdir())
    Path({str(trace)!r}).write_text(str(location))
    (location / 'owned.txt').write_text('temporary')
    raise AssertionError('real workload assertion')
""")
    with pytest.raises(AssertionError, match="real workload assertion"):
        run_memory_workload(fixture, "work", 100_000)
    assert not Path(trace.read_text()).exists()


def test_memory_child_cannot_silently_run_a_smaller_count(tmp_path: Path) -> None:
    fixture = tmp_path / "workload.py"
    fixture.write_text('def work(count):\n    return {"count": 3}\n')
    with pytest.raises(AssertionError):
        run_memory_workload(fixture, "work", 100_000)


def test_memory_supervisor_timeout_cleans_owned_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from scripts import qa_memory_workload as module

    locations = []

    def timeout_run(command, **kwargs):
        owned = Path(kwargs["env"]["TMPDIR"])
        (owned / "partial.sqlite").write_text("completed prefix")
        locations.append(owned)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(module.subprocess, "run", timeout_run)
    with pytest.raises(subprocess.TimeoutExpired):
        run_memory_workload(tmp_path / "unused.py", "work", 100_000)
    assert locations and not locations[0].exists()


def test_memory_child_refuses_disabled_assertions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "workload.py"
    fixture.write_text('def work(count):\n    return {"count": count}\n')
    monkeypatch.setenv("PYTHONOPTIMIZE", "1")
    with pytest.raises(AssertionError, match="requires enabled assertions"):
        run_memory_workload(fixture, "work", 100_000)
