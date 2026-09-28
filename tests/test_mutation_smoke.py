from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mutation_smoke_covers_critical_decision_classes() -> None:
    namespace = runpy.run_path(str(ROOT / "scripts/run_mutation_smoke.py"), run_name="redposture_mutation_smoke")
    mutations = namespace["MUTATIONS"]

    assert len(mutations) >= 4
    sources = {mutation.source for mutation in mutations}
    assert "redposture_core/cve.py" in sources
    assert "redposture_core/stage_runtime.py" in sources
    assert "redposture_core/clients/http_api.py" in sources
    assert "redposture_core/auth_detection.py" in sources
    for mutation in mutations:
        assert mutation.tests
        assert mutation.original != mutation.replacement
        assert mutation.original in (ROOT / mutation.source).read_text(encoding="utf-8")


def test_mutation_runner_does_not_count_import_errors_as_killed(tmp_path, monkeypatch) -> None:
    import subprocess

    from scripts import run_mutation_smoke as runner

    mutation = runner.MUTATIONS[0]

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 2, "ERROR collecting tests: ImportError", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    killed, output = runner.run_mutation(mutation)
    assert killed is False
    assert "ImportError" in output
