from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import tomlkit

ROOT = Path(__file__).resolve().parents[1]


def _load_reporter() -> object:
    path = ROOT / "scripts" / "run_output_quality_audit.py"
    spec = importlib.util.spec_from_file_location("run_output_quality_audit", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_output_marker_is_registered_and_excluded_from_default_pytest() -> None:
    config = tomlkit.parse((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]

    assert "not local_output_audit" in str(config["addopts"])
    assert any(str(marker).startswith("local_output_audit:") for marker in config["markers"])
    for name in (
        "test_local_output_audit.py",
        "test_concurrency_stress.py",
        "test_sigint_runtime.py",
        "test_soak_qa.py",
    ):
        source = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "pytest.mark.local_output_audit" in source
        assert "xfail" not in source


def test_output_quality_audit_is_local_only_and_writes_both_report_formats() -> None:
    shell = (ROOT / "scripts" / "run_output_quality_audit.sh").read_text(encoding="utf-8")
    reporter = (ROOT / "scripts" / "run_output_quality_audit.py").read_text(encoding="utf-8")
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / ".github/workflows").glob("*.yml"))

    assert shell.startswith("#!/usr/bin/env bash\nset -uo pipefail")
    assert "run_output_quality_audit.py" in shell
    assert "report.json" in reporter
    assert "report.md" in reporter
    assert "known-output-defects" in reporter
    assert "load-sigint-and-nested" in reporter
    assert "output-mutations" in reporter
    assert "docker-full-service-matrix" in reporter
    assert "run_output_quality_audit" not in workflows
    assert "run_mutation_smoke.py" not in workflows


def test_junit_parser_reports_pass_fail_skip_and_reproducible_nodeids(tmp_path: Path) -> None:
    reporter = _load_reporter()
    junit = tmp_path / "result.xml"
    junit.write_text(
        """<?xml version='1.0' encoding='utf-8'?>
<testsuites tests='3' failures='1' skipped='1'>
  <testsuite name='pytest' tests='3' failures='1' skipped='1'>
    <testcase classname='tests.test_output' name='test_pass' file='tests/test_output.py' />
    <testcase classname='tests.test_output' name='test_fail[redis]' file='tests/test_output.py'>
      <failure message='expected clean TSV'>E assert 'REDIS   ' == 'REDIS'</failure>
    </testcase>
    <testcase classname='tests.test_output' name='test_skip' file='tests/test_output.py'>
      <skipped message='Docker unavailable' />
    </testcase>
  </testsuite>
</testsuites>
""",
        encoding="utf-8",
    )

    counts, failures = reporter._pytest_counts(junit)

    assert counts == {"passed": 1, "failed": 1, "skipped": 1, "errors": 0}
    assert failures[0]["nodeid"] == "tests/test_output.py::test_fail[redis]"


def test_report_writer_keeps_stage_commands_defects_and_skipped_stands(tmp_path: Path) -> None:
    reporter = _load_reporter()
    failed = reporter.StageResult(
        name="known-output-defects",
        category="known-defects",
        command="python -m pytest -m local_output_audit",
        duration_seconds=1.25,
        status="failed",
        returncode=1,
        log=str(tmp_path / "failed.log"),
        failed=1,
        failures=[
            {
                "nodeid": "tests/test_local_output_audit.py::test_stored_tsv_module_tag_has_no_padding[redis]",
                "message": "expected clean TSV",
                "details": "E assert 'REDIS   ' == 'REDIS'",
            }
        ],
    )
    skipped = reporter.StageResult(
        name="docker-full-service-matrix",
        category="docker",
        command="./scripts/run_lab_matrix_sequential.sh /tmp/out",
        duration_seconds=0.0,
        status="skipped",
        returncode=None,
        log=str(tmp_path / "docker.log"),
        reason="Docker unavailable",
    )

    reporter._write_reports(tmp_path, [failed, skipped], "2026-09-24T00:00:00+00:00")

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert payload["summary"]["defects"] == 1
    assert payload["defects"][0]["module"] == "redis"
    assert payload["skipped_stands"] == [{"stage": "docker-full-service-matrix", "reason": "Docker unavailable"}]
    assert payload["local_failing_tests"] == [
        "tests/test_local_output_audit.py::test_stored_tsv_module_tag_has_no_padding[redis]"
    ]
    assert "## Detected defects" in markdown
    assert "Docker unavailable" in markdown


def test_report_writer_accepts_explicit_docker_reproduction_details(tmp_path: Path) -> None:
    reporter = _load_reporter()
    result = reporter.StageResult(
        name="docker-full-service-matrix",
        category="docker",
        command="./scripts/run_lab_matrix_sequential.sh /tmp/out",
        duration_seconds=10.0,
        status="failed",
        returncode=1,
        log=str(tmp_path / "docker.log"),
        failed=1,
        failures=[
            {
                "nodeid": "docker_tls",
                "module": "docker",
                "message": "TLS service was not detected",
                "details": "status=fail error=docker API HTTP 400: Bad Request",
                "reproduce": "redposture docker -t 127.0.0.1 --port 2376 --insecure --system",
                "actual_and_expected": "actual: status=fail; expected: confirmed Docker TLS service",
            }
        ],
    )

    reporter._write_reports(tmp_path, [result], "2026-09-24T00:00:00+00:00")

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert payload["defects"][0]["module"] == "docker"
    assert payload["defects"][0]["reproduce"].startswith("redposture docker")
    assert payload["defects"][0]["actual_and_expected"].startswith("actual:")
