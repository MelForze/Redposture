"""Bounded QA-runner regressions; no Docker, install, CI or scale workload runs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from redposture_core.module_registry import AUDIT_MODULE_NAMES
from scripts import matrix_flag_coverage as matrix
from scripts import run_http_detection_qa as http
from scripts import run_output_quality_audit as output
from scripts import run_qa_handoff as handoff

ROOT = Path(__file__).resolve().parents[1]


def shell(source, tmp_path, env=None):
    return subprocess.run(
        ["bash", "-c", source],
        cwd=tmp_path,
        env={**os.environ, **(env or {})},
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def function(name, path):
    text = path.read_text()
    return text[text.index(name + "() {") :].split("\n}\n", 1)[0] + "\n}\n"


def executable(path, text):
    path.write_text("#!/usr/bin/env bash\n" + text)
    path.chmod(0o755)


def test_q1_minimum_and_free_threaded_install_collection_dependencies(tmp_path):
    driver = tmp_path / "python"
    calls = tmp_path / "calls"
    executable(
        driver,
        """printf '%s\\n' "$*" >> "$QA_CALLS"
if [[ "$*" == '-m venv '* ]]; then
  mkdir -p "$3/bin"
  cp "$0" "$3/bin/python"
  printf '#!/usr/bin/env bash\\nexit 0\\n' > "$3/bin/redposture"
  chmod +x "$3/bin/redposture"
fi
""",
    )
    result = shell(
        f'bash "{ROOT}/scripts/run_dependency_compat.sh" min',
        tmp_path,
        {"PYTHON_BOOTSTRAP": str(driver), "QA_CALLS": str(calls)},
    )
    assert result.returncode == 0, result.stderr
    assert any("pip install" in line and "hypothesis" in line.lower() for line in calls.read_text().splitlines())
    calls.write_text("")
    workflow = (ROOT / ".github/workflows/advanced-quality.yml").read_text()
    run = workflow.split("- name: Install smoke dependencies", 1)[1].split("- name:", 1)[0].split("run: |", 1)[1]
    result = shell(
        "\n".join(line.strip() for line in run.splitlines()),
        tmp_path,
        {"PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "QA_CALLS": str(calls)},
    )
    assert result.returncode == 0
    assert "hypothesis" in calls.read_text().lower()


def test_q2_planned_token_mapping_is_complete_but_requires_executed_evidence(tmp_path):
    script = ROOT / "scripts/run_lab_matrix_sequential.sh"
    planned = matrix.build_coverage_report(script)
    assert planned["missing_actions"] == {}
    status = tmp_path / "matrix-status.tsv"
    status.write_text(
        "module\tlabel\texpected_exit\texit_code\n"
        + "".join(f"{case.module}\t{case.label}\t0\t0\n" for case in matrix.parse_matrix_cases(script.read_text()))
    )
    unexecuted = matrix.build_coverage_report(script, status_file=status)
    assert all(name in unexecuted["missing_actions"] for name in ("vault", "nomad", "jupyter"))
    (tmp_path / "focused-token-apis.xml").write_text(
        "<testsuites><testsuite>"
        + "".join(
            f'<testcase name="test_real_http_runner_prefix_tls_token_inventory_and_discovery[{module}]"/>'
            for module in ("vault", "nomad", "jupyter")
        )
        + '<testcase name="test_execute_http_contract[False-nomad-job]"/>'
        + '<testcase name="test_execute_http_contract[False-jupyter-kernel]"/>'
        + "</testsuite></testsuites>"
    )
    executed = matrix.build_coverage_report(script, status_file=status)
    assert executed["missing_actions"] == {}


def test_q2_static_gate_precedes_any_docker_boundary(tmp_path):
    driver = tmp_path / "python"
    executable(driver, 'echo "gate:$*"; exit 17\n')
    result = shell(
        f'bash "{ROOT}/scripts/run_lab_matrix_sequential.sh" "{tmp_path}/artifacts"',
        tmp_path,
        {
            "PYTHON_BIN": str(driver),
            "REDPOSTURE_MATRIX_PROFILE": "extended",
            "REDPOSTURE_LAB_DIR": str(tmp_path / "missing"),
        },
    )
    assert result.returncode == 17 and "matrix_flag_coverage.py" in result.stdout


def test_q3_handoff_runs_only_supported_locked_pythons(tmp_path):
    calls = []

    def run(command, log, **kwargs):
        calls.append(command)
        return 0, 0.0

    with (
        patch.object(handoff.shutil, "which", side_effect=lambda name: "/fake/" + name),
        patch.object(handoff, "_run_logged", side_effect=run),
    ):
        report = handoff._python_matrix(tmp_path)
    assert [row["python"] for row in report["results"]] == ["py312", "py313", "py314"]
    assert all(Path(command[-1]).exists() for command in calls if "--requirement" in command)


@pytest.mark.parametrize("service", ["minio", "valkey"])
def test_q4_sequential_snapshot_precedes_prepare(tmp_path, service):
    body = function("start_service", ROOT / "scripts/run_lab_matrix_sequential.sh")
    setup = """ROOT_DIR=/repo; LAB_DIR=/lab; PYTHON_BIN=qa_python
qa_python(){ if [[ "$*" == *qa_service_policy.py* ]]; then echo 1; else echo prepare; return 1; fi; }
snapshot_service_images(){ echo snapshot; }
"""
    result = shell(setup + body + f"\nstart_service {service} || true", tmp_path)
    assert result.stdout.splitlines()[:2] == ["snapshot", "prepare"]


def test_q4_focused_snapshot_precedes_prepare(tmp_path):
    text = (ROOT / "scripts/run_minio_kubeapi_lab.sh").read_text()
    body = text.split("trap cleanup EXIT\n", 1)[1].split("openssl req", 1)[0]
    setup = """ROOT_DIR=/repo; PYTHON_BIN=qa_python; COMPOSE_FILE=/fixture; PROJECT=qa
qa_python(){ if [[ "$*" == *qa_owned_images.py* ]]; then echo snapshot; else echo prepare; fi; }
"""
    result = shell(setup + body, tmp_path, {"REDPOSTURE_QA_CLEAN_IMAGES": "1", "TMPDIR": str(tmp_path)})
    assert result.stdout.splitlines() == ["snapshot", "prepare"]


@pytest.mark.parametrize("reporter", ["output", "http"])
def test_q5_old_junit_is_never_credited(tmp_path, reporter):
    (tmp_path / "stale.xml").write_text('<testsuites><testsuite><testcase name="old-pass"/></testsuite></testsuites>')
    with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
        if reporter == "output":
            result = output._run_stage(
                output.Stage("stale", "test", ("no-pytest",), pytest=True), tmp_path, False, None
            )
            assert result.passed == 0
        else:
            http_result = http._run("stale", ["no-pytest"], tmp_path, junit=True)
            assert http_result["counts"]["passed"] == 0


@pytest.mark.parametrize("response", ["KeeperErrorCode = ConnectionLoss", "numChildren = 99999"])
def test_q6_scale_ready_requires_actual_seed_count(tmp_path, response):
    text = (ROOT / "scripts/setup_zookeeper_scale_lab.sh").read_text()
    tail = text[text.index("LAST_NODE=") :]
    setup = f"""set -euo pipefail
SEED_PATH=/redposture/scale_100000; ZNODE_COUNT=100000; PROFILE=100k
ZK_SCALE_PORT=32181; START_TS=$(date +%s); TMP_DIR={tmp_path}
run_zkcli_script(){{ echo '{response}'; }}
"""
    result = shell(setup + tail, tmp_path)
    assert result.returncode != 0 and "is ready" not in result.stdout


def test_q6_seed_helper_does_not_swallow_zookeeper_errors(tmp_path):
    body = function("run_zkcli_script", ROOT / "scripts/setup_zookeeper_scale_lab.sh")
    setup = """CONTAINER_ID=qa
 docker(){ if [[ "$1" == cp ]]; then return 0; fi; echo 'KeeperErrorCode = ConnectionLoss'; return 0; }
"""
    result = shell(setup + body + "\nrun_zkcli_script /unused /unused", tmp_path)
    assert result.returncode != 0


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_q7_module_attribution_is_exact_and_current(module):
    assert set(output.AUDIT_MODULES) == set(AUDIT_MODULE_NAMES)
    assert output._module_from_nodeid(f"tests/test_contract.py::test_output[{module}]") == module
    assert module in http.MODULES


@pytest.mark.parametrize(
    "script,args",
    [("run_full_local_qa.sh", ["--section", "fixtures"]), ("run_version_qa.sh", []), ("run_qa_handoff.sh", ["full"])],
)
def test_r8_failed_tee_never_reports_success(tmp_path, script, args):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(ROOT / "scripts" / script, scripts)
    executable(
        scripts / "run_full_local_qa.sh" if script == "run_qa_handoff.sh" else scripts / "run_real_cve_matrix.sh",
        "echo stage-ok; exit 0\n",
    )
    executable(tmp_path / "python", "echo stage-ok; exit 0\n")
    executable(
        tmp_path / "tee", 'if [[ "$*" == *summary.txt* ]]; then exec /usr/bin/tee "$@"; fi; cat >/dev/null; exit 9\n'
    )
    artifact = tmp_path / "artifacts"
    command = [
        "bash",
        str(scripts / script),
        *(["full", str(artifact)] if script == "run_qa_handoff.sh" else [str(artifact), *args]),
    ]
    result = subprocess.run(
        command,
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "PYTHON_BIN": str(tmp_path / "python"),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0


@pytest.mark.parametrize("reporter", ["output", "http"])
@pytest.mark.parametrize("artifact", ["absent", "malformed"])
def test_q5_missing_or_malformed_current_junit_fails_explicitly(tmp_path, reporter, artifact):
    def run(*args, **kwargs):
        if artifact == "malformed":
            (tmp_path / "current.xml").write_text("<truncated")
        return subprocess.CompletedProcess([], 0)

    with patch.object(subprocess, "run", side_effect=run):
        if reporter == "output":
            result = output._run_stage(
                output.Stage("current", "test", ("no-pytest",), pytest=True), tmp_path, False, None
            )
            assert result.status == "failed" and "JUnit" in result.reason
        else:
            http_result = http._run("current", ["no-pytest"], tmp_path, junit=True)
            assert http_result["status"] == "failed" and "JUnit" in http_result["reason"]


def test_q2_token_fixture_path_is_checkout_owned(tmp_path):
    from scripts.qa_fixture_paths import compose_file

    assert compose_file(ROOT, "token-apis") == ROOT / "tests/fixtures/token_apis/docker-compose.yml"
    assert compose_file(tmp_path, "redis") == tmp_path / "lab/services/redis/docker-compose.yml"


def test_q6_verified_count_can_report_ready(tmp_path):
    text = (ROOT / "scripts/setup_zookeeper_scale_lab.sh").read_text()
    tail = text[text.index("LAST_NODE=") :]
    setup = f"""set -euo pipefail
SEED_PATH=/redposture/scale_100000; ZNODE_COUNT=100000; PROFILE=100k
ZK_SCALE_PORT=32181; START_TS=$(date +%s); TMP_DIR={tmp_path}
run_zkcli_script(){{ echo 'numChildren = 100000'; }}
"""
    result = shell(setup + tail, tmp_path)
    assert result.returncode == 0 and "is ready" in result.stdout and "actual_count:" in result.stdout


def test_q6_seed_helper_allows_existing_nodes(tmp_path):
    body = function("run_zkcli_script", ROOT / "scripts/setup_zookeeper_scale_lab.sh")
    setup = """CONTAINER_ID=qa
 docker(){ if [[ "$1" == cp ]]; then return 0; fi; echo 'KeeperErrorCode = NodeExists for /redposture'; return 0; }
"""
    result = shell(setup + body + "\nrun_zkcli_script /unused /unused", tmp_path)
    assert result.returncode == 0
