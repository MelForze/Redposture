"""The all-module performance gate stays explicit and preserves its inputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_full_local_qa.sh"


def test_all_module_profile_is_listed_but_not_added_to_default_long_qa():
    listed = subprocess.run(["bash", str(RUNNER), "--list"], capture_output=True, text=True, check=True)
    assert "module-performance" in listed.stdout
    planned = subprocess.run(["bash", str(RUNNER), "--plan"], capture_output=True, text=True, check=True)
    assert "section: module-performance" not in planned.stdout


def test_module_profile_requires_baseline_and_image_before_starting_a_sample(tmp_path):
    env = dict(os.environ)
    env.pop("REDPOSTURE_MODULE_PROFILE_BASELINE", None)
    env.pop("REDPOSTURE_MODULE_PROFILE_IMAGE", None)
    result = subprocess.run(
        ["bash", str(RUNNER), str(tmp_path / "qa"), "--section", "module-performance"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    log = (tmp_path / "qa/sections/module-performance.log").read_text()
    assert "REDPOSTURE_MODULE_PROFILE_BASELINE" in log
    assert "failed sections: module-performance" in result.stderr + result.stdout


def test_module_profile_passes_literal_paths_and_complete_comparison_settings(tmp_path):
    recorded = tmp_path / "arguments.json"
    fake_python = tmp_path / "python"
    fake_python.write_text(
        f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
        f"Path({str(recorded)!r}).write_text(json.dumps(sys.argv[1:]))\n"
    )
    fake_python.chmod(0o755)
    baseline = tmp_path / "before tree; literal"
    env = dict(
        os.environ,
        PYTHON_BIN=str(fake_python),
        REDPOSTURE_MODULE_PROFILE_BASELINE=str(baseline),
        REDPOSTURE_MODULE_PROFILE_IMAGE="profile-image:local",
    )
    output = tmp_path / "qa output"
    result = subprocess.run(
        ["bash", str(RUNNER), str(output), "--section", "module-performance"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    arguments = json.loads(recorded.read_text())
    assert arguments[:3] == ["scripts/run_qa_with_timeout.py", "7200", "--"]
    assert "scripts/compare_module_performance.py" in arguments
    assert arguments[arguments.index("--before") + 1] == str(baseline)
    assert arguments[arguments.index("--after") + 1] == str(ROOT)
    assert arguments[arguments.index("--container-image") + 1] == "profile-image:local"
    assert arguments[arguments.index("--modules") + 1] == "all"
    assert arguments[arguments.index("--mode") + 1] == "detect"
    assert arguments[arguments.index("--repeats") + 1] == "3"
    assert arguments[arguments.index("--output") + 1] == str(output / "module-performance")
