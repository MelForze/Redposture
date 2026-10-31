from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.run_ci_parallel import Job, run_jobs


def test_parallel_runner_starts_all_versions_and_preserves_each_result(tmp_path: Path) -> None:
    probe = (
        "import json, pathlib, sys, time; "
        "tag, root, code = sys.argv[1:]; "
        "started = time.monotonic(); "
        "time.sleep(0.3); "
        "finished = time.monotonic(); "
        "pathlib.Path(root, tag + '.json').write_text(json.dumps([started, finished])); "
        "print('result=' + tag, flush=True); "
        "sys.exit(int(code))"
    )
    jobs = [
        Job(tag, (sys.executable, "-c", probe, tag, str(tmp_path), str(exit_code)))
        for tag, exit_code in (("py312", 0), ("py313", 7), ("py314", 0))
    ]

    results = run_jobs(jobs, tmp_path / "artifacts", sample_interval=0.05, max_rss_bytes=512 * 1024 * 1024)

    assert {tag: result.exit_code for tag, result in results.items()} == {"py312": 0, "py313": 7, "py314": 0}
    intervals = [json.loads((tmp_path / f"{tag}.json").read_text()) for tag in results]
    assert max(start for start, _ in intervals) < min(end for _, end in intervals)
    for tag in results:
        assert f"result={tag}" in (tmp_path / "artifacts" / f"{tag}.log").read_text()
    report = json.loads((tmp_path / "artifacts" / "results.json").read_text())
    assert report["overall_status"] == "failed"
    assert {tag: item["exit_code"] for tag, item in report["jobs"].items()} == {
        "py312": 0,
        "py313": 7,
        "py314": 0,
    }


def test_ci_scripts_expose_parallel_mode_without_removing_serial_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    for script in ("check_ci_matrix.sh", "check_before_push.sh"):
        help_text = subprocess.check_output(["bash", f"scripts/{script}", "--help"], cwd=root, text=True)
        assert "--parallel-tests" in help_text
        assert "--sequential-tests" in help_text
