"""Validate anonymous, admin, Reporter and invalid-token access on real GitLab."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_extended_version_matrix import _record  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--version", default="17.7.1")
    args = parser.parse_args()
    output = args.artifact_dir / "gitlab-contracts"
    output.mkdir(parents=True)
    results = []
    for name, token in (
        ("anonymous", None),
        ("root", "glpat-redposture-lab-root-2026"),
        ("reporter", "glpat-redposture-lab-analyst-2026"),
        ("invalid", "glpat-wrong-fixture-token"),
    ):
        command = [
            sys.executable,
            str(ROOT / "redposture.py"),
            "gitlab",
            "-t",
            "http://127.0.0.1:18080",
            "--timeout",
            "15",
            "--enum-cve",
            *(["--token", token] if token else []),
        ]
        run = subprocess.run([*command, "--format", "json"], capture_output=True, text=True, check=True, timeout=180)
        (output / f"{name}.jsonl").write_text(run.stdout + run.stderr)
        record = _record(run.stdout)
        assert record.get("is_gitlab") is True
        enumeration = record["cve_enumeration"]
        if name in {"root", "reporter"}:
            assert record.get("token_valid") is True
            assert enumeration["products"][0]["normalized_version"] == args.version
            assert record["token_user"].get("is_admin", False) is (name == "root")
            projects = {project["path_with_namespace"] for project in record["token_projects"]}
            assert {"redposture-lab/security-reports", "redposture-lab/incident-timeline"} <= projects
        else:
            if name == "invalid":
                assert record.get("token_valid") is False
            assert enumeration["status"] == "version_unknown"
            assert not enumeration["findings"]
        assert not any(item.get("privileges_required") == "L" for item in enumeration["findings"]) or name in {
            "root",
            "reporter",
        }
        for mode, options in (("txt", []), ("debug", ["--debug"])):
            target = output / f"{name}-{mode}.tsv"
            run = subprocess.run(
                [*command, *options, "--no-color", "-o", str(target)],
                capture_output=True,
                text=True,
                check=True,
                timeout=180,
            )
            (output / f"{name}-{mode}.log").write_text(run.stdout + run.stderr)
            assert "CVE's Enumeration" not in run.stdout or "potentially affected" in run.stdout
            assert "\x1b" not in target.read_text()
            assert all(len(line.split("\t")) == 4 for line in target.read_text().splitlines())
        results.append({"case": name, "status": "passed", "cve_status": enumeration["status"]})
        print(f"[passed] GitLab {name}", flush=True)
    (output / "report.json").write_text(json.dumps({"results": results}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
