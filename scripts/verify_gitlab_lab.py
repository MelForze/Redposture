"""Validate anonymous, admin, Reporter and invalid-token access on real GitLab."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_extended_version_matrix import _record  # noqa: E402


def verify_unknown_version_findings(enumeration: dict[str, object]) -> None:
    assert enumeration["status"] == "version_unknown"
    findings = enumeration["findings"]
    assert isinstance(findings, list)
    assert all(
        isinstance(item, dict)
        and item.get("product") == "gitlab"
        and item.get("detected_version") is None
        and item.get("version_assessment") == "unknown"
        and item.get("privileges_required") == "N"
        and item.get("access_basis") == "network"
        for item in findings
    )


def verify_rendered_findings(enumeration: dict[str, object], output: str) -> None:
    findings = enumeration["findings"]
    assert isinstance(findings, list)
    for item in findings:
        assert isinstance(item, dict)
        identifier = item.get("id")
        assert isinstance(identifier, str)
        expected = f"Possibly {identifier}" if enumeration["status"] == "version_unknown" else identifier
        assert expected in output


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
        json_command = [*command, "--format", "json"]
        (output / f"{name}.command.txt").write_text(shlex.join(json_command) + "\n")
        run = subprocess.run(json_command, capture_output=True, text=True, check=True, timeout=180)
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
            verify_unknown_version_findings(enumeration)
        assert not any(item.get("privileges_required") == "L" for item in enumeration["findings"]) or name in {
            "root",
            "reporter",
        }
        for mode, options in (("txt", []), ("debug", ["--debug"])):
            target = output / f"{name}-{mode}.tsv"
            txt_command = [*command, *options, "--no-color", "-o", str(target)]
            (output / f"{name}-{mode}.command.txt").write_text(shlex.join(txt_command) + "\n")
            run = subprocess.run(
                txt_command,
                capture_output=True,
                text=True,
                check=True,
                timeout=180,
            )
            (output / f"{name}-{mode}.log").write_text(run.stdout + run.stderr)
            verify_rendered_findings(enumeration, run.stdout)
            assert "\x1b" not in target.read_text()
            assert all(len(line.split("\t")) == 4 for line in target.read_text().splitlines())
        results.append({"case": name, "status": "passed", "cve_status": enumeration["status"]})
        print(f"[passed] GitLab {name}", flush=True)
    (output / "report.json").write_text(json.dumps({"results": results}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
