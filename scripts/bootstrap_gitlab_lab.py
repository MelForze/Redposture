"""Populate and verify an owned real GitLab QA project with bounded commands."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_service_version_matrix import run  # noqa: E402
from scripts.seed_real_vendors import request  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--compose", type=Path, default=ROOT / "lab/services/gitlab/docker-compose.yml")
    parser.add_argument("--project")
    args = parser.parse_args()
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    compose = ["docker", "compose", *(["-p", args.project] if args.project else []), "-f", str(args.compose)]
    run(
        [*compose, "exec", "-T", "gitlab-real", "gitlab-rails", "runner", "/qa/seed.rb"],
        args.artifact_dir / "bootstrap.log",
        timeout=600,
    )
    checks = []
    for username, token, admin in (
        ("root", "glpat-redposture-lab-root-2026", True),
        ("analyst", "glpat-redposture-lab-analyst-2026", False),
    ):
        headers = {"Private-Token": token}
        status, body, _ = request("http://127.0.0.1:18080/api/v4/user", headers=headers)
        payload = json.loads(body)
        assert status == 200 and payload.get("username") == username and payload.get("is_admin", False) is admin, (
            "real GitLab role bootstrap failed"
        )
        status, body, _ = request("http://127.0.0.1:18080/api/v4/version", headers=headers)
        payload = json.loads(body)
        assert status == 200 and payload.get("version") and payload.get("revision"), (
            "protected version endpoint not ready"
        )
        checks.append({"username": username, "admin": admin, "version": payload["version"], "status": "passed"})
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/seed_real_vendors.py"),
            "gitlab",
            "http://127.0.0.1:15003",
            str(args.artifact_dir / "registry"),
        ],
        check=True,
        timeout=300,
    )
    (args.artifact_dir / "report.json").write_text(json.dumps({"checks": checks}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
