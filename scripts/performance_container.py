"""Owned offline container for a single performance sample."""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any


def container_sample(root: Path, script: Path, source: Path, output: Path, image: str, flags: list[str]) -> int:
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True, timeout=30
    ).strip()
    if not image_id.startswith("sha256:"):
        raise ValueError("cannot pin measurement image")
    name = "redposture-workflow-profile-" + uuid.uuid4().hex
    lease_path = output.with_suffix(".container.json")
    lease = {"name": name, "image_id": image_id, "output": str(output.resolve()), "cleanup": "PENDING"}
    lease_path.write_text(json.dumps(lease, indent=2) + "\n")
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--name",
        name,
        "--label",
        "redposture.qa.profile-output=" + str(output.resolve()),
        "--network",
        "none",
        "--cpus",
        "2",
        "--memory",
        "1g",
        "--pids-limit",
        "512",
        "--mount",
        f"type=bind,src={source.resolve()},dst=/profile-source,readonly",
        "--mount",
        f"type=bind,src={root},dst=/profile-tools,readonly",
        "--mount",
        f"type=bind,src={output.parent.resolve()},dst=/profile-output",
        image_id,
        "python",
        "/profile-tools/" + str(script.relative_to(root)),
        "--source",
        "/profile-source",
        "--output",
        "/profile-output/" + output.name,
        *flags,
    ]
    try:
        result = subprocess.run(command, timeout=600, check=False)
    finally:
        cleanup = subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, timeout=30, check=False)
        lease["cleanup"] = (
            "PASS" if cleanup.returncode == 0 or b"no such container" in cleanup.stderr.lower() else "FAIL"
        )
        lease_path.write_text(json.dumps(lease, indent=2) + "\n")
        if lease["cleanup"] != "PASS":
            raise RuntimeError("container cleanup failed; do not start another sample")
    if not output.exists():
        raise RuntimeError(f"sample exited {result.returncode} without artifact")
    payload: dict[str, Any] = json.loads(output.read_text())
    payload.update(
        container_image_id=image_id,
        container_limits={"cpus": 2, "memory_bytes": 1024**3, "pids": 512, "network": "none"},
    )
    output.write_text(json.dumps(payload, indent=2) + "\n")
    return result.returncode
