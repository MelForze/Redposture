"""Persist mount evidence before teardown; never prune or remove borrowed volumes."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=30).stdout


class VolumeLedger:
    def __init__(self, path: Path, label: str, owner: str, run: Callable[..., str] = docker) -> None:
        self.path, self.label, self.owner, self.run = path, label, owner, run
        self.state: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}
        if self.state and self.state["selector"] != {"label": label, "owner": owner}:
            raise RuntimeError("volume ledger ownership mismatch")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.state, indent=2) + "\n")
        temporary.replace(self.path)

    def _ids(self) -> list[str]:
        return self.run("ps", "-aq", "--filter", f"label={self.label}={self.owner}").split()

    def begin(self) -> None:
        if self.state:
            return
        if self._ids():
            raise RuntimeError("QA project already has containers; refusing to adopt existing resources")
        if (
            self.label == "com.docker.compose.project"
            and self.run("volume", "ls", "-q", "--filter", f"label={self.label}={self.owner}").split()
        ):
            raise RuntimeError("QA project already has volumes; refusing to adopt existing resources")
        self.state = {
            "selector": {"label": self.label, "owner": self.owner},
            "baseline": self.run("volume", "ls", "-q").split(),
            "containers": {},
            "volumes": {},
        }
        self._save()

    @staticmethod
    def _implicit(container: dict[str, Any], mount: dict[str, Any]) -> bool:
        host = container.get("HostConfig") or {}
        if host.get("VolumesFrom"):
            return False
        destination = mount.get("Destination")
        for binding in host.get("Binds") or []:
            if len(parts := binding.split(":")) >= 2 and parts[1] == destination:
                return False
        for binding in host.get("Mounts") or []:
            if binding.get("Target") == destination and binding.get("Source"):
                return False
        return True

    def capture(self) -> None:
        if not self.state:
            raise RuntimeError("volume baseline is missing")
        ids = self._ids()
        for container in json.loads(self.run("inspect", *ids)) if ids else []:
            labels = container.get("Config", {}).get("Labels") or {}
            if labels.get(self.label) != self.owner:
                raise RuntimeError("container ownership mismatch")
            self.state["containers"][container["Id"]] = container.get("Mounts", [])
            self._save()  # Preserve evidence even if a subsequent inspect fails.
            for mount in container.get("Mounts", []):
                name = mount.get("Name")
                if mount.get("Type") != "volume" or not name or name in self.state["baseline"]:
                    continue
                volume = json.loads(self.run("volume", "inspect", name))[0]
                own_label = (volume.get("Labels") or {}).get(self.label) == self.owner
                if own_label or self._implicit(container, mount):
                    self.state["volumes"].setdefault(name, volume)
        # Compose can create a named volume before container creation fails.
        if self.label == "com.docker.compose.project":
            names = self.run("volume", "ls", "-q", "--filter", f"label={self.label}={self.owner}").split()
            for name in names:
                if name not in self.state["baseline"]:
                    volume = json.loads(self.run("volume", "inspect", name))[0]
                    if (volume.get("Labels") or {}).get(self.label) != self.owner:
                        raise RuntimeError("volume ownership mismatch")
                    self.state["volumes"].setdefault(name, volume)
        self._save()

    def cleanup(self) -> None:
        existing = set(self.run("volume", "ls", "-q").split())
        errors = []
        for name, proof in self.state.get("volumes", {}).items():
            if name in self.state["baseline"] or name not in existing:
                continue
            actual = json.loads(self.run("volume", "inspect", name))[0]
            if any(actual.get(key) != proof.get(key) for key in ("CreatedAt", "Driver", "Mountpoint", "Labels")):
                errors.append(f"{name}: volume identity changed")
                continue
            if self.run("ps", "-aq", "--filter", "volume=" + name).strip():
                errors.append(f"{name}: volume still in use")
                continue
            self.run("volume", "rm", name)  # No --force; Docker also checks use atomically.
        self.state["cleanup_errors"] = errors
        self._save()
        if errors:
            raise RuntimeError("; ".join(errors))


def guarded_command(command: list[str], directory: Path) -> list[str]:
    if command[:2] != ["docker", "compose"]:
        return command
    return [sys.executable, str(Path(__file__).resolve()), str(directory / "volumes"), *command]


def main(argv: list[str]) -> int:
    directory, *command = argv
    # Locate the subcommand without confusing option values with actions.
    actions = {"up", "create", "down", "rm"}
    options_with_values = {
        "-p",
        "--project-name",
        "-f",
        "--file",
        "--profile",
        "--env-file",
        "--project-directory",
        "--ansi",
        "--parallel",
        "--progress",
    }
    index = None
    cursor = 2
    while cursor < len(command):
        value = command[cursor]
        if value in options_with_values:
            cursor += 2
        elif value.startswith("-"):
            cursor += 1
        else:
            index = cursor if value in actions else None
            break
    if command[:2] != ["docker", "compose"] or index is None:
        return subprocess.call(command)
    prefix = command[:index]
    config = json.loads(
        subprocess.run(
            [*prefix, "config", "--format", "json"], check=True, capture_output=True, text=True, timeout=30
        ).stdout
    )
    project = config["name"]
    key = hashlib.sha256(
        (project + os.environ.get("DOCKER_CONTEXT", "") + os.environ.get("DOCKER_HOST", "")).encode()
    ).hexdigest()[:20]
    ledger = VolumeLedger(Path(directory) / (key + ".json"), "com.docker.compose.project", project)
    ledger.begin()
    action = command[index]
    if action in {"down", "rm"}:
        ledger.capture()  # If proof cannot be saved, do not destroy its source.
        command = [v for i, v in enumerate(command) if i <= index or v not in {"--volumes", "-v"}]
    child = subprocess.Popen(command)
    old_handlers = {}

    def stop(signum: int, _frame: Any) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    for signum in (signal.SIGTERM, signal.SIGINT):
        old_handlers[signum] = signal.signal(signum, stop)
    try:
        code = child.wait()
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        ledger.capture()
    if action in {"down", "rm"}:
        ledger.cleanup()
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"[error] QA volume guard: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
