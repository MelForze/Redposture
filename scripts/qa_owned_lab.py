"""Small serial Docker lab with bounded commands and explicit resource ownership."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any


class OwnedLab:
    def __init__(self, out: Path) -> None:
        self.out = out
        out.mkdir(parents=True, exist_ok=False)
        self.owner = "rphard22-" + uuid.uuid4().hex[:12]
        self.label = "io.redposture.qa.owner=" + self.owner
        self.commands: list[dict[str, Any]] = []
        self.before = self.snapshot()
        self.mounts: set[str] = set()
        self.names: list[str] = []

    def run(self, *args: str, input: str | None = None, timeout: float = 30, check: bool = True) -> str:
        started = time.monotonic()
        child = subprocess.Popen(
            args,
            cwd=self.out,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = child.communicate(input, timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)
            raise
        row = {
            "args": args,
            "code": child.returncode,
            "seconds": time.monotonic() - started,
            "stdout": stdout,
            "stderr": stderr,
        }
        self.commands.append(row)
        (self.out / "commands.json").write_text(json.dumps(self.commands, indent=2))
        if check and child.returncode:
            raise RuntimeError(f"exit {child.returncode}: {args}: {stderr[-1500:]}")
        return stdout

    def docker(self, *args: str, **kwargs: Any) -> str:
        return self.run("docker", *args, **kwargs)

    def snapshot(self) -> dict[str, Any]:
        ids = self.docker("ps", "-aq").split()
        containers = json.loads(self.docker("inspect", *ids)) if ids else []
        network_lines = self.docker("network", "ls", "--no-trunc", "--format", "json").splitlines()
        return {
            "containers": {c["Id"]: c["State"]["Running"] for c in containers},
            "volumes": self.docker("volume", "ls", "-q").split(),
            "networks": [json.loads(line) for line in network_lines],
        }

    def network(self) -> str:
        if not getattr(self, "_network", None):
            self.docker("network", "create", "--label", self.label, self.owner)
            self._network = self.owner
        return self._network

    def start(
        self,
        name: str,
        image: str,
        *,
        command: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        ports: tuple[int, ...] = (),
        published: dict[int, int] | None = None,
        mounts: tuple[str, ...] = (),
        memory: str = "384m",
        privileged: bool = False,
    ) -> str:
        container = self.owner + "-" + name
        self.names.append(container)
        args = [
            "run",
            "-d",
            "--pull=never",
            "--name",
            container,
            "--label",
            self.label,
            "--network",
            self.network(),
            "--network-alias",
            name,
            "--memory",
            memory,
            "--cpus",
            "1",
            "--pids-limit",
            "256",
        ]
        if privileged:
            args.append("--privileged")
        for key, value in (env or {}).items():
            args.extend(("-e", key + "=" + value))
        for port in ports:
            args.extend(("-p", f"127.0.0.1::{port}"))
        for inner, outer in (published or {}).items():
            args.extend(("-p", f"127.0.0.1:{outer}:{inner}"))
        for mount in mounts:
            args.extend(("-v", mount))
        try:
            self.docker(*args, image, *command, timeout=90)
        finally:
            self.collect_mounts()
        return container

    def collect_mounts(self) -> None:
        ids = self.docker("ps", "-aq", "--filter", "label=" + self.label).split()
        if ids:
            for container in json.loads(self.docker("inspect", *ids)):
                assert container["Config"]["Labels"].get("io.redposture.qa.owner") == self.owner
                self.mounts.update(m["Name"] for m in container.get("Mounts", []) if m["Type"] == "volume")

    def port(self, name: str, port: int) -> int:
        value = self.docker("port", self.owner + "-" + name, str(port) + "/tcp").strip()
        return int(value.rsplit(":", 1)[1])

    def execute(self, name: str, *args: str, **kwargs: Any) -> str:
        return self.docker("exec", "-i", self.owner + "-" + name, *args, **kwargs)

    def ready(self, name: str, *args: str, seconds: float = 90) -> None:
        deadline = time.monotonic() + seconds
        while True:
            try:
                self.execute(name, *args, timeout=min(10, max(0.1, deadline - time.monotonic())))
                return
            except (RuntimeError, subprocess.TimeoutExpired):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{name} not ready in {seconds}s") from None
                time.sleep(0.25)

    def close(self) -> dict[str, Any]:
        self.collect_mounts()
        ids = self.docker("ps", "-aq", "--filter", "label=" + self.label).split()
        for container in ids:
            self.docker("logs", "--tail", "100", container, check=False)
            self.docker("rm", "-f", "-v", container)
        for volume in sorted(self.mounts - set(self.before["volumes"])):
            if volume in self.docker("volume", "ls", "-q").split():
                assert not self.docker("ps", "-aq", "--filter", "volume=" + volume).strip()
                self.docker("volume", "rm", volume)
        networks = self.docker("network", "ls", "-q", "--filter", "label=" + self.label).split()
        for network in networks:
            self.docker("network", "rm", network)
        after = self.snapshot()
        before_networks = {n["ID"]: n["Name"] for n in self.before["networks"]}
        after_networks = {n["ID"]: n["Name"] for n in after["networks"]}
        preservation = {
            "containers": all(after["containers"].get(k) == v for k, v in self.before["containers"].items()),
            "volumes": set(self.before["volumes"]) <= set(after["volumes"]),
            "networks": set(before_networks) <= set(after_networks),
            "missing_networks": {k: v for k, v in before_networks.items() if k not in after_networks},
            "new_containers": sorted(set(after["containers"]) - set(self.before["containers"])),
            "new_volumes": sorted(set(after["volumes"]) - set(self.before["volumes"])),
            "owned_remaining": self.docker("ps", "-aq", "--filter", "label=" + self.label).split(),
        }
        (self.out / "preservation.json").write_text(json.dumps(preservation, indent=2))
        return preservation

    def __enter__(self) -> OwnedLab:
        return self

    def __exit__(self, *_args: Any) -> None:
        result = self.close()
        assert all(result[key] for key in ("containers", "volumes", "networks")), result
        assert not result["owned_remaining"] and not result["new_volumes"], result
