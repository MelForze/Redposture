"""Ownership proof is required before removing a QA volume."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.qa_owned_volumes import VolumeLedger


class Docker:
    def __init__(self) -> None:
        self.volumes = {"original": {"Name": "original", "CreatedAt": "before", "Labels": {}}}
        self.containers: list[dict] = []
        self.removed: list[str] = []

    def __call__(self, *args: str) -> str:
        if args[:3] == ("volume", "ls", "-q"):
            return "\n".join(
                name
                for name, volume in self.volumes.items()
                if len(args) == 3 or volume.get("Labels", {}).get("com.docker.compose.project") == "qa"
            )
        if args[:2] == ("volume", "inspect"):
            return json.dumps([self.volumes[name] for name in args[2:]])
        if args[:2] == ("volume", "rm"):
            self.removed.append(args[2])
            del self.volumes[args[2]]
            return args[2]
        if args[:2] == ("ps", "-aq"):
            if args[-1].startswith("volume="):
                return "\n".join(
                    c["Id"] for c in self.containers if any(m["Name"] == args[-1][7:] for m in c["Mounts"])
                )
            return "\n".join(c["Id"] for c in self.containers)
        if args[0] == "inspect":
            return json.dumps(self.containers)
        raise AssertionError(args)

    def add(self, name: str, *, source: str = "", owner: str = "qa") -> None:
        self.volumes[name] = {"Name": name, "CreatedAt": "new", "Labels": {}}
        self.containers.append(
            {
                "Id": "c" + name,
                "Config": {"Labels": {"com.docker.compose.project": owner}},
                "HostConfig": {"Mounts": [{"Type": "volume", "Source": source, "Target": "/data"}]},
                "Mounts": [{"Type": "volume", "Name": name, "Destination": "/data"}],
            }
        )


def test_capture_survives_reload_and_cleans_only_new_implicit_mounts(tmp_path: Path) -> None:
    docker = Docker()
    ledger = VolumeLedger(tmp_path / "volumes.json", "com.docker.compose.project", "qa", docker)
    ledger.begin()
    docker.add("anonymous")
    docker.add("borrowed", source="borrowed")
    docker.containers[0]["Mounts"].append({"Type": "volume", "Name": "original", "Destination": "/old"})
    ledger.capture()
    evidence = json.loads(ledger.path.read_text())
    assert evidence["containers"] and "anonymous" in evidence["volumes"]
    docker.containers = []
    restored = VolumeLedger(ledger.path, "com.docker.compose.project", "qa", docker)
    restored.cleanup()
    assert docker.removed == ["anonymous"]
    assert {"original", "borrowed"} <= docker.volumes.keys()


def test_capture_refuses_foreign_containers_and_cleanup_never_forces_in_use_volume(tmp_path: Path) -> None:
    docker = Docker()
    ledger = VolumeLedger(tmp_path / "volumes.json", "com.docker.compose.project", "qa", docker)
    ledger.begin()
    docker.add("foreign", owner="user")
    with pytest.raises(RuntimeError, match="ownership"):
        ledger.capture()
    docker.containers = []
    docker.add("owned")
    ledger.capture()
    with pytest.raises(RuntimeError, match="in use"):
        ledger.cleanup()
    assert not docker.removed


def test_volume_name_reuse_is_not_ownership(tmp_path: Path) -> None:
    docker = Docker()
    ledger = VolumeLedger(tmp_path / "volumes.json", "com.docker.compose.project", "qa", docker)
    ledger.begin()
    docker.add("reused")
    ledger.capture()
    docker.containers = []
    docker.volumes["reused"]["CreatedAt"] = "recreated-by-user"
    with pytest.raises(RuntimeError, match="identity"):
        ledger.cleanup()
    assert not docker.removed


def test_existing_project_refused_before_baseline_is_written(tmp_path: Path) -> None:
    docker = Docker()
    docker.add("existing")
    ledger = VolumeLedger(tmp_path / "volumes.json", "com.docker.compose.project", "qa", docker)
    with pytest.raises(RuntimeError, match="already"):
        ledger.begin()
    assert not ledger.path.exists()


def test_existing_named_project_volume_is_not_adopted(tmp_path: Path) -> None:
    docker = Docker()
    docker.volumes["older"] = {"Name": "older", "CreatedAt": "before", "Labels": {"com.docker.compose.project": "qa"}}
    ledger = VolumeLedger(tmp_path / "volumes.json", "com.docker.compose.project", "qa", docker)
    with pytest.raises(RuntimeError, match="already has volumes"):
        ledger.begin()
    assert not ledger.path.exists()
