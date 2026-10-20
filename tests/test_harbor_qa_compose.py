"""Harbor generated-bind regression; no Docker or live stand mutation."""

from __future__ import annotations

import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import prepare_harbor_qa_compose as harbor

ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE = b"-----BEGIN CERTIFICATE-----\nqa-certificate-bytes\n-----END CERTIFICATE-----\n"


def generated(tmp_path: Path):
    source = tmp_path / "data/secret/registry/root.crt"
    config = tmp_path / "common/config/registry"
    source.parent.mkdir(parents=True)
    config.mkdir(parents=True)
    source.write_bytes(CERTIFICATE)
    source.chmod(0o600)
    (config / "root.crt").write_bytes(b"")
    config_mount = dict(type="bind", source=str(config), target="/etc/registry", read_only=True, bind={"selinux": "z"})
    nested = dict(type="bind", source=str(source), target="/etc/registry/root.crt")
    other = dict(type="bind", source=str(tmp_path / "data/registry"), target="/storage", bind={"selinux": "z"})
    payload = dict(
        services={
            "registry": dict(image="goharbor/registry-photon:v2.11.1", volumes=[other, config_mount, nested]),
            "registryctl": dict(image="goharbor/harbor-registryctl:v2.11.1", volumes=[deepcopy(config_mount)]),
            "other": dict(image="unrelated", volumes=[deepcopy(nested)]),
        },
        networks={"harbor": {"name": "qa-owned"}},
    )
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(json.dumps(payload, indent=2) + "\n")
    return compose, payload, source, config


def test_certificate_is_materialized_and_only_registry_nested_mount_removed(tmp_path):
    compose, before, source, config = generated(tmp_path)
    expected = deepcopy(before)
    expected["services"]["registry"]["volumes"].pop()
    assert harbor.prepare_compose(compose) is True
    assert (config / "root.crt").read_bytes() == source.read_bytes() == CERTIFICATE
    assert (config / "root.crt").stat().st_mode & 0o444 == 0o444
    assert json.loads(compose.read_text()) == expected
    assert source.stat().st_mode & 0o777 == 0o600
    contents, modified = compose.read_bytes(), compose.stat().st_mtime_ns
    assert harbor.prepare_compose(compose) is False
    assert compose.read_bytes() == contents and compose.stat().st_mtime_ns == modified


@pytest.mark.parametrize(
    "change", ["missing_source", "missing_parent", "foreign_parent", "foreign_source", "duplicate_child"]
)
def test_invalid_mapping_fails_without_compose_or_destination_changes(tmp_path, change):
    compose, payload, source, config = generated(tmp_path)
    mounts = payload["services"]["registry"]["volumes"]
    if change == "missing_source":
        source.unlink()
    elif change == "missing_parent":
        mounts.pop(1)
    elif change == "foreign_parent":
        mounts[1]["source"] = str(tmp_path.parent / "foreign-config")
    elif change == "foreign_source":
        mounts[2]["source"] = str(tmp_path.parent / "foreign-cert")
    else:
        mounts.append(deepcopy(mounts[2]))
    compose.write_text(json.dumps(payload))
    before = compose.read_bytes()
    with pytest.raises((ValueError, OSError)):
        harbor.prepare_compose(compose)
    assert compose.read_bytes() == before
    assert (config / "root.crt").read_bytes() == b""


def test_relative_generated_paths_are_resolved_beside_compose(tmp_path):
    compose, payload, source, config = generated(tmp_path)
    for mount in payload["services"]["registry"]["volumes"]:
        mount["source"] = os.path.relpath(mount["source"], tmp_path)
    compose.write_text(json.dumps(payload))
    assert harbor.prepare_compose(compose)
    assert (config / "root.crt").read_bytes() == CERTIFICATE


@pytest.mark.parametrize("already_generated", [False, True])
def test_sequential_matrix_prepares_then_repairs_before_compose_override(tmp_path, already_generated):
    text = (ROOT / "scripts/run_lab_matrix_sequential.sh").read_text()
    function = text[text.index("compose_service() {") :].split("\n}\n", 1)[0] + "\n}\n"
    out = tmp_path / "out"
    (out / "logs").mkdir(parents=True)
    if already_generated:
        (out / "stands/harbor").mkdir(parents=True)
        (out / "stands/harbor/docker-compose.yml").write_text("{}")
    calls = tmp_path / "calls"
    setup = """
ROOT_DIR=/repo; LAB_DIR=/lab; PYTHON_BIN=qa_python; COMPOSE_PROJECT_NAME=qa
qa_python(){
  case "$1" in
    *prepare_version.py) echo prepare >> "$CALLS"; mkdir -p "$3"; printf '{}' > "$3/docker-compose.yml" ;;
    *prepare_harbor_qa_compose.py) echo repair >> "$CALLS" ;;
    *) return 17 ;;
  esac
}
qa_compose_override(){ echo override >> "$CALLS"; echo /override; }
docker(){ echo docker >> "$CALLS"; }
"""
    run = subprocess.run(
        ["bash", "-c", setup + function + "\ncompose_service registry-harbor config"],
        env={**os.environ, "CALLS": str(calls), "OUT_DIR": str(out)},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert run.returncode == 0, run.stderr
    assert calls.read_text().splitlines() == ([] if already_generated else ["prepare"]) + [
        "repair",
        "override",
        "docker",
    ]
