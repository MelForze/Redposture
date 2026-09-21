from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
import tomlkit

ROOT = Path(__file__).resolve().parents[1]
PROJECT_VERSION = str(tomlkit.parse((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])


def _load_verifier() -> ModuleType:
    path = ROOT / "scripts" / "verify_release_artifact.py"
    spec = importlib.util.spec_from_file_location("verify_release_artifact", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wheel(path: Path, *, include_catalog: bool = True, version: str = PROJECT_VERSION) -> Path:
    dist_info = f"redposture-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("redposture_core/cli.py", "")
        archive.writestr("redposture_core/module_registry.py", "")
        archive.writestr("redposture_core/cve.py", "")
        if include_catalog:
            archive.writestr(
                "redposture_core/data/cve_catalog.json",
                json.dumps({"catalog_version": "test", "entries": [{"id": "CVE-2000-0001"}]}),
            )
        archive.writestr(f"{dist_info}/METADATA", f"Name: redposture\nVersion: {version}\n")
        archive.writestr(
            f"{dist_info}/entry_points.txt",
            "[console_scripts]\nredposture = redposture_core.cli:main\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    return path


def test_release_artifact_verifier_accepts_complete_wheel(tmp_path: Path) -> None:
    verifier = _load_verifier()
    verifier.verify_wheel(_wheel(tmp_path / "redposture.whl"), expected_version=PROJECT_VERSION)


def test_release_artifact_verifier_rejects_missing_catalog_and_version_drift(tmp_path: Path) -> None:
    verifier = _load_verifier()
    with pytest.raises(ValueError, match="cve_catalog"):
        verifier.verify_wheel(
            _wheel(tmp_path / "missing.whl", include_catalog=False),
            expected_version=PROJECT_VERSION,
        )
    with pytest.raises(ValueError, match="does not match"):
        verifier.verify_wheel(_wheel(tmp_path / "stale.whl", version="0.0.0"), expected_version=PROJECT_VERSION)
