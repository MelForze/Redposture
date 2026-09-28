"""Validate seeded inventory and credential isolation on a real local Harbor."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_extended_version_matrix import _record  # noqa: E402
from scripts.seed_real_vendors import push_image  # noqa: E402


def validate_inventory(record: dict[str, Any]) -> None:
    assert record.get("is_harbor") is True, "Harbor not confirmed"
    assert record.get("provided_credentials_ok") is True, "admin credentials not verified"
    assert record.get("harbor_error") is None, record.get("harbor_error")
    assert {"core/control-plane", "security/scanner-adapter"} <= set(record.get("harbor_repositories") or [])
    assert {"core/control-plane:latest", "security/scanner-adapter:latest"} <= set(record.get("images") or [])
    artifacts = record.get("harbor_artifacts") or []
    assert any(item.startswith("core/control-plane:latest@sha256:") for item in artifacts)
    assert any(item.startswith("security/scanner-adapter:latest@sha256:") for item in artifacts)
    enumeration = record["cve_enumeration"]
    assert [item["product_key"] for item in enumeration["products"]] == ["harbor"]
    assert all(item["product"] == "harbor" for item in enumeration["findings"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:18280")
    args = parser.parse_args()
    output = args.artifact_dir / "harbor-contracts"
    output.mkdir(parents=True)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/seed_real_vendors.py"), "harbor", args.url, str(output)],
        check=True,
        timeout=300,
    )
    # A second level of repository nesting exercises Harbor v2's double URL
    # encoding and the v1 full repository path, against the actual registry.
    push_image(args.url, "core/nested/controller", "admin", "Harbor12345")
    results = []
    for name, extra in (
        ("anonymous", []),
        ("admin", ["-u", "admin", "-p", "Harbor12345"]),
        ("invalid", ["-u", "admin", "-p", "wrong-password"]),
    ):
        command = [
            sys.executable,
            str(ROOT / "redposture.py"),
            "registry",
            "-t",
            args.url,
            "--timeout",
            "15",
            "--harbor",
            "--images",
            "--enum-cve",
            *extra,
        ]
        run = subprocess.run([*command, "--format", "json"], check=True, capture_output=True, text=True, timeout=180)
        (output / f"{name}.jsonl").write_text(run.stdout + run.stderr)
        record = _record(run.stdout)
        assert record.get("is_harbor") is True
        if name == "admin":
            validate_inventory(record)
            assert record.get("image_count") == 3
            assert any(item.startswith("core/nested/controller:latest@sha256:") for item in record["harbor_artifacts"])
        elif name == "invalid":
            assert record.get("provided_credentials_ok") is False
            assert not any(item.get("privileges_required") == "L" for item in record["cve_enumeration"]["findings"])
        for mode, options in (("txt", []), ("debug", ["--debug"])):
            target = output / f"{name}-{mode}.tsv"
            run = subprocess.run(
                [*command, *options, "--no-color", "-o", str(target)],
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
            (output / f"{name}-{mode}.log").write_text(run.stdout + run.stderr)
            assert "\x1b" not in target.read_text()
            assert all(len(line.split("\t")) == 4 for line in target.read_text().splitlines())
            assert "CVE's Enumeration" not in run.stdout or "potentially affected" in run.stdout
        results.append(
            {
                "case": name,
                "status": "passed",
                "version": record["harbor_info"]["harbor_version"],
                "cve_status": record["cve_enumeration"]["status"],
            }
        )
        print(f"[passed] Harbor {name}", flush=True)
    (output / "report.json").write_text(json.dumps({"results": results}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
