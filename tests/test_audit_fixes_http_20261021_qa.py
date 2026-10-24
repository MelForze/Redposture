"""QA gate audit reproductions without Docker startup."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from redposture_core.cve import enumerate_record, load_catalog
from scripts import verify_auth_service_matrix as auth

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "invalid",
    [
        {"auth_valid": None, "auth_probe_status": "error", "auth_required": True, "status": "auth_required"},
        {"credential_state": "unverified", "auth_required": True},
        {"auth_required": True, "status": "auth_required"},
        {"credential_verified": False, "credential_verification": "unverified", "auth_required": True},
    ],
)
def test_qa21_01_auth_gate_does_not_credit_unknown_as_rejection(monkeypatch, invalid):
    monkeypatch.setattr(auth, "CASES", (auth.CASES[2],))
    monkeypatch.setattr(auth, "_wait_for_port", lambda p: None)
    monkeypatch.setattr(auth, "_wait_for_anonymous_result", lambda c: {"auth_required": True})
    monkeypatch.setattr(
        auth, "_scan", lambda case, creds: invalid if creds[1] == "definitely-wrong" else {"auth_valid": True}
    )
    with pytest.raises(AssertionError, match="rejection|unverified"):
        auth.main()


@pytest.mark.parametrize(
    "verdict",
    [
        {"auth_valid": False},
        {"provided_credentials_ok": False},
        {"credentials_valid": False},
        {"credential_state": "invalid"},
        {"auth_probe_status": "rejected"},
        {"credential_verified": False, "credential_verification": "rejected"},
    ],
)
def test_qa21_01_auth_gate_accepts_explicit_rejection(monkeypatch, verdict):
    monkeypatch.setattr(auth, "CASES", (auth.CASES[2],))
    monkeypatch.setattr(auth, "_wait_for_port", lambda p: None)
    monkeypatch.setattr(auth, "_wait_for_anonymous_result", lambda c: {"auth_required": True})
    monkeypatch.setattr(
        auth,
        "_scan",
        lambda case, creds: (
            {**verdict, "auth_required": True} if creds[1] == "definitely-wrong" else {"auth_valid": True}
        ),
    )
    assert auth.main() == 0


@pytest.mark.parametrize("returncode", [0, 17])
def test_qa21_02_legacy_runner_delegates_arguments_environment_and_exit(tmp_path, returncode):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(ROOT / "scripts/run_lab_matrix.sh", scripts)
    (scripts / "run_lab_matrix_sequential.sh").write_text(f"""#!/usr/bin/env bash
printf '%s\\n' "$@"
printf 'profile=%s\\n' "$REDPOSTURE_MATRIX_PROFILE"
exit {returncode}
""")
    result = subprocess.run(
        ["bash", str(scripts / "run_lab_matrix.sh"), "path with spaces", "--extra-argument"],
        env={**os.environ, "REDPOSTURE_MATRIX_PROFILE": "extended"},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == returncode
    assert result.stdout.splitlines() == ["path with spaces", "--extra-argument", "profile=extended"]


@pytest.mark.parametrize("label", ["airflow_creds", "airflow_anonymous"])
def test_qa21_03_airflow_golden_catalog_stamp_and_findings_are_current(label):
    record = json.loads((ROOT / "tests/fixtures/golden" / (label + ".json")).read_text())[0]
    actual = enumerate_record(
        "airflow", record, catalog=load_catalog(), confirmed=True, credentials_provided=label == "airflow_creds"
    )
    expected = record["cve_enumeration"]
    assert expected["findings"] == actual["findings"]
    assert expected["catalog_version"] == actual["catalog_version"]
