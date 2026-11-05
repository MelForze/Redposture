"""Repeated auth cases need a uniform QA budget; postrun must stay strict."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.qa_compose_override import build_override
from tests.test_full_local_qa_contract import _load_postrun_verifier

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("service", ["grafana", "grafana-2", "grafana-3", "grafana-4", "grafana-5"])
def test_grafana_qa_replicas_have_uniform_budget_for_repeated_auth(service: str) -> None:
    config: dict[str, Any] = {
        "services": {
            service: {
                "container_name": f"redposture-lab-{service}",
                "image": "grafana/grafana-oss:13.0.2",
                "environment": {"GF_SECURITY_ADMIN_USER": "admin", "GF_SECURITY_ADMIN_PASSWORD": "fixture-pass"},
            }
        }
    }
    original = copy.deepcopy(config)
    override = build_override(config, "qa-grafana")
    environment = override["services"][service]["environment"]
    assert environment == {
        **config["services"][service]["environment"],
        "GF_SECURITY_BRUTE_FORCE_LOGIN_PROTECTION_MAX_ATTEMPTS": "1000",
    }
    assert "GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION" not in environment
    assert config == original


@pytest.mark.parametrize(
    ("name", "image"),
    [("custom-grafana", "grafana/grafana-oss:13.0.2"), ("redposture-lab-grafana", "another/product:1")],
)
def test_grafana_budget_does_not_modify_unrelated_service(name: str, image: str) -> None:
    config = {"services": {"grafana": {"container_name": name, "image": image, "environment": {"KEEP": "value"}}}}
    override = build_override(config, "qa-grafana")
    assert override["services"]["grafana"] == {"container_name": "qa-grafana-" + name}


def test_generated_compose_cache_preserves_grafana_environment(tmp_path: Path) -> None:
    config: dict[str, Any] = {
        "services": {
            "grafana": {
                "container_name": "redposture-lab-grafana",
                "image": "grafana/grafana-oss:13.0.2",
                "environment": {"GF_AUTH_ANONYMOUS_ENABLED": "false", "GF_SECURITY_ADMIN_PASSWORD": "fixture-pass"},
                "ports": [{"target": 3000, "published": "3000"}],
            }
        }
    }
    output = tmp_path / "resolved.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/qa_compose_override.py"),
            "--project",
            "qa-grafana",
            "--config-output",
            str(output),
        ],
        input=json.dumps(config),
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    override = json.loads(proc.stdout)
    cached = json.loads(output.read_text())
    service = cached["services"]["grafana"]
    assert service["environment"] == {
        **config["services"]["grafana"]["environment"],
        "GF_SECURITY_BRUTE_FORCE_LOGIN_PROTECTION_MAX_ATTEMPTS": "1000",
    }
    assert service["environment"] == override["services"]["grafana"]["environment"]
    assert service["ports"] == config["services"]["grafana"]["ports"]


def test_grafana_replica_validation_still_rejects_one_failed_login(tmp_path: Path) -> None:
    verifier = _load_postrun_verifier()
    artifact = tmp_path / "grafana.jsonl"
    records = [
        {"host": "127.0.0.1", "port": port, "status": "weak_default_creds", "is_grafana": True}
        for port in [3000, 13001, 13002, 13003, 13004]
    ]
    rows = [{"label": "grafana_multi_instance_urls", "exit_code": "0", "json_path": str(artifact)}]
    artifact.write_text("\n".join(json.dumps(record) for record in records))
    verifier._validate_multi_record_consistency(rows)
    records[0]["status"] = "auth_required"
    artifact.write_text("\n".join(json.dumps(record) for record in records))
    with pytest.raises(SystemExit, match="inconsistent status"):
        verifier._validate_multi_record_consistency(rows)
