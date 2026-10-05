"""Keep the real-service OpenSearch credential QA aligned with the scan contract."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.verify_postrun import _validate_opensearch_defcreds_contract


def test_opensearch_postrun_accepts_expanded_order_and_verified_logstash(tmp_path: Path) -> None:
    usernames = (
        "admin",
        "admin",
        "admin",
        "admin",
        "elastic",
        "elastic",
        "elastic",
        "elastic",
        "kibana",
        "kibana",
        "logstash",
        "logstash_system",
        "opensearch",
        "opensearch",
    )
    attempts = []
    for index, username in enumerate(usernames):
        verified = index == 10
        attempts.append(
            {
                "username": username,
                "password": "<redacted>",
                "source": "default",
                "status": "weak_default_creds" if verified else "auth_required",
                "error": None if verified else "authentication failed",
                "auth_probe_status": "verified" if verified else "rejected",
                "auth_probe_http_status": 200 if verified else 401,
                "auth_probe_endpoint": "/_plugins/_security/authinfo",
                "auth_error_detail": None if verified else {"status": 401},
                "network_attempted": True,
                "verification_capability": "identity_endpoint_supported",
            }
        )
    record = {
        "host": "127.0.0.1",
        "port": 29201,
        "status": "weak_default_creds",
        "vendor": "opensearch",
        "scheme": "https",
        "auth_required": True,
        "auth_valid": True,
        "effective_username": "logstash",
        "error": None,
        "attempted_credentials": attempts,
    }
    artifact = tmp_path / "opensearch.json"
    artifact.write_text(json.dumps(record) + "\n", encoding="utf-8")
    _validate_opensearch_defcreds_contract(
        [{"label": "opensearch_defcreds", "exit_code": "0", "json_path": str(artifact)}]
    )
