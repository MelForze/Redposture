"""Safety-property tests for the Airflow module.

These pin invariants that must hold no matter what the target returns — the
properties an auditor relies on to be safe to run and safe to share:

* detection and anonymous probing never send credentials on the wire;
* the token-exchange login carries credentials in the body, never as a header;
* every request is bounded by the response-size cap (no unbounded reads);
* the winning password is redacted from JSON output and only echoed in TXT;
* the 3.x bearer JWT is kept in memory and never serialized;
* the credential gate opens only on an exact ``True``, never a truthy value;
* the audit is read-only (no data/enumeration hook) and TLS is intentionally
  accepted (exposure audit, not a trust check).

No Docker or network.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients import airflow_api
from redposture_core.modules.airflow import actions, render, stage
from redposture_core.modules.airflow.types import CredentialResult


class SpyPool:
    """Records every wire call an AirflowClient makes."""

    def __init__(self, *, status: int = 200, body: bytes = b'{"version":"2.10.5"}') -> None:
        self.status = status
        self.body = body
        self.calls: list[dict] = []

    def request(self, method, url, *, headers=None, body=None, response_size_cap=None):
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers or {}), "body": body, "cap": response_size_cap}
        )
        return SimpleNamespace(status=self.status, body=self.body, headers={}, error=None)

    def close(self) -> None:
        pass


# --- credentials never leak onto the wire during unauthenticated stages -----


def test_detection_never_sends_credentials_even_when_present():
    pool = SpyPool()
    client = airflow_api.AirflowClient(
        pool, scheme="http", host="h", port=8080, basic_user="airflow", basic_password="airflow"
    )
    actions.detect_airflow(client)
    assert pool.calls, "detection must actually probe the target"
    assert all("Authorization" not in call["headers"] for call in pool.calls)


def test_anonymous_probe_never_sends_credentials_even_when_present():
    pool = SpyPool(status=401, body=b"")
    client = airflow_api.AirflowClient(
        pool, scheme="http", host="h", port=8080, basic_user="airflow", basic_password="airflow"
    )
    actions.classify_anonymous(client, "v1")
    assert pool.calls and all("Authorization" not in call["headers"] for call in pool.calls)


def test_token_exchange_puts_credentials_in_body_not_header():
    pool = SpyPool(body=b'{"access_token":"JWT"}')
    client = airflow_api.AirflowClient(
        pool, scheme="http", host="h", port=8080, basic_user="airflow", basic_password="airflow"
    )
    client.post_json("/auth/token", {"username": "airflow", "password": "s3cret"})
    call = pool.calls[0]
    assert "Authorization" not in call["headers"]
    assert call["body"] is not None and b"s3cret" in call["body"]


# --- bounded reads ----------------------------------------------------------


def test_every_request_enforces_the_response_size_cap():
    pool = SpyPool()
    client = airflow_api.AirflowClient(pool, scheme="http", host="h", port=8080)
    client.get("/api/v1/version", authed=False)
    client.post_json("/auth/token", {"username": "a", "password": "b"})
    assert pool.calls and all(call["cap"] == airflow_api._RESPONSE_CAP for call in pool.calls)
    assert airflow_api._RESPONSE_CAP == 2 * 1024 * 1024


# --- password redaction -----------------------------------------------------


def test_spec_declares_password_redaction():
    spec = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert "credential_password" in spec.structured_output_redact_fields


def test_password_redacted_from_json_but_echoed_in_txt():
    record = {
        "host": "h",
        "port": 8080,
        "status": "detected",
        "credential_state": "valid",
        "credential_password": "S3CRET",
        "role": "admin",
        "credential_results": [{"username": "airflow", "state": "valid", "error_code": None}],
    }
    # TXT accepted line echoes user:pass (house convention).
    txt = render._format_record(record, "txt")
    assert "airflow:S3CRET" in txt and "(role:admin)" in txt
    # The JSON path emits nothing from the renderer; the field is stripped by the
    # framework via structured_output_redact_fields (mirrored here).
    assert render._format_record(record, "json") == ""
    redacted = dict(record)
    for field in ("attempted_credentials", "credential_password"):
        redacted.pop(field, None)
    assert "credential_password" not in redacted
    assert "S3CRET" not in json.dumps(redacted)


# --- bearer JWT stays in memory ---------------------------------------------


def test_bearer_token_is_never_serialized_into_the_record(monkeypatch):
    monkeypatch.setattr(
        actions,
        "verify_credential",
        lambda *a, **k: CredentialResult(state="valid", username="airflow", bearer_token="JWT-SECRET"),
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **k: object())
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    ctx = SimpleNamespace(
        credential=SimpleNamespace(username="airflow", password="airflow", source="provided"), lifecycle_state=state
    )
    try:
        out = actions.auth_record(ctx, {"api_generation": "v2"})
    finally:
        state.close()
    assert state.bearer_token == "JWT-SECRET"  # kept for the in-process role probe
    assert "bearer_token" not in out
    assert "JWT-SECRET" not in json.dumps(out)


# --- credential gate is strict ---------------------------------------------


@pytest.mark.parametrize(
    ("value", "opened"),
    [(True, True), (False, False), (1, False), ("yes", False), (None, False), (0, False)],
)
def test_credential_gate_opens_only_on_exact_true(value, opened):
    from redposture_core.audit_models import AuditRecord

    record = AuditRecord(
        host="h", port=8080, service="airflow", status="detected", extra={"provided_credentials_ok": value}
    )
    assert stage._airflow_credential_gate(None, record)[0] is opened


# --- read-only posture and intentional TLS acceptance -----------------------


def test_airflow_audit_is_read_only():
    spec = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert spec.data is None  # no enumeration/mutation hook
    assert actions.host_stage is None


def test_lifecycle_pool_accepts_tls_by_design(monkeypatch):
    captured: dict = {}
    real = actions.HttpSessionPool

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(actions, "HttpSessionPool", spy)
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    try:
        assert captured.get("insecure") is True
    finally:
        state.close()
