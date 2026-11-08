"""Protected Airflow API calibration, including identity independent of DAG ACL."""

from __future__ import annotations

import base64
import json

import pytest

from scripts import performance_http_fixtures as peers
from scripts.performance_contracts import credential_summary, credential_verdict_errors


def request(path, pair=None, *, limited=False, method="GET"):
    headers = {b"authorization": b"Basic " + base64.b64encode((":".join(pair)).encode())} if pair else {}
    wire = peers.airflow_reply(method, path, headers, b"", valid_pair=("reader", "correct"), limited=limited)
    head, _, body = wire.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(body)


@pytest.mark.parametrize("pair", [None, ("reader", "wrong"), ("other", "correct")])
def test_every_protected_collection_rejects_wrong_or_missing_pair(pair):
    for path in ["/api/v1/dags", "/api/v1/variables", "/api/v1/connections"]:
        status, payload = request(path, pair)
        assert status == payload["status"] == 401 and payload["title"] == "Unauthorized"
        assert "airflow.apache.org" in payload["type"] and payload["detail"]


def test_limited_pair_has_independent_variable_access_while_dags_and_connections_are_denied():
    assert request("/api/v1/dags", ("reader", "correct"), limited=True)[0] == 403
    assert request("/api/v1/connections", ("reader", "correct"), limited=True)[0] == 403
    code, data = request("/api/v1/variables?limit=1&offset=1", ("reader", "correct"), limited=True)
    assert code == 200 and len(data["variables"]) == 1 and data["total_entries"] == 2
    assert request("/api/v1/variables", limited=True)[0] == 401


def test_public_version_is_not_a_public_dag_collection_and_pagination_terminates():
    assert request("/api/v1/version")[1]["version"] == "2.9.2"
    assert request("/api/v2/version")[0] == 404
    assert request("/api/v1/dags", ("reader", "correct"))[1]["total_entries"] == 3
    assert request("/api/v1/dags?limit=2&offset=3", ("reader", "correct"))[1] == {"dags": [], "total_entries": 3}
    assert request("/unsupported", ("reader", "correct"))[0] == 404
    assert request("/api/v1/dags", ("reader", "correct"), method="POST")[0] == 403


@pytest.mark.parametrize("state,verified", [("invalid", False), ("valid", True), ("valid_but_restricted", True)])
def test_single_pair_observation_reads_identity_from_module_proof_without_adding_a_public_ledger(state, verified):
    record = {
        "service": "airflow",
        "is_airflow": True,
        "credential_state": state,
        "credential_results": [{"username": "reader", "state": state, "error_code": "401" if not verified else None}],
        "credential_password": "observed",
        "provided_credentials_ok": verified,
    }
    assert credential_summary(record)["attempts_observed"] == 1
    expected = {("reader", "observed", None)} if verified else set()
    assert not credential_verdict_errors(record, accepted_identities=expected)
    assert "attempted_credentials" not in record


@pytest.mark.parametrize(
    "change",
    [
        {"credential_password": None},
        {"provided_credentials_ok": None},
        {"credential_state": "verification_unavailable"},
        {"is_airflow": False},
    ],
)
def test_unavailable_or_incomplete_single_pair_proof_cannot_pass(change):
    record = {
        "service": "airflow",
        "is_airflow": True,
        "credential_state": "invalid",
        "credential_results": [{"username": "reader", "state": "invalid", "error_code": "401"}],
        "credential_password": "observed",
        "provided_credentials_ok": False,
        **change,
    }
    assert credential_verdict_errors(record, accepted_identities=set())


@pytest.mark.parametrize("limited", [False, True])
def test_inventory_gate_checks_full_objects_counts_and_denials(limited):
    from scripts.performance_contracts import airflow_inventory_errors

    record = {
        "provided_credentials_ok": True,
        "show_dags_requested": True,
        "show_keys_requested": True,
        "show_connections_requested": True,
        "variable_keys": ["deployment_region", "pipeline_pool"],
        "variable_keys_count": 2,
        "variable_keys_total": 2,
        "variable_keys_truncated": False,
        "dag_ids": [] if limited else ["finance_daily", "events_ingest", "warehouse_rollup"],
        "dag_ids_count": 0 if limited else 3,
        "dag_ids_total": 0 if limited else 3,
        "dag_ids_truncated": False,
        "airflow_connections_count": 0 if limited else 2,
        "airflow_connections_total": 0 if limited else 2,
        "airflow_connections_truncated": False,
        "airflow_connections": []
        if limited
        else [
            {
                "connection_id": name,
                "conn_type": "postgres",
                "host": "database.internal",
                "port": 5432,
                "login": "reader",
                "schema": "analytics",
            }
            for name in ("warehouse_reporting", "events_archive")
        ],
    }
    if limited:
        record.update(
            {
                "dag_ids_error": "HTTP 403",
                "connections_error": "HTTP 403",
                "authenticated_dags_access": "denied",
                "authenticated_dags_http_status": 403,
                "authenticated_connections_access": "denied",
                "authenticated_connections_http_status": 403,
            }
        )
    assert not airflow_inventory_errors(record, limited=limited)
    assert airflow_inventory_errors({**record, "variable_keys": ["pipeline_pool", "pipeline_pool"]}, limited=limited)
    assert airflow_inventory_errors({**record, "variable_keys_truncated": True}, limited=limited)
    assert airflow_inventory_errors({**record, "show_connections_requested": False}, limited=limited)
    if limited:
        assert airflow_inventory_errors({**record, "dag_ids_error": None}, limited=True)
    else:
        assert airflow_inventory_errors({**record, "dag_ids": [{"bad": "value"}]}, limited=False)
        assert airflow_inventory_errors({**record, "airflow_connections": [{"connection_id": []}]}, limited=False)
