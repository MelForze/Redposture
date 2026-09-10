"""Credential-plan merging, client construction and lifecycle scenarios.

Covers `build_airflow_plan` default-credential merging/dedup, the `_client_for`
pool/scheme selection (with and without a lifecycle state), and the lifecycle
factory. No network.
"""

from __future__ import annotations

from types import SimpleNamespace

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import actions
from redposture_core.modules.airflow.stage import build_airflow_plan


def _pairs(plan):
    return [(run.username, run.password) for run in plan.credential_runs]


# --- credential-run merging ------------------------------------------------


def test_plan_without_defcreds_has_no_default_pairs():
    plan = build_airflow_plan(parse_args(["airflow", "-t", "127.0.0.1", "-u", "airflow", "-p", "secret"]))
    pairs = set(_pairs(plan))
    assert ("airflow", "secret") in pairs
    assert ("admin", "admin") not in pairs and ("airflow", "airflow") not in pairs


def test_plan_with_defcreds_includes_full_catalog():
    plan = build_airflow_plan(parse_args(["airflow", "-t", "127.0.0.1", "--defcreds"]))
    pairs = set(_pairs(plan))
    for pair in actions._DEFAULT_CREDENTIALS:
        assert pair in pairs


def test_plan_defcreds_dedups_provided_pair():
    plan = build_airflow_plan(
        parse_args(["airflow", "-t", "127.0.0.1", "-u", "airflow", "-p", "airflow", "--defcreds"])
    )
    assert _pairs(plan).count(("airflow", "airflow")) == 1


def test_plan_defcreds_default_runs_are_sorted_stably():
    first = _pairs(build_airflow_plan(parse_args(["airflow", "-t", "127.0.0.1", "--defcreds"])))
    second = _pairs(build_airflow_plan(parse_args(["airflow", "-t", "127.0.0.1", "--defcreds"])))
    assert first == second


# --- client construction ---------------------------------------------------


def test_client_for_fallback_https_on_tls_port():
    ctx = SimpleNamespace(host="h", port=8443, args=SimpleNamespace(timeout=5.0), lifecycle_state=None)
    client = actions._client_for(ctx)
    assert client.scheme == "https" and client.host == "h" and client.port == 8443


def test_client_for_fallback_http_on_plain_port():
    ctx = SimpleNamespace(host="h", port=8080, args=SimpleNamespace(timeout=5.0), lifecycle_state=None)
    assert actions._client_for(ctx).scheme == "http"


def test_client_for_uses_lifecycle_pool_and_resolved_scheme():
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    state.resolved_scheme = "http"  # pre-resolved -> no scheme probe fires
    ctx = SimpleNamespace(host="h", port=8080, args=SimpleNamespace(timeout=5.0), lifecycle_state=state)
    try:
        client = actions._client_for(ctx, basic_user="u", basic_password="p")
        assert client.scheme == "http"
        assert client._pool is state.pool
        assert client.basic_user == "u" and client.basic_password == "p"
    finally:
        state.close()


def test_client_for_passes_bearer_token():
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), "h", 8080)
    state.resolved_scheme = "http"
    ctx = SimpleNamespace(host="h", port=8080, args=SimpleNamespace(timeout=5.0), lifecycle_state=state)
    try:
        client = actions._client_for(ctx, bearer_token="JWT")
        assert client.bearer_token == "JWT"
    finally:
        state.close()


# --- lifecycle factory -----------------------------------------------------


def test_lifecycle_factory_builds_state_for_target():
    ctx = SimpleNamespace(args=SimpleNamespace(timeout=5.0, retries=0), host="h", port=8080)
    state = actions.airflow_lifecycle_state_factory(ctx)
    try:
        assert isinstance(state, actions.AirflowLifecycleState)
        assert state.host == "h" and state.port == 8080
        assert state.resolved_scheme is None and state.bearer_token is None
    finally:
        state.close()


def test_lifecycle_state_coerces_host_and_port_types():
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=5.0, retries=0), host=10, port="8081")
    try:
        assert state.host == "10" and state.port == 8081 and isinstance(state.port, int)
    finally:
        state.close()


def test_lifecycle_state_tolerates_missing_timeout_and_retries():
    # Defensive defaults when args lacks timeout/retries (None -> fallbacks).
    state = actions.AirflowLifecycleState(SimpleNamespace(timeout=None, retries=None), "h", 8080)
    state.close()
