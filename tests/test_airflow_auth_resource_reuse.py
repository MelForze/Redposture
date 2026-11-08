"""Auth capability handoff preserves identity, endpoint and response boundaries."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions
from redposture_core.stage_runtime import AuditCredentialRun


class Case:
    def __init__(self, *, limited=False):
        self.limited = limited
        self.restricted_names = {"dags", "connections"}
        self.base = "http://qa.local:8080"
        self.prefix = "/airflow"
        self.calls = []
        self.change = lambda path, response: response

    def factory(self, ctx=None, *, basic_user=None, basic_password=None, bearer_token=None):
        case = self

        class Client:
            base_url = case.base
            base_path = case.prefix

            def get(self, path, *, authed=True):
                case.calls.append((path, authed, basic_user, basic_password))
                name = path.split("?")[0].rsplit("/", 1)[-1]
                denied = basic_user is None or not authed or (case.limited and name in case.restricted_names)
                status = 401 if basic_user is None or not authed else 403 if denied else 200
                if denied:
                    payload = {"status": status, "title": "Denied", "detail": "not allowed"}
                else:
                    values = {
                        "dags": [{"dag_id": x} for x in ("a", "b", "c")],
                        "variables": [{"key": "region"}, {"key": "pool"}],
                        "connections": [{"connection_id": "warehouse"}, {"connection_id": "archive"}],
                    }[name]
                    count = (
                        7
                        if name == "dags"
                        and (
                            basic_password == "second"
                            or case.base != "http://qa.local:8080"
                            or case.prefix != "/airflow"
                        )
                        else len(values)
                    )
                    payload = {name: values[:1] if "?" in path else values, "total_entries": count}
                url = self.base_url + self.base_path + path
                response = AirflowResponse(
                    status,
                    {"Content-Type": "application/json"},
                    json.dumps(payload).encode(),
                    request_url=url,
                    final_url=url,
                )
                return case.change(path, response)

        return Client()

    def ctx(self, *, password="correct"):
        return SimpleNamespace(
            args=SimpleNamespace(),
            host="qa.local",
            port=8080,
            lifecycle_state=None,
            credential=AuditCredentialRun(username="reader", password=password, source="provided"),
        )

    def proof(self):
        return actions.verify_credential(self.factory, "v1", "reader", "correct")

    def authenticate(self, monkeypatch):
        monkeypatch.setattr(actions, "_client_for", self.factory)
        return actions.auth_record(
            self.ctx(), {"is_airflow": True, "api_generation": "v1", "auth_required": True, "status": "auth_required"}
        )


def test_valid_auth_retains_count_without_a_second_dag_query_or_response_body(monkeypatch):
    case = Case()
    result = case.authenticate(monkeypatch)
    assert result["provided_credentials_ok"] is True
    assert result["authenticated_dags_count"] == 3
    assert result["authenticated_keys_count"] == result["authenticated_connections_count"] == 2
    assert [call[0] for call in case.calls] == [
        "/api/v1/dags",
        "/api/v1/variables?limit=1&offset=0",
        "/api/v1/connections?limit=1&offset=0",
    ]
    assert "resource_evidence" not in json.dumps(result) and "AuthResourceEvidence" not in json.dumps(result)


def test_limited_auth_reuses_both_proof_resources_but_keeps_anonymous_control(monkeypatch):
    case = Case(limited=True)
    result = case.authenticate(monkeypatch)
    assert result["provided_credentials_ok"] is True and result["credential_state"] == "valid_but_restricted"
    assert result["authenticated_dags_access"] == result["authenticated_connections_access"] == "denied"
    assert result["authenticated_keys_count"] == 2
    assert [call[0] for call in case.calls] == [
        "/api/v1/dags",
        "/api/v1/variables?limit=1&offset=0",
        "/api/v1/variables?limit=1&offset=0",
        "/api/v1/connections?limit=1&offset=0",
    ]
    assert case.calls[2][1:3] == (False, None)


def test_connections_can_prove_limited_auth_when_variables_are_denied(monkeypatch):
    case = Case(limited=True)
    case.restricted_names = {"dags", "variables"}
    result = case.authenticate(monkeypatch)
    assert result["provided_credentials_ok"] is True
    assert result["credential_state"] == "valid_but_restricted"
    assert result["authenticated_keys_access"] == "denied"
    assert result["authenticated_connections_count"] == 2
    assert [call[0] for call in case.calls] == [
        "/api/v1/dags",
        "/api/v1/variables?limit=1&offset=0",
        "/api/v1/connections?limit=1&offset=0",
        "/api/v1/connections?limit=1&offset=0",
        "/api/v1/variables?limit=1&offset=0",
    ]
    assert case.calls[3][1:3] == (False, None)


def test_public_variables_do_not_prove_the_supplied_pair():
    case = Case(limited=True)

    def make_variables_public(path, response):
        if path.startswith("/api/v1/variables") and not case.calls[-1][1]:
            return replace(response, http_status=200, body=b'{"variables":[],"total_entries":0}')
        return response

    case.change = make_variables_public
    proof = case.proof()
    assert proof.state == "verification_unavailable" and proof.resource_evidence is None
    assert any(path.startswith("/api/v1/variables") and not authed for path, authed, _, _ in case.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_url", None),
        ("final_url", None),
        ("final_url", "https://elsewhere/api/v1/dags"),
        ("final_url", "http://qa.local:8080/another/api/v1/dags"),
    ],
)
def test_missing_or_changed_response_url_uses_fresh_count(monkeypatch, field, value):
    case = Case()
    case.change = lambda path, response: replace(response, **{field: value}) if path == "/api/v1/dags" else response
    result = case.authenticate(monkeypatch)
    assert result["provided_credentials_ok"] is True and result["authenticated_dags_count"] == 3
    assert any(call[0] == "/api/v1/dags?limit=1&offset=0" for call in case.calls)


@pytest.mark.parametrize("change", ["username", "password", "origin", "prefix", "generation"])
def test_another_credential_endpoint_or_generation_cannot_reuse_evidence(monkeypatch, change):
    case = Case()
    proof = case.proof()
    assert proof.resource_evidence is not None
    case.calls.clear()
    if change == "origin":
        case.base = "http://elsewhere:8080"
    if change == "prefix":
        case.prefix = "/another"
    ctx = case.ctx(password="second" if change == "password" else "correct")
    if change == "username":
        ctx.credential = AuditCredentialRun(username="other", password="second", source="provided")
    monkeypatch.setattr(actions, "_client_for", case.factory)
    result = actions.capabilities_record(
        ctx,
        {"api_generation": "v2" if change == "generation" else "v1", "credential_state": "valid"},
        auth_evidence=proof.resource_evidence,
    )
    assert len(case.calls) == 3
    assert any("dags?limit=1" in call[0] for call in case.calls)
    assert result["authenticated_dags_count"] == (None if change == "generation" else 7)


@pytest.mark.parametrize("mutation", ["truncated", "malformed", "bool_total", "missing_total", "transport"])
def test_incomplete_response_never_becomes_cached_auth_or_count(monkeypatch, mutation):
    case = Case()

    def modify(path, response):
        if path != "/api/v1/dags":
            return response
        if mutation == "truncated":
            return replace(response, truncated=True)
        if mutation == "transport":
            return replace(response, transport_error="broken")
        body = (
            b"not JSON"
            if mutation == "malformed"
            else b'{"dags":[],"total_entries":true}'
            if mutation == "bool_total"
            else b'{"dags":[]}'
        )
        return replace(response, body=body)

    case.change = modify
    proof = case.proof()
    assert proof.resource_evidence is None and proof.state not in {"valid", "valid_but_restricted"}
    result = case.authenticate(monkeypatch)
    assert result["provided_credentials_ok"] is not True and "authenticated_dags_count" not in result


def test_direct_classification_without_evidence_still_reads_each_resource():
    case = Case()
    result = actions.classify_capabilities(case.factory(basic_user="reader", basic_password="correct"), "v1")
    assert result.dags.count == 3 and len(case.calls) == 3
    assert all("?limit=1&offset=0" in call[0] for call in case.calls)
