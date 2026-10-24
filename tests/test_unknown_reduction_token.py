"""Metadata fallback must reduce missing facts without fabricating access."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.nomad import actions as nomad
from redposture_core.modules.vault import actions as vault
from redposture_core.modules.vault import render as vault_render
from tests.test_audit_output_contracts_extended import _RecordingConsole


def reply(value, status=200, **kwargs):
    return HttpResponse(status, json.dumps(value).encode(), {}, **kwargs)


def ctx():
    return NS(host="qa", port=8200, args=NS(), credential=NS(token="valid"))


def test_nomad_documented_prerelease_is_not_reported_as_a_stable_release():
    assert nomad._config_version({"Version": "1.10.1", "VersionPrerelease": "dev"}) == "1.10.1-dev"


@pytest.mark.parametrize("version", ["1.10.1", {"Version": "1.10.1"}])
def test_nomad_documented_and_nested_config_versions_are_equivalent(monkeypatch, version):
    routes = {
        "/v1/agent/self": reply({"config": {"Version": version, "ACL": {"Enabled": True}}, "stats": {"nomad": {}}}),
        "/v1/status/leader": reply("qa:4647"),
        "/ui/": reply({}, 404),
        "/v1/jobs?namespace=default": reply({}, 403),
    }
    monkeypatch.setattr(nomad, "_get", lambda c, b, p, t=None: routes[p])
    result = nomad.detect_record(ctx())
    assert result["is_nomad"] is True
    assert result["version"] == "1.10.1" and result["acl_enabled"] is True


@pytest.mark.parametrize("version", ["1.10.1", {"Version": "1.10.1"}])
def test_nomad_authenticated_metadata_uses_both_version_schemas(monkeypatch, version):
    routes = {
        "/v1/acl/token/self": reply({"SecretID": "valid", "AccessorID": "id", "Type": "client"}),
        "/v1/agent/self": reply({"config": {"Version": version, "ACL": {"Enabled": True}}}),
    }
    monkeypatch.setattr(nomad, "_get", lambda c, b, p, t=None: routes[p])
    result = nomad.auth_record(ctx(), {"api_endpoint": "http://qa", "status": "auth_required"})
    assert result["provided_credentials_ok"] is True
    assert result["version"] == "1.10.1" and result["acl_enabled"] is True


@pytest.mark.parametrize("bad", ["not-a-version", True, {}, [], None])
def test_nomad_bad_metadata_never_becomes_a_version(monkeypatch, bad):
    routes = {
        "/v1/acl/token/self": reply({"SecretID": "valid", "AccessorID": "id", "Type": "client"}),
        "/v1/agent/self": reply({"config": {"Version": bad}}),
    }
    monkeypatch.setattr(nomad, "_get", lambda c, b, p, t=None: routes[p])
    result = nomad.auth_record(ctx(), {"api_endpoint": "http://qa", "status": "auth_required"})
    assert result.get("version") is None


def test_vault_recovers_version_from_valid_seal_status_without_claiming_auth(monkeypatch):
    routes = {
        "/v1/sys/health": reply({"initialized": False, "sealed": True, "standby": False}, 503),
        "/v1/sys/seal-status": reply({"initialized": False, "sealed": True, "type": "shamir", "version": "1.21.0"}),
    }
    monkeypatch.setattr(vault, "_client", lambda c: object())
    monkeypatch.setattr(vault, "_request", lambda client, b, p, **k: routes[p])
    result = vault.detect_record(ctx())
    assert result["is_vault"] is True and result["version"] == "1.21.0"
    assert result["auth_required"] is None and result["initialized"] is False


def test_vault_discover_keeps_known_mount_count_without_verbose_inventory(monkeypatch):
    monkeypatch.setattr(vault, "_client", lambda c: object())
    monkeypatch.setattr(vault, "_inventory_section", lambda *a: ([{"path": "secret/", "type": "kv"}], "allowed"))
    monkeypatch.setattr(vault, "_discover_kv", lambda *a: ([], False, []))
    context = ctx()
    context.args.discover = True
    result = vault.data_record(context, {"host": "qa", "port": 8200, "api_endpoint": "http://qa", "token_valid": True})
    assert result["mounts"] is None
    assert result["mounts_count"] == 1
    lines = vault_render._format_inventory_records(result, "txt")
    assert any("(mounts:1)" in line for line in lines)
    assert not any("mounts:unknown" in line for line in lines)
    console = _RecordingConsole()
    for line in lines:
        vault_render._render_colored_vault_line(console, line)
    assert ("mounts:1", "true_red") in console.paint_calls


@pytest.mark.parametrize(
    "invalid",
    [
        reply({"type": "shamir", "version": "1.21.0"}),
        reply({"initialized": False, "sealed": True, "type": "shamir", "version": "1.21.0"}, truncated=True),
    ],
)
def test_vault_rejects_unproven_seal_metadata(monkeypatch, invalid):
    routes = {
        "/v1/sys/health": reply({"initialized": False, "sealed": True, "standby": False}, 503),
        "/v1/sys/seal-status": invalid,
    }
    monkeypatch.setattr(vault, "_client", lambda c: object())
    monkeypatch.setattr(vault, "_request", lambda client, b, p, **k: routes[p])
    result = vault.detect_record(ctx())
    assert result.get("version") is None and result["is_vault"] is False
