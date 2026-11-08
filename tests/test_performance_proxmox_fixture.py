"""Proxmox ticket errors and read ACLs must remain distinguishable."""

from __future__ import annotations

import json
from urllib.parse import urlencode

import pytest

from scripts import performance_http_fixtures as fixtures
from scripts.performance_contracts import (
    credential_digest,
    credential_summary,
    credential_verdict_errors,
    identity_digest,
    proxmox_inventory_errors,
)


def request(path, *, method="GET", body=b"", ticket=False, limited=False):
    raw = fixtures.proxmox_reply(
        method,
        path,
        {b"cookie": b"PVEAuthCookie=profile-ticket"} if ticket else {},
        body,
        valid_pair=("reader@pve", "correct"),
        limited=limited,
    )
    head, _, body = raw.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), json.loads(body), head


@pytest.mark.parametrize("pair", [("reader@pve", "wrong"), ("reader@pam", "correct")])
def test_ticket_rejection_is_a_specific_pve_authentication_failure(pair):
    status, payload, head = request(
        "/api2/json/access/ticket",
        method="POST",
        body=urlencode(dict(zip(("username", "password"), pair, strict=True))).encode(),
    )
    assert status == 401 and payload["data"] is None and payload["message"] == "authentication failure"
    assert b"Server: pve-api-daemon/" in head


@pytest.mark.parametrize("limited", [False, True])
def test_valid_ticket_is_returned_without_confusing_read_acl_with_password(limited):
    status, payload, _ = request(
        "/api2/json/access/ticket", method="POST", body=b"username=reader%40pve&password=correct", limited=limited
    )
    assert status == 200 and payload["data"]["ticket"] == "profile-ticket"
    assert payload["data"]["username"] == "reader@pve" and payload["data"]["CSRFPreventionToken"]
    assert request("/api2/json/access", ticket=True, limited=limited)[0] == 200
    status, body, _ = request("/api2/json/nodes", ticket=True, limited=limited)
    if limited:
        assert status == 403 and "Permission check failed" in body["message"]
    else:
        assert status == 200 and [x["node"] for x in body["data"]] == ["pve-app", "pve-data", "pve-edge"]


def test_no_cookie_or_bad_form_cannot_create_a_successful_identity():
    assert request("/api2/json/access")[0] == 401
    assert request("/api2/json/access/ticket", method="POST", body=b"broken")[0] == 400
    assert request("/api2/json/nodes/pve-app/qemu/100/agent/exec", method="POST", ticket=True)[0] == 403
    assert request("/not-pve", ticket=True)[0] == 404


def row(status="auth_failed", error="pve credential rejected: authentication failure"):
    return {
        "service": "proxmox",
        "auth_method": "password",
        "auth_username": "reader@pve",
        "auth_password": "wrong",
        "status": status,
        "error": error,
        "auth_attempts": [{"username": "reader@pve", "password": "wrong", "source": "provided", "ok": "False"}],
    }


def test_single_proxmox_pair_uses_observed_identity_and_explicit_verdict_without_modifying_record():
    record = row()
    before = dict(record)
    assert credential_summary(record)["attempts_observed"] == 1
    assert credential_summary(record)["invalid"] == 1
    assert credential_digest(record) == identity_digest([("reader@pve", "wrong", None)])
    assert credential_verdict_errors(record, accepted_identities=set()) == []
    assert record == before


@pytest.mark.parametrize(
    "status,error",
    [("fail", "pve login response inconclusive: Unauthorized"), ("auth_failed", "proxy says no"), ("fail", "timeout")],
)
def test_unavailable_or_generic_error_is_never_normalized_into_rejection(status, error):
    assert credential_verdict_errors(row(status, error), accepted_identities=set())


def test_different_or_missing_auth_attempt_cannot_supply_root_identity():
    record = row()
    record["auth_attempts"][0]["username"] = "other"
    assert credential_summary(record)["attempts_observed"] == 0
    record = row()
    record["auth_attempts"].append("broken")
    assert credential_summary(record)["attempts_observed"] == 0


def test_explicit_default_pair_ledger_keeps_each_password_rejection():
    assert (
        credential_verdict_errors(
            {
                "attempted_credentials": [
                    {
                        "auth_method": "password",
                        "username": "root@pam",
                        "password": "wrong",
                        "status": "auth_failed",
                        "error": "pve credential rejected: authentication failure",
                    }
                ]
            },
            accepted_identities=set(),
        )
        == []
    )


@pytest.mark.parametrize("status", ["token_ok", "weak_default_creds"])
def test_accepted_password_requires_consistent_attempt_and_root(status):
    record = row(status, None)
    assert credential_summary(record)["attempts_observed"] == 0
    record["auth_attempts"][0]["ok"] = "True"
    assert credential_summary(record)["attempts_observed"] == 1
    assert credential_verdict_errors(record, accepted_identities={("reader@pve", "wrong", None)}) == []
    assert credential_verdict_errors(record, accepted_identities=set())


@pytest.mark.parametrize("limited", [False, True])
def test_node_and_user_matcher_requires_complete_objects_or_explicit_acl(limited):
    row = {
        "is_proxmox": True,
        "auth_method": "password",
        "status": "token_ok",
        "show_nodes": True,
        "show_users": True,
        "nodes": [] if limited else ["pve-app", "pve-data", "pve-edge"],
        "users": None if limited else ["root@pam", "monitor@pve", "backup@pve"],
        "nodes_error": "Permission check failed (Sys.Audit)" if limited else None,
        "users_error": "unexpected HTTP 403 from /access/users" if limited else None,
    }
    assert proxmox_inventory_errors(row, limited=limited) == []
    assert proxmox_inventory_errors({**row, "nodes": [], "nodes_error": None}, limited=limited)
    assert proxmox_inventory_errors({**row, "users": ["root@pam"] * 3}, limited=limited)
    assert proxmox_inventory_errors({**row, "status": "fail"}, limited=limited)


def test_profile_pair_preserves_pve_realm_and_default_catalogue_account():
    assert fixtures.profile_pair("proxmox", "defcreds", "valid") == ("root@pam", "root")
    assert fixtures.profile_pair("proxmox", "credentials", "valid") == ("profile-reader@pve", "profile-password")
