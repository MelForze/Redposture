"""Controlled token identities, separate ACL denials and unknown API routes."""

from __future__ import annotations

import json

import pytest

from scripts.performance_http_fixtures import token_reply


def get(module, path, token=None, *, limited=False):
    header = {"vault": b"x-vault-token", "nomad": b"x-nomad-token", "jupyter": b"authorization"}[module]
    value = ("token " if module == "jupyter" else "") + str(token)
    wire = token_reply(
        "GET",
        path,
        {header: value.encode()} if token else {},
        b"",
        module=module,
        valid_token="profile-token",
        limited=limited,
    )
    head, _, body = wire.partition(b"\r\n\r\n")
    try:
        data = json.loads(body)
    except ValueError:
        data = body.decode()
    return int(head.split(b" ")[1]), data


@pytest.mark.parametrize(
    "module,path", [("vault", "/v1/auth/token/lookup-self"), ("nomad", "/v1/acl/token/self"), ("jupyter", "/api/me")]
)
@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_unknown_or_missing_token_gets_an_explicit_product_rejection(module, path, token):
    status, data = get(module, path, token)
    assert status == 403
    if module == "vault":
        assert data == {"errors": ["permission denied", "invalid token"]}
    elif module == "nomad":
        assert data == "ACL token not found"
    else:
        assert data == {"message": "Forbidden", "reason": None}


@pytest.mark.parametrize(
    "module,path", [("vault", "/v1/auth/token/lookup-self"), ("nomad", "/v1/acl/token/self"), ("jupyter", "/api/me")]
)
def test_limited_token_is_still_a_verified_identity(module, path):
    status, data = get(module, path, "profile-token", limited=True)
    assert status == 200
    assert get(module, "/not-an-api", "profile-token")[0] == 404
    if module == "vault":
        assert data["data"]["id"] == "profile-token"
    elif module == "nomad":
        assert data["SecretID"] == "profile-token" and data["Type"] == "client"
    else:
        assert data["identity"]["username"] == "profile-reader"


@pytest.mark.parametrize(
    "module,path", [("vault", "/v1/sys/mounts"), ("nomad", "/v1/jobs?namespace=default"), ("jupyter", "/api/kernels")]
)
def test_inventory_access_is_separate_from_token_validity(module, path):
    assert get(module, path, "profile-token")[0] == 200
    assert get(module, path, "profile-token", limited=True)[0] == 403


def test_jupyter_detection_is_public_but_status_remains_protected():
    assert get("jupyter", "/api")[0] == 200
    assert get("jupyter", "/api/status")[0] == 403
    assert get("jupyter", "/api/status", "profile-token")[0] == 200
    assert get("jupyter", "/api/status", "profile-token", limited=True)[0] == 403


def test_nomad_public_leader_is_a_json_string_not_a_plaintext_error():
    reply = token_reply("GET", "/v1/status/leader", {}, b"", module="nomad", valid_token=None)
    assert json.loads(reply.partition(b"\r\n\r\n")[2]) == "127.0.0.1:4647"


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter"])
def test_read_only_identity_never_approves_a_write_or_execution_request(module):
    reply = token_reply("POST", "/api/terminals", {}, b"anything", module=module, valid_token="profile-token")
    assert reply.startswith(b"HTTP/1.1 403")
