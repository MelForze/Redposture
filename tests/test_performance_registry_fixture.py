"""Protected registry identity, catalogue pagination and independent read ACLs."""

from __future__ import annotations

import base64
import json

import pytest

from scripts import performance_http_fixtures as fixtures
from scripts.performance_contracts import registry_inventory_errors


def request(path, pair=None, *, method="GET", limited=False):
    header = {} if pair is None else {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())}
    raw = fixtures.registry_reply(method, path, header, b"", valid_pair=("reader", "correct"), limited=limited)
    head, _, body = raw.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), json.loads(body), head


@pytest.mark.parametrize("pair", [None, ("reader", "wrong"), ("other", "correct")])
def test_protected_v2_rejects_unverified_credentials_with_actual_registry_fingerprint(pair):
    status, payload, head = request("/v2/", pair)
    assert status == 401 and payload["errors"][0]["code"] == "UNAUTHORIZED"
    assert b"Docker-Distribution-API-Version: registry/2.0" in head
    assert b'WWW-Authenticate: Basic realm="profile-registry"' in head


@pytest.mark.parametrize("limited", [False, True])
def test_valid_identity_is_independent_of_repository_acl(limited):
    assert request("/v2/", ("reader", "correct"), limited=limited)[0] == 200
    status, body, _ = request("/v2/billing/worker/tags/list", ("reader", "correct"), limited=limited)
    if limited:
        assert status == 403 and body["errors"][0]["code"] == "DENIED"
    else:
        assert status == 200 and body == {"name": "billing/worker", "tags": ["2026.11", "stable", "rollback"]}


def test_catalogue_cursor_reaches_all_known_repositories():
    status, first, head = request("/v2/_catalog?n=100", ("reader", "correct"))
    assert status == 200 and first["repositories"] == ["billing/worker", "observability/collector"]
    assert b'Link: </v2/_catalog?n=2&last=observability%2Fcollector>; rel="next"' in head
    status, last, head = request("/v2/_catalog?n=2&last=observability%2Fcollector", ("reader", "correct"))
    assert status == 200 and last["repositories"] == ["platform/api"]
    assert b"Link:" not in head


def test_unknown_repository_or_mutating_request_does_not_return_fake_success():
    status, body, _ = request("/v2/not-here/tags/list", ("reader", "correct"))
    assert status == 404 and body["errors"][0]["code"] == "NAME_UNKNOWN"
    assert request("/v2/platform/api/manifests/latest", ("reader", "correct"), method="PUT")[0] == 403
    assert request("/not-a-registry-route", ("reader", "correct"))[0] == 404


@pytest.mark.parametrize("limited", [False, True])
def test_registry_action_observer_checks_full_selected_tags_and_explicit_denial(limited):
    row = {
        "is_registry": True,
        "provided_credentials_ok": True,
        "show_tags": True,
        "repository": "billing/worker",
        "selected_repository_tags": None if limited else ["2026.11", "rollback", "stable"],
        "images_error": "billing/worker: authentication required" if limited else None,
    }
    assert registry_inventory_errors(row, limited=limited) == []
    assert registry_inventory_errors({**row, "provided_credentials_ok": None}, limited=limited)
    assert registry_inventory_errors({**row, "repository": "wrong/repo"}, limited=limited)
    assert registry_inventory_errors({**row, "selected_repository_tags": [], "images_error": None}, limited=limited)
    assert registry_inventory_errors({**row, "selected_repository_tags": ["stable"] * 3}, limited=limited)


def test_full_images_matcher_checks_every_repository_tag_and_rejects_duplicates():
    images = sorted(
        name + ":" + tag
        for name in ("billing/worker", "observability/collector", "platform/api")
        for tag in ("2026.11", "stable", "rollback")
    )
    row = {
        "is_registry": True,
        "provided_credentials_ok": True,
        "show_images": True,
        "image_count": 9,
        "images": images,
        "images_error": None,
    }
    assert registry_inventory_errors(row, limited=False) == []
    assert registry_inventory_errors({**row, "images": [images[0]] * 9}, limited=False)
