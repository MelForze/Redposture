"""Observed Keycloak config tokenUrl is an OAuth endpoint, not a token value."""

from __future__ import annotations

import pytest

from scripts.discovery_accuracy import MODULES, READERS, scan


@pytest.mark.parametrize("route", (*MODULES, *READERS))
def test_oauth_endpoint_is_not_a_secret_token(route):
    rows, status = scan(route, {"tokenUrl": "http://127.0.0.1:1/token"})
    assert status == "complete"
    assert not rows, rows


@pytest.mark.parametrize("route", ("common", "disk-json", "stream-json", "elastic"))
def test_token_endpoint_metadata_keeps_embedded_uri_password(route):
    rows, status = scan(route, {"tokenUrl": "https://fixture:inactive-embedded!42@auth.invalid/token"})
    assert status == "complete"
    assert [r["value"] for r in rows] == ["https://fixture:inactive-embedded!42@auth.invalid/token"]


def test_real_opaque_token_field_is_still_sensitive():
    rows, status = scan("common", {"token": "inactive-opaque-token!42"})
    assert status == "complete"
    assert [r["value"] for r in rows] == ["inactive-opaque-token!42"]
