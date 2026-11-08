"""Selecting a vendor cannot turn an unavailable endpoint into a clean negative."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.registry import actions


def options(product):
    result = dict.fromkeys(
        [
            "show_images",
            "docker",
            "show_tags",
            "metadata",
            "harbor",
            "gitlab",
            "nexus",
            "assets",
            "inspect",
            "download",
        ],
        False,
    )
    result.update(product=product, repository=None, tag=None, image=None)
    result[product] = True
    return result


@pytest.fixture(autouse=True)
def restore_transport():
    previous = getattr(actions._THREAD_LOCAL_HTTP, "state", None)
    yield
    actions._THREAD_LOCAL_HTTP.state = previous


def ctx():
    return SimpleNamespace(
        host="qa.invalid",
        port=5443,
        args=SimpleNamespace(timeout=1, retries=0),
        lifecycle_state=actions.RegistryLifecycleState(),
        credential=SimpleNamespace(username=None, password=None, token=None),
    )


@pytest.mark.parametrize("product", ["harbor", "nexus", "gitlab"])
@pytest.mark.parametrize(
    "error", ["connection refused", "connection timeout", "TLS handshake failed", "incomplete response body"]
)
def test_vendor_selection_preserves_failed_probe_and_full_error(monkeypatch, product, error):
    calls = []
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: calls.append(a[3]) or (0, b"", {}, error))
    result = actions.detect_registry(ctx(), options(product))
    assert result["is_registry"] is False and not result.get("is_" + product)
    assert result["status"] == "fail" and result["error"] == error
    assert result["stage_failed_at"] == "detect_protocol"
    assert result["stages"][0]["result"] == "fail"
    assert calls == (["/v2/", "/service/rest/v1/status"] if product == "nexus" else ["/v2/"])
    assert result["provided_credentials"] is False


@pytest.mark.parametrize("product", ["harbor", "nexus", "gitlab"])
def test_successful_foreign_response_is_still_a_clean_negative(monkeypatch, product):
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: (200, b'{"service":"ordinary"}', {}, None))
    result = actions.detect_registry(ctx(), options(product))
    assert result["status"] == "not_registry" and result["is_registry"] is False
    assert result["stage_failed_at"] is None
    assert result["error"] == "requested " + product + " fingerprint not confirmed"


def test_nexus_can_be_confirmed_by_independent_status_after_missing_v2(monkeypatch):
    def request(_host, _port, _method, path, _timeout, **_kwargs):
        if path == "/v2/":
            return 0, b"", {}, "connection refused"
        assert path == "/service/rest/v1/status"
        return 401, b"", {"server": "Nexus/3.72.0-04 (OSS)"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    result = actions.detect_registry(ctx(), options("nexus"))
    assert result["is_nexus"] is True and result["is_registry"] is True
    assert result["status"] == "auth_required" and result["auth_required"] is True
    assert result["error"] is None and result["stage_failed_at"] is None
