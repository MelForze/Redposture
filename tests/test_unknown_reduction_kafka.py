from __future__ import annotations

import json
from types import SimpleNamespace as NS

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import ui


def test_confirmed_kafka_ui_empty_clusters_proves_anonymous_list_access(monkeypatch):
    def response(value, status=200):
        return HttpResponse(status, json.dumps(value).encode(), {})

    routes = {
        "/api/info": response({"build": {"version": "v0.7.2", "commitId": "abc"}, "name": "provectus"}),
        "/api/config/authentication": response({}, 404),
        "/api/authorization": response({"rbacEnabled": False, "userInfo": None}),
        "/api/clusters": response([]),
        "/login": response({}, 404),
    }
    monkeypatch.setattr(ui.http_surfaces, "detect", lambda *a: None)
    monkeypatch.setattr(ui, "_get", lambda pool, base, path: routes[path])
    state = NS(ui_http=object())
    result = ui.detect_ui(NS(host="qa", port=8080, args=NS(), target=NS(scheme="http", path="")), state)
    assert result["is_kafka_ui"] is True
    assert result["auth_required"] is False and result["status"] == "open_no_auth"
    assert result["cluster_count"] == 0 and state.ui_anonymous_clusters == []


def test_empty_array_alone_is_not_a_product_fingerprint():
    assert ui._clusters([]) is None
