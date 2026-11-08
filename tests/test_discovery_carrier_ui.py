"""Full carriers cross the actual supported UI HTTP readers, not a DTO shortcut."""

from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

import pytest

from scripts import discovery_ui_accuracy as ui
from scripts.discovery_ui_accuracy import UIHTTP


@pytest.mark.parametrize("product", ui.SUPPORTED)
def test_supported_ui_keeps_complete_carriers_and_credential_objects(monkeypatch, product):
    uri = "postgres://qa:p%40ss@db.invalid/app"
    oauth = {"client_id": "qa-app", "client_secret": "inactive-client-secret-42"}
    basic = "Basic " + base64.b64encode(b"qa:inactive-basic-password-84").decode()
    body = {"uri": uri, "oauth": oauth, "authorization": basic}
    raw = json.dumps(body).encode()

    class CarrierHTTP(UIHTTP):
        def _route(self, method, url, **kwargs):
            response = super()._route(method, url, **kwargs)
            parsed = urlsplit(url)
            if product == "minio_console" and parsed.path.endswith("/objects/download"):
                start = int(kwargs["headers"]["Range"].split("=")[1].split("-")[0])
                if start >= len(raw):
                    return 416, b"", {}
                return 206, raw[start:], {"Content-Range": f"bytes {start}-{len(raw) - 1}/{len(raw)}"}
            if product == "portainer" and parsed.path.endswith("/containers/c1/logs"):
                return 200, raw + b"\n", {}
            if product in {"provectus", "kafbat"} and "/messages" in parsed.path:
                events = [
                    {"type": "MESSAGE", "message": {"partition": 0, "offset": 0, "value": raw.decode()}},
                    {"type": "DONE"},
                ]
                return (
                    200,
                    ("\n\n".join("data:" + json.dumps(event) for event in events) + "\n\n").encode(),
                    {"Content-Type": "text/event-stream"},
                )
            return response

    monkeypatch.setattr(ui, "UIHTTP", CarrierHTTP)
    case = dict(next(c for c in ui.load()["cases"] if c["product"] == product and c["mode"] == "allowed"))
    case["body"] = body
    result = ui.run_case(case)
    assert result["status"] == "complete", result
    rows = result["findings"]
    assert len(rows) == 3, rows
    assert {(r["type"], r["value"]) for r in rows} == {
        ("connection_string", uri),
        ("basic_auth", basic),
        ("oauth_credentials", json.dumps(oauth, separators=(",", ":"), sort_keys=True)),
    }
    assert all(r["path"] for r in rows)
    assert any(s["read"] and s["complete"] for s in result["sources"])
    assert "\x1b" not in json.dumps(result)
