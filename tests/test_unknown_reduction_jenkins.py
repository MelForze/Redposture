import json
from types import SimpleNamespace as NS

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jenkins import actions, render
from tests.test_audit_output_contracts_extended import _RecordingConsole


def test_verified_identity_keeps_version_from_its_existing_response(monkeypatch):
    def get(client, base, path, basic=None):
        if path == "/whoAmI/api/json" and basic:
            return HttpResponse(
                200,
                json.dumps(
                    {
                        "_class": "hudson.security.WhoAmI",
                        "name": "qa",
                        "authenticated": True,
                        "anonymous": False,
                        "authorities": ["authenticated"],
                    }
                ).encode(),
                {"X-Jenkins": "2.541.3"},
            )
        if path == "/whoAmI/api/json":
            return HttpResponse(401, b"{}", {})
        return HttpResponse(200, b'{"jobs":[]}', {})

    monkeypatch.setattr(actions, "_client", lambda c: object())
    monkeypatch.setattr(actions, "_get", get)
    result = actions.auth_record(
        NS(credential=NS(username="qa", password="pass"), lifecycle_state=NS()),
        {"api_endpoint": "http://qa", "version": None},
    )
    assert result["provided_credentials_ok"] is True and result["version"] == "2.541.3"


def test_running_jenkins_build_is_not_an_unknown_final_result():
    lines = render._format_inventory_records(
        {
            "host": "qa",
            "port": 8080,
            "builds_requested": True,
            "builds": [{"job": "demo", "number": 1, "result": None, "building": True}],
        },
        "txt",
    )
    assert any("(result:RUNNING)" in line for line in lines)
    console = _RecordingConsole()
    for line in lines:
        render._render_colored_jenkins_line(console, line)
    assert any("result:RUNNING" in text and color == "orange" for text, color in console.paint_calls)


def test_missing_build_state_remains_unknown_and_final_result_is_kept():
    for result, building, expected in [(None, None, "unknown"), ("FAILURE", False, "FAILURE")]:
        lines = render._format_inventory_records(
            {
                "host": "qa",
                "port": 8080,
                "builds_requested": True,
                "builds": [{"job": "demo", "number": 1, "result": result, "building": building}],
            },
            "txt",
        )
        assert any(f"(result:{expected})" in line for line in lines)
