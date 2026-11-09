"""Read-only RabbitMQ sources keep URI carriers and virtual-host boundaries."""

from types import SimpleNamespace

import pytest

from redposture_core.modules.rabbitmq import actions, discover
from tests.test_docker_discover import Pool


@pytest.fixture
def context(monkeypatch):
    Pool.calls = []
    Pool.routes = {
        "/api/parameters": (
            200,
            [
                {
                    "component": "shovel",
                    "name": "qa",
                    "vhost": "/",
                    "value": {
                        "src-uri": "amqp://qa:inactive!42@source.invalid/",
                        "dest-uri": "amqp://qa:inactive!49@dest.invalid/",
                    },
                }
            ],
        ),
        "/api/definitions": (
            200,
            {"parameters": [], "users": [{"name": "qa", "password_hash": "hash-must-not-be-plaintext"}], "queues": []},
        ),
        "/api/definitions/%2F": (
            200,
            {"parameters": [{"name": "qa", "value": {"uri": "amqp://qa:inactive!42@source.invalid/"}}]},
        ),
    }
    client = SimpleNamespace(pool=Pool(), base_url="http://qa.invalid", username="qa", password="login-only!42")
    monkeypatch.setattr(actions, "_read_client", lambda ctx, prior: client)
    return SimpleNamespace(host="qa.invalid", port=15672, args=SimpleNamespace(timeout=1, discover_time=30, vhost=None))


def run(ctx):
    return discover.discover(ctx, {"status": "valid_credentials", "provided_credentials_ok": True})


def test_full_uri_values_no_hashes_or_login_credential_in_findings(context):
    report = run(context)
    assert report["status"] == "complete"
    assert {(f["type"], str(f["value"])) for f in report["findings"]} == {
        ("connection_string", "amqp://qa:inactive!42@source.invalid/"),
        ("connection_string", "amqp://qa:inactive!49@dest.invalid/"),
    }
    assert Pool.calls == ["/api/parameters", "/api/definitions"]
    assert all(s["read"] and s["complete"] for s in report["sources"])


def test_selected_vhost_never_reads_other_vhosts(context):
    context.args.vhost = "/"
    report = run(context)
    assert Pool.calls == ["/api/definitions/%2F"]
    assert report["status"] == "complete" and len(report["findings"]) == 1
    assert not next(s for s in report["sources"] if s["id"].endswith("runtime_parameters"))["requested"]


def test_limited_access_preserves_readable_findings_and_reports_denial(context):
    Pool.routes["/api/definitions"] = (403, {"password": "error-document-not-a-source"})
    report = run(context)
    assert report["status"] == "partial" and len(report["findings"]) == 2
    row = next(s for s in report["sources"] if s["id"].endswith("definitions"))
    assert row["denied"] == 1 and not row["complete"]


def test_all_denied_is_unavailable_not_complete(context):
    Pool.routes = {"/api/parameters": (401, {}), "/api/definitions": (403, {})}
    report = run(context)
    assert report["status"] == "unavailable" and not report["findings"]


def test_readable_benign_empty_definitions_are_complete(context):
    Pool.routes = {
        "/api/parameters": (200, []),
        "/api/definitions": (200, {"parameters": [], "users": [{"password_hash": "$2b$12$" + "q" * 53}]}),
    }
    report = run(context)
    assert report["status"] == "complete" and not report["findings"]


def test_unverified_access_never_starts_content_reads(context):
    report = discover.discover(context, {"status": "auth_required"})
    assert report["status"] == "partial" and not Pool.calls
