"""Read-only Connect config and Schema Registry version sources."""

from types import SimpleNamespace

import pytest

from redposture_core.modules.kafka import ui
from tests.test_docker_discover import Pool


def run(vendor, routes):
    Pool.calls = []
    Pool.routes = routes
    ctx = SimpleNamespace(host="qa", port=8083, args=SimpleNamespace(discover=True, discover_time=30, timeout=1))
    state = SimpleNamespace(ui_http=Pool(), ui_base="http://qa")
    return ui.collect_ui(
        ctx, {"status": "open_no_auth", "kafka_interface": "http_surface", "ui_vendor": vendor}, state, {}
    )


def test_connect_configs_are_scanned_once_and_keep_full_uri():
    uri = "postgres://qa:fixture-pass!42@database.invalid/app"
    result = run(
        "kafka_connect",
        {
            "/connectors": (200, ["billing/a", "billing/a"]),
            "/connectors/billing%2Fa/config": (200, {"connector.class": "FileStreamSource", "connection.url": uri}),
        },
    )
    report = result["content_discovery"]
    assert report["status"] == "complete"
    assert [str(f["value"]) for f in report["findings"]] == [uri]
    assert "/connectors/billing%2Fa/config" in report["findings"][0]["object_path"]
    assert Pool.calls.count("/connectors/billing%2Fa/config") == 1


@pytest.mark.parametrize("status", [401, 403])
def test_denied_connect_configuration_never_scans_error_body(status):
    result = run(
        "kafka_connect", {"/connectors": (200, ["x"]), "/connectors/x/config": (status, {"password": "not-readable"})}
    )
    report = result["content_discovery"]
    assert report["status"] == "partial" and not report["findings"]
    assert next(s for s in report["sources"] if s["id"] == "kafka.connect_configs")["denied"] == 1


def test_registry_reads_all_versions_including_deleted_without_mutation():
    result = run(
        "schema_registry",
        {
            "/subjects": (200, ["orders/value", "orders/value"]),
            "/subjects/orders%2Fvalue/versions": (200, [1, 2, 2]),
            "/subjects/orders%2Fvalue/versions/1": (
                200,
                {"subject": "orders/value", "version": 1, "id": 1, "schema": '{"password":"version-one!42"}'},
            ),
            "/subjects/orders%2Fvalue/versions/2": (
                200,
                {"subject": "orders/value", "version": 2, "id": 2, "schema": '{"password":"version-two!42"}'},
            ),
        },
    )
    report = result["content_discovery"]
    assert report["status"] == "complete"
    assert {str(f["value"]) for f in report["findings"]} == {"version-one!42", "version-two!42"}
    assert Pool.calls.count("/subjects/orders%2Fvalue/versions/2") == 1


def test_invalid_catalog_identity_is_partial_not_silent_complete():
    result = run("kafka_connect", {"/connectors": (200, [None, ""])})
    assert result["content_discovery"]["status"] == "partial"


def test_unrelated_config_document_is_not_scanned_as_connector_configuration():
    result = run(
        "kafka_connect",
        {
            "/connectors": (200, ["x"]),
            "/connectors/x/config": (200, {"password": "unrelated-error!42"}),
        },
    )
    report = result["content_discovery"]
    assert report["status"] == "partial" and not report["findings"]


def test_registry_manifest_records_deleted_version_reads():
    result = run(
        "schema_registry",
        {
            "/subjects": (200, ["qa"]),
            "/subjects/qa/versions": (200, [1]),
            "/subjects/qa/versions/1": (200, {"subject": "qa", "version": 1, "id": 1, "schema": '"string"'}),
        },
    )
    report = result["content_discovery"]
    assert report["status"] == "complete" and not report["findings"]
    assert all(source["scope"].endswith("?deleted=true") for source in report["sources"])
