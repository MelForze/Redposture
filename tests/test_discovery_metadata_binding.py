"""Metadata labels retain physical Value paths without becoming entropy hits."""

import pytest

from scripts.discovery_accuracy import scan


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
@pytest.mark.parametrize("label", ["internal_cluster_id", "version", "checksum"])
def test_metadata_name_value_is_not_a_secret(route, label):
    rows, status = scan(route, {"parameters": [{"name": label, "value": "rabbitmq-cluster-id-Ph9KYWzPelBGgt88rAOwyQ"}]})
    assert status == "complete" and rows == []


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
def test_metadata_name_does_not_hide_explicit_credentials(route):
    value = "amqp://qa:inactive!42@broker.invalid/"
    rows, status = scan(route, {"parameters": [{"name": "internal_cluster_id", "value": value}]})
    assert status == "complete"
    assert [(r["type"], r["value"]) for r in rows] == [("connection_string", value)]
