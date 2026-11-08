"""Read-only Kafka HTTP surfaces, separate from form UI and native SASL.

Protocol peers are not real deployments. Product schemas and provenance are
listed in PERFORMANCE.md; no endpoint implements mutations or credentials.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from scripts.performance_http_fixtures import response
from scripts.performance_kafka_ui import exchange_errors

SURFACES = frozenset({"akhq", "redpanda-console", "rest-proxy", "connect", "ksqldb", "schema-registry"})
VENDORS = {
    "akhq": "akhq",
    "redpanda-console": "redpanda_console",
    "rest-proxy": "kafka_rest_proxy",
    "connect": "kafka_connect",
    "ksqldb": "ksqldb",
    "schema-registry": "schema_registry",
}
NAMES = tuple(f"billing.invoice.{i:03}" for i in range(201))


def http_reply(method: str, path: str, body: bytes, *, surface: str, access: str) -> bytes:
    if surface not in SURFACES or access not in {"open", "denied"}:
        raise ValueError("unsupported Kafka HTTP fixture")
    if method != "GET" or body:
        return response(403, {"message": "QA peer permits only bodyless GET"})
    route = urlsplit(path).path
    routes: dict[str, Any] = {}
    media = "application/json"
    if surface == "akhq":
        routes = {"/": "<title>AKHQ</title>", "/api/me": {"logged": False, "roles": [{"actions": ["READ"]}]}}
    elif surface == "redpanda-console":
        routes = {
            "/": "<title>Redpanda Console</title>",
            "/admin/startup": {"isHttpOk": True, "isKafkaOk": True},
            "/api/topics": {"topics": [{"topicName": name, "partitionCount": 3} for name in NAMES]},
        }
    elif surface == "rest-proxy":
        routes = {
            "/topics": list(NAMES),
            "/v3/clusters": {"kind": "KafkaClusterList", "data": [{"cluster_id": "qa-billing-cluster"}]},
        }
        if route == "/topics":
            media = "application/vnd.kafka.v2+json"
    elif surface == "connect":
        routes = {
            "/": {"version": "3.7.0", "commit": "2ae524ed625438c5", "kafka_cluster_id": "qa-billing-cluster"},
            "/connectors": list(NAMES),
        }
    elif surface == "ksqldb":
        routes = {
            "/info": {
                "KsqlServerInfo": {
                    "version": "0.29.0",
                    "kafkaClusterId": "qa-billing-cluster",
                    "ksqlServiceId": "billing_",
                    "serverStatus": "RUNNING",
                }
            }
        }
    elif surface == "schema-registry":
        routes = {"/subjects": [name + "-value" for name in NAMES]}
        media = "application/vnd.schemaregistry.v1+json"
    if access == "denied":
        # Keep independently public identity, deny readable catalogue. This
        # deliberately exposes fingerprints that cannot prove a protected API.
        if route in {"/api/topics", "/topics", "/connectors", "/subjects"}:
            return response(403, {"message": "catalogue forbidden"})
        if surface == "akhq" and route == "/api/me":
            return response(200, {"logged": False, "roles": []})
    if route not in routes:
        return response(404, {"message": "unknown route"})
    value = routes[route]
    return response(200, value, headers={"Content-Type": "text/html" if isinstance(value, str) else media})


def record_errors(record: dict[str, Any], wire: dict[str, Any] | None, *, surface: str, topics: bool) -> list[str]:
    errors = exchange_errors(wire)
    if errors:
        return errors
    assert wire is not None
    if surface not in SURFACES:
        return ["unknown Kafka HTTP surface"]
    calls = wire["calls"]
    if any(c["method"] != "GET" or c["headers"].get("cookie") for c in calls):
        return ["credential or mutation request on read-only Kafka surface"]
    if record.get("ui_vendor") != VENDORS[surface] or record.get("kafka_interface") != "http_surface":
        return ["wrong Kafka HTTP product identity"]
    expected = (
        [name + "-value" for name in NAMES]
        if surface == "schema-registry"
        else list(NAMES)
        if surface in {"redpanda-console", "rest-proxy", "connect"}
        else []
    )
    if record.get("http_inventory") != expected:
        errors.append("Kafka HTTP catalogue differs from full known values")
    if record.get("provided_credentials_ok") or any(
        record.get(key) for key in ["attempted_credentials", "credential_attempts"]
    ):
        errors.append("read-only Kafka surface fabricated credential attempts")
    if topics:
        if surface in {"redpanda-console", "rest-proxy"}:
            if record.get("ui_topics") != [{"name": name} for name in NAMES] or record.get("ui_topics_partial"):
                errors.append("requested Kafka HTTP topics incomplete or different")
        elif not record.get("ui_unsupported_actions"):
            errors.append("unsupported Kafka HTTP topic action lacks explicit reason")
    expected_path = {
        "akhq": "/api/me",
        "redpanda-console": "/api/topics",
        "rest-proxy": "/topics",
        "connect": "/connectors",
        "ksqldb": "/info",
        "schema-registry": "/subjects",
    }[surface]
    replies = [c for c in calls if c["path"] == expected_path and c["status"] == 200]
    if not replies:
        errors.append("missing received catalogue or product proof")
    else:
        try:
            payload = json.loads(replies[-1]["response_body"])
            received = payload.get("topics") if surface == "redpanda-console" and isinstance(payload, dict) else payload
            if surface == "redpanda-console" and isinstance(received, list):
                received = [r.get("topicName") if isinstance(r, dict) else None for r in received]
            if expected and received != expected:
                errors.append("received catalogue differs from known values")
        except (ValueError, UnicodeError):
            errors.append("malformed received product JSON")
    return errors
