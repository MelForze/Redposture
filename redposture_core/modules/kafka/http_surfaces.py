"""Read-only fingerprints for Kafka web consoles and REST gateways."""

from __future__ import annotations

from typing import Any

from ...clients.http_api import HttpResponse
from ...clients.http_session import HttpSessionPool
from ...utils import utc_now_iso

_PRODUCTS = {
    "akhq": "AKHQ",
    "redpanda_console": "Redpanda Console",
    "kafka_rest_proxy": "Kafka REST Proxy",
    "kafka_connect": "Kafka Connect",
    "ksqldb": "ksqlDB",
    "schema_registry": "Schema Registry",
}


def product_name(vendor: str | None) -> str | None:
    return _PRODUCTS.get(vendor or "")


def _header(response: HttpResponse, name: str) -> str:
    return next((str(value) for key, value in response.headers.items() if key.lower() == name), "")


def _json(response: HttpResponse) -> Any:
    if response.error or response.truncated or response.status != 200:
        return None
    try:
        return response.json()
    except (ValueError, UnicodeError):
        return None


def _get(pool: HttpSessionPool, base: str, path: str) -> HttpResponse:
    return pool.request(
        "GET",
        base + path,
        response_size_cap=128 * 1024,
        allow_cross_origin_redirects=False,
        preserve_authorization_on_cross_origin=False,
    )


def detect(pool: HttpSessionPool, base: str, ctx: Any) -> dict[str, Any] | None:
    """Confirm a product using at least two independent product-specific signals."""
    port = int(ctx.port)
    target = getattr(ctx, "target", None)
    explicit = (
        getattr(target, "explicit_port", None) is not None
        or getattr(target, "scheme", None) in {"http", "https"}
        or getattr(getattr(ctx, "args", None), "port", None) is not None
    )
    candidates = (
        tuple(_PRODUCTS)
        if explicit
        else ("akhq", "redpanda_console")
        if port in {8080, 80, 443, 8443}
        else ("kafka_rest_proxy",)
        if port == 8082
        else ("kafka_connect",)
        if port == 8083
        else ("ksqldb",)
        if port == 8088
        else ("schema_registry",)
        if port == 8081
        else tuple(_PRODUCTS)
    )
    home: HttpResponse | None = None
    vendor: str | None = None
    version: str | None = None
    signals: list[str] = []
    inventory: list[str] = []
    anonymous_read: bool | None = None

    if "akhq" in candidates or "redpanda_console" in candidates or "kafka_connect" in candidates:
        home = _get(pool, base, "/")
    if "akhq" in candidates and home is not None:
        page = _get(pool, base, "/ui") if home.status in {301, 302, 307, 308} else home
        if page.status == 200 and "<title>AKHQ</title>" in page.text[:32768]:
            me = _json(_get(pool, base, "/api/me"))
            if isinstance(me, dict) and isinstance(me.get("logged"), bool) and isinstance(me.get("roles"), list):
                vendor, signals = "akhq", ["akhq_title", "akhq_me_schema"]
                anonymous_read = any(
                    isinstance(role, dict) and "READ" in role.get("actions", ()) for role in me["roles"]
                )
    if vendor is None and "redpanda_console" in candidates and home is not None:
        if home.status == 200 and "<title>Redpanda Console</title>" in home.text[:32768]:
            startup = _json(_get(pool, base, "/admin/startup"))
            if isinstance(startup, dict):
                vendor, signals = "redpanda_console", ["redpanda_title", "redpanda_startup"]
                topics = _json(_get(pool, base, "/api/topics"))
                anonymous_read = isinstance(topics, (list, dict))
                if isinstance(topics, list):
                    inventory = [
                        str(item.get("name"))
                        for item in topics[:200]
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    ]
    if vendor is None and "kafka_rest_proxy" in candidates:
        topics_response = _get(pool, base, "/topics")
        clusters = _json(_get(pool, base, "/v3/clusters"))
        topics = _json(topics_response)
        if (
            "application/vnd.kafka." in _header(topics_response, "content-type").lower()
            and isinstance(topics, list)
            and isinstance(clusters, dict)
            and clusters.get("kind") == "KafkaClusterList"
            and isinstance(clusters.get("data"), list)
        ):
            vendor, signals = "kafka_rest_proxy", ["kafka_vendor_content_type", "kafka_cluster_list"]
            anonymous_read, inventory = True, [item for item in topics[:200] if isinstance(item, str)]
    if vendor is None and "kafka_connect" in candidates and home is not None:
        root = _json(home)
        if isinstance(root, dict) and all(
            isinstance(root.get(key), str) for key in ("version", "commit", "kafka_cluster_id")
        ):
            connectors = _json(_get(pool, base, "/connectors"))
            if isinstance(connectors, list):
                vendor, version, signals = "kafka_connect", root["version"], ["connect_root_schema", "connectors_array"]
                anonymous_read = True
                inventory = [item for item in connectors[:200] if isinstance(item, str)]
    if vendor is None and "ksqldb" in candidates:
        info = _json(_get(pool, base, "/info"))
        server = info.get("KsqlServerInfo") if isinstance(info, dict) else None
        if isinstance(server, dict) and all(
            isinstance(server.get(key), str) for key in ("version", "kafkaClusterId", "serverStatus")
        ):
            vendor, version, signals = "ksqldb", server["version"], ["ksql_server_info", "ksql_cluster_id"]
            anonymous_read = None  # Public /info is not proof of data read.
    if vendor is None and "schema_registry" in candidates:
        subjects_response = _get(pool, base, "/subjects")
        subjects = _json(subjects_response)
        if (
            "application/vnd.schemaregistry.v1+json" in _header(subjects_response, "content-type").lower()
            and isinstance(subjects, list)
            and all(isinstance(item, str) for item in subjects[:20])
        ):
            vendor, signals = "schema_registry", ["schema_registry_vendor_content_type", "subjects_array"]
            anonymous_read, inventory = True, subjects[:200]

    if vendor is None:
        return None
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": port,
        "is_kafka": True,
        "is_kafka_ui": True,
        "kafka_interface": "http_surface",
        "ui_vendor": vendor,
        "ui_base": base,
        "version": version,
        "auth_required": False if anonymous_read else None,
        "anonymous_read": anonymous_read,
        "http_inventory": inventory,
        "status": "open_no_auth" if anonymous_read else "unknown_auth",
        "detection_status": "confirmed",
        "detection_signals": signals,
        "credential_verification_status": "unavailable",
        "error": None,
    }


def collect(record: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Expose only inventory proven readable during detection."""
    payload = dict(record)
    vendor = str(record.get("ui_vendor") or "")
    items = record.get("http_inventory")
    if not isinstance(items, list):
        items = []
    if options.get("show_topics") and vendor in {"kafka_rest_proxy", "redpanda_console"}:
        payload["show_topics"] = True
        payload["ui_topics"] = [{"name": item} for item in items if isinstance(item, str)]
    elif options.get("show_topics"):
        payload["ui_unsupported_actions"] = "topic enumeration is not supported by this HTTP surface"
    if options.get("dump"):
        payload["ui_unsupported_actions"] = "message dump is not supported by this HTTP surface"
    return payload
