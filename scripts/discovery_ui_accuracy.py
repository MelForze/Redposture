"""Locked UI reader contracts: authored HTTP fixtures, not vendor/production accuracy."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.kafka import ui as kafka_ui
from redposture_core.modules.portainer import actions as portainer_actions

CORPUS = Path(__file__).resolve().parents[1] / "tests/fixtures/discovery_accuracy/ui-holdout-v4.json"
SHA256 = "5d80ab03c46ea810edd4edfbe00f7d3f29a545deab9f65e5d2df6ea12afd3ee6"
BASE = "http://ui.accuracy.invalid"
SUPPORTED = ("kibana", "opensearch_dashboards", "minio_console", "portainer", "provectus", "kafbat")
UNSUPPORTED = ("mongo_express", "redis_insight", "pgadmin", "postgrest", "kubernetes_dashboard")
HTTP_SURFACES = ("akhq", "redpanda_console", "kafka_rest_proxy", "kafka_connect", "ksqldb", "schema_registry")


def load(path: Path = CORPUS) -> dict[str, Any]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("UI holdout changed; preserve old evidence and review a new version")
    return json.loads(raw)


def full(value: Any) -> str:
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else str(value)


class UIHTTP:
    """Only the real UI reader is replaced at the HTTP boundary, not its engine."""

    def __init__(self, case: dict[str, Any]):
        self.case = case
        self.calls: list[tuple[str, str]] = []
        self.timeout = 1.0
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def _backend(self, method: str, path: str, body: bytes) -> Any:
        if self.case["mode"] == "denied":
            return 403, self.case["body"], {}
        index = "qa-ui"
        if path.startswith("/_resolve/index/"):
            return 200, {"indices": [{"name": index, "attributes": ["open"]}]}, {}
        if "_mapping" in path:
            return (
                200,
                {
                    index: {
                        "mappings": {"properties": {"credentials": {"properties": {"password": {"type": "keyword"}}}}}
                    }
                },
                {},
            )
        if "_settings" in path and path.startswith("/" + index):
            return 200, {index: {"settings": {}}}, {}
        if "_count" in path:
            return 200, {"count": 1}, {}
        if method == "DELETE":
            return 200, {"succeeded": True, "num_freed": 1}, {}
        if "_pit" in path or "point_in_time" in path:
            return 200, {"id": "ui-context", "pit_id": "ui-context"}, {}
        if path.split("?")[0].endswith("/_search") or path.startswith("/_search?"):
            query = json.loads(body or b"{}")
            hits = (
                []
                if query.get("search_after")
                else [{"_index": index, "_id": "record-1", "_source": self.case["body"], "sort": [0]}]
            )
            return 200, {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": hits}}, {}
        if path.startswith("/_cluster/settings"):
            return 200, {"persistent": {}, "transient": {}}, {}
        if path.startswith("/_nodes/settings"):
            return 200, {"nodes": {}}, {}
        if path == "/_index_template":
            return 200, {"index_templates": []}, {}
        if path == "/_component_template":
            return 200, {"component_templates": []}, {}
        if path in {"/_template", "/_ingest/pipeline"}:
            return 200, {}, {}
        raise AssertionError(("unhandled backend request", method, path))

    def _route(self, method: str, url: str, **kwargs: Any) -> tuple[int, Any, dict[str, str]]:
        assert url.startswith(BASE + "/"), "UI credentials/content crossed the declared origin"
        parsed = urlsplit(url)
        path = parsed.path
        query = parse_qs(parsed.query)
        self.calls.append((method, parsed.path + ("?" + parsed.query if parsed.query else "")))
        product = self.case["product"]
        if product in {"kibana", "opensearch_dashboards"}:
            assert method == "POST" and path == "/api/console/proxy"
            assert kwargs["headers"]["kbn-xsrf" if product == "kibana" else "osd-xsrf"] == "redposture"
            assert kwargs["headers"]["Cookie"] == "ui-session=known"
            return self._backend(query["method"][0], query["path"][0], kwargs.get("body") or b"")
        assert method == "GET", "reader attempted a write or execution request"
        if product in {"kafka_connect", "schema_registry"}:
            if self.case["mode"] == "denied":
                return 403, self.case["body"], {}
            if product == "kafka_connect":
                if path == "/connectors":
                    return 200, ["qa"], {}
                if path == "/connectors/qa/config":
                    return 200, {"connector.class": "FileStreamSourceConnector", **self.case["body"]}, {}
            else:
                assert query["deleted"] == ["true"]
                if path == "/subjects":
                    return 200, ["qa-value"], {}
                if path == "/subjects/qa-value/versions":
                    return 200, [1], {}
                if path == "/subjects/qa-value/versions/1":
                    return (
                        200,
                        {"subject": "qa-value", "version": 1, "id": 1, "schema": json.dumps(self.case["body"])},
                        {},
                    )
            raise AssertionError(("unhandled Kafka config source", path))
        if product in UNSUPPORTED:
            return 200, "<html><title>Mongo Express</title><body>password=" + self.case["value"] + "</body></html>", {}
        if product == "portainer":
            assert kwargs.get("headers", {}).get("Authorization") == "Bearer ui-token"
            if self.case["mode"] == "denied":
                return 403, self.case["body"], {}
            if path == "/api/endpoints":
                return 200, [{"Id": 1, "Name": "qa-engine"}], {}
            if path.endswith("/containers/json"):
                return 200, [{"Id": "c1", "Names": ["qa"], "Image": "qa-image"}], {}
            if path.endswith("/containers/c1/json"):
                return 200, {"Config": {"Tty": True, "Env": ["TOKEN=[REDACTED]"]}}, {}
            if path.endswith("/containers/c1/logs"):
                assert query.get("follow") == ["0"] and query.get("tail") == ["all"]
                return 200, self.case.get("source_text", 'password="' + self.case["value"] + '"\n').encode(), {}
            if path.endswith("/volumes"):
                return 200, {"Volumes": []}, {}
            if path.endswith("/info"):
                return 200, {"ServerVersion": "27.5.1", "Swarm": {"LocalNodeState": "inactive"}}, {}
            if path.endswith("/system/df"):
                return 200, {"LayersSize": 0, "Images": [], "Containers": [], "Volumes": []}, {}
            if path.endswith(("/configs", "/secrets")):
                return 503, {"message": "not a swarm manager"}, {}
            if path == "/api/stacks" or path.endswith(("/images/json", "/networks")):
                return 200, [], {}
            raise AssertionError(("unhandled Portainer request", path))
        if product == "minio_console":
            assert kwargs.get("headers", {}).get("Cookie") == "ui-session=known"
            if path == "/api/v1/buckets":
                return 200, {"buckets": [{"name": "qa"}]}, {}
            if path.endswith("/objects"):
                return 200, {"objects": [{"name": "deploy/app.env"}], "isTruncated": False}, {}
            if path.endswith("/objects/download"):
                assert query["prefix"] == ["deploy/app.env"]
                raw = self.case.get("source_text", "PASSWORD=" + self.case["value"] + "\n").encode()
                if self.case["mode"] == "denied":
                    return 403, raw, {}
                start = int(kwargs["headers"]["Range"].split("=")[1].split("-")[0])
                if start >= len(raw):
                    return 416, b"", {}
                return 206, raw[start:], {"Content-Range": f"bytes {start}-{len(raw) - 1}/{len(raw)}"}
            raise AssertionError(("unhandled Console request", path))
        if product in {"provectus", "kafbat"}:
            assert kwargs.get("headers", {}).get("Cookie") == "ui-session=known"
            if path == "/api/clusters":
                return 200, [{"name": "qa", "brokerCount": 1}], {}
            if path == "/api/clusters/qa/topics/orders":
                return 200, {"partitions": [{"partition": 0, "offsetMin": 0, "offsetMax": 1}]}, {}
            if "/messages" in path:
                value = json.dumps(
                    self.case["body"]
                    if self.case.get("source_document")
                    else {
                        "password": self.case["value"],
                        "tokenUrl": "https://auth.invalid/token",
                        "maskedPassword": "[REDACTED]",
                    },
                    ensure_ascii=False,
                )
                events = [
                    {"type": "MESSAGE", "message": {"partition": 0, "offset": 0, "value": value}},
                    {"type": "DONE"},
                ]
                raw = (
                    "\n\n".join("data:" + json.dumps(event, ensure_ascii=False) for event in events) + "\n\n"
                ).encode()
                return (403 if self.case["mode"] == "denied" else 200), raw, {"Content-Type": "text/event-stream"}
            raise AssertionError(("unhandled Kafka UI request", path))
        raise AssertionError(product)

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        status, value, headers = self._route(method, url, **kwargs)
        body = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        return HttpResponse(status, body, headers)

    request_once = request

    def request_stream(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        response = self.request(method, url, **kwargs)
        on_response = kwargs.get("on_response")
        if on_response:
            on_response(response.status, response.headers)
        for offset in range(0, len(response.body), 7):
            kwargs["on_chunk"](response.body[offset : offset + 7])
        return HttpResponse(response.status, b"", response.headers)


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    pool = UIHTTP(case)
    start = time.monotonic()
    cpu = time.process_time()
    emitted: list[str] = []
    args = SimpleNamespace(discover=True, discover_time=30, timeout=1, _discover_implicit_dump=True)
    ctx = SimpleNamespace(
        host="ui.accuracy.invalid",
        port=80,
        args=args,
        credential=SimpleNamespace(username="fixture", password="login-not-source!42", token=None),
        lifecycle_state=None,
        live_emit=emitted.extend,
    )
    product = case["product"]
    prior = {
        "status": "valid_credentials",
        "provided_credentials_ok": True,
        "ui_product": product,
        "ui": {
            "endpoint": BASE,
            "session_cookie": "ui-session=known",
            "session_token": "ui-token" if product == "portainer" else "",
        },
    }
    with (
        patch.object(web_panels, "HttpSessionPool", lambda **kw: pool),
        patch("redposture_core.clients.http_session.HttpSessionPool", lambda **kw: pool),
    ):
        if product in HTTP_SURFACES:
            state = SimpleNamespace(ui_base=BASE, ui_http=pool)
            record = kafka_ui.collect_ui(
                ctx,
                {**prior, "kafka_interface": "http_surface", "ui_vendor": product, "http_inventory": [case["body"]]},
                state,
                {"dump": True, "ui_dump_all": True},
            )
            if product in {"kafka_connect", "schema_registry"}:
                report = record["content_discovery"]
                rows, status = report["findings"], report["status"]
            else:
                assert record.get("ui_unsupported_actions")
                assert "content_discovery" not in record
                rows, status = [], "unsupported_by_ui"
        elif product in {"provectus", "kafbat"}:
            ctx.lifecycle_state = SimpleNamespace(
                ui_base=BASE, ui_http=pool, ui_cookie="ui-session=known", ui_vendor=product
            )
            record = kafka_ui.collect_ui(
                ctx, prior, ctx.lifecycle_state, {"dump": True, "ui_dump_all": True, "query_topic": "orders"}
            )
            report = record["content_discovery"]
            rows = report["findings"]
            status = report["status"]
        elif product == "portainer":
            record = portainer_actions.data_record(ctx, prior)
            report = record["content_discovery"]
            rows = report["findings"]
            status = report["status"]
        else:
            record = web_panels.enumerate_panel(ctx, prior)
            report = record["ui"]["inventory"]["discover"]
            rows = report.get("records", [])
            status = report.get("status") or ("partial" if report.get("partial") else "complete")
    normalized = []
    for row in rows:
        places = row.get("locations") or [row]
        for place in places:
            path = full(place.get("path", place.get("object_path", row.get("object_path", ""))))
            locator = {
                key: full(place[key])
                for key in ("source_kind", "object", "index", "id", "bucket", "key")
                if place.get(key) is not None
            }
            if product == "minio_console":
                locator = {key: full(row[key]) for key in ("bucket", "key")}
            normalized.append(
                {
                    "type": row.get("type", row.get("secret_type")),
                    "value": full(row["value"]),
                    "path": path,
                    "place": locator,
                }
            )
    content = record.get("content_discovery") or {}
    panel = ((record.get("ui") or {}).get("inventory") or {}).get("discover") or {}
    sources = record.get("discover_sources") or content.get("sources") or panel.get("sources") or []
    wall, cpu_used = time.monotonic() - start, time.process_time() - cpu
    return {
        "status": status,
        "sources": sources,
        "findings": normalized,
        "requests": len(pool.calls),
        "calls": pool.calls,
        "wall_seconds": wall,
        "cpu_seconds": cpu_used,
        "first_finding_seconds": None,
        "first_finding_measurement": "not instrumented; streaming assertions are separate regressions",
        "early_output_lines": len(emitted),
    }


def compare(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    def key(row: dict[str, Any]) -> str:
        return json.dumps(row, sort_keys=True, ensure_ascii=False)

    expected = Counter(key(row) for row in case["expected"])
    actual = Counter(key(row) for row in result["findings"])
    status_ok = (
        result["status"] == case["status"]
        if case["status"] != "incomplete"
        else result["status"] in {"partial", "unavailable"}
    )
    return {
        "tp": sum((expected & actual).values()),
        "fn": sum((expected - actual).values()),
        "fp": sum((actual - expected).values()),
        "duplicates": sum(max(0, n - 1) for n in actual.values()),
        "status_ok": status_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    for case in load()["cases"]:
        result = run_case(case)
        rows.append({"id": case["id"], "product": case["product"], **result, "accuracy": compare(case, result)})
    passed = all(
        not row["accuracy"]["fn"]
        and not row["accuracy"]["fp"]
        and not row["accuracy"]["duplicates"]
        and row["accuracy"]["status_ok"]
        for row in rows
    )
    report = {
        "status": "PASS" if passed else "FAIL",
        "scope": "locked authored UI HTTP-boundary fixture gate; not vendor/production certification",
        "corpus_sha256": SHA256,
        "routes": len({c["product"] for c in rows}),
        "cases": rows,
        "peak_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(report["status"], len(rows), "cases")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
