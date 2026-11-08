"""Independent known-answer detection gate; serial loopback, never remote scans.

Fixture responses emulate protocols. They are not real-product certification.
Run from a source checkout with development dependencies installed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import resource
import socketserver
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from redposture_core import web_panels
from redposture_core.cli_args import parse_args
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.detection_steps import run_async_requests
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec
from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS, PRODUCTS, _product_server
from tests.test_web_panels import _FIXTURES as _LEGACY_UI_FIXTURES
from tests.test_web_panels import _response

PANEL_PRODUCTS = {
    "portainer": "portainer",
    "mongodb": "mongo_express",
    "elastic_kibana": "kibana",
    "elastic_osd": "opensearch_dashboards",
    "redis": "redis_insight",
    "postgres": "pgadmin",
    "minio": "minio_console",
    "postgres_postgrest": "postgrest",
    "kubeapi_dashboard": "kubernetes_dashboard",
}
_FIXTURES = {
    **_LEGACY_UI_FIXTURES,
    "postgres_postgrest": {
        "/": _response(
            200,
            {"swagger": "2.0", "info": {"title": "PostgREST API"}, "paths": {}},
            headers={"Server": "postgrest/12.2.0", "Content-Type": "application/openapi+json"},
        )
    },
    "kubeapi_dashboard": {
        "/": _response(
            200,
            "<html><head><title>Kubernetes Dashboard</title></head><body><kd-root></kd-root></body></html>",
            headers={"Content-Type": "text/html"},
        )
    },
}

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/detection_accuracy/holdout.json"
# Updated only on an explicitly reviewed new corpus version, never by a gate run.
CORPUS_SHA256 = "d7f8efce0aa44f9a15505679ea2371d3110fcec757f87ec85431a3b17cece599"


def load_holdout() -> dict[str, Any]:
    raw = CORPUS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CORPUS_SHA256:
        raise ValueError("holdout changed: review labels and version before replacing the locked SHA")
    data = json.loads(raw)
    ids = [row["id"] for row in data["cases"]]
    if len(ids) != len(set(ids)) or any(row["expected"] is not False for row in data["cases"]):
        raise ValueError("invalid independent holdout labels")
    return data


@contextmanager
def response_peer(
    routes: dict[str, tuple[int, bytes, dict[str, str]]],
    responder: Callable[[str, str, dict[bytes, bytes], bytes], bytes] | None = None,
) -> Iterator[tuple[int, list[bytes]]]:
    """Own all sockets/threads; generic wildcard responses are deliberate."""
    requests: list[bytes] = []
    errors: list[str] = []

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = False
        block_on_close = True

        def handle_error(self, request: Any, client_address: Any) -> None:
            errors.append(repr(sys.exc_info()[1]))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(0.4)
            try:
                data = bytearray()
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    part = self.request.recv(4096)
                    if not part:
                        break
                    data.extend(part)
                    if len(data) >= 4 and data[:4] not in (b"GET ", b"HEAD", b"POST"):
                        break
                requests.append(bytes(data))
                path = bytes(data).split(b" ", 2)[1].decode("ascii", "replace") if b" " in data else "/"
                if responder is not None:
                    head, _, body = bytes(data).partition(b"\r\n\r\n")
                    request_headers = {
                        line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip()
                        for line in head.split(b"\r\n")[1:]
                        if b":" in line
                    }
                    length = int(request_headers.get(b"content-length", b"0"))
                    while len(body) < length:
                        part = self.request.recv(min(65536, length - len(body)))
                        if not part:
                            return
                        body += part
                    method = head.split(b" ", 1)[0].decode("ascii", "replace")
                    try:
                        reply = responder(method, path, request_headers, body)
                    except Exception as exc:
                        raise RuntimeError(f"accuracy peer responder failed: {exc!r}") from exc
                    self.request.sendall(reply)
                    return
                status, body, headers = routes.get(path, routes.get("*", (404, b"{}", {})))
                head = f"HTTP/1.1 {status} Control\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
                head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                self.request.sendall(head.encode() + b"\r\n" + body)
            except (OSError, ValueError):
                return

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield int(server.server_address[1]), requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        if thread.is_alive():
            raise RuntimeError("accuracy peer did not stop")
        if errors:
            raise RuntimeError("accuracy peer handler failed: " + "; ".join(errors))


def detect(module: str, port: int, mode: str, *, prefix: str = "", surface: str | None = None) -> dict[str, Any]:
    extra = ["--protocol", "native"] if module == "clickhouse" else ["--plaintext"] if module == "grpc" else []
    if module == "clickhouse" and surface == "http":
        extra = ["--protocol", "http"]
    if module == "oracle":
        extra += ["--service", "FREEPDB1", "--protocol", "tcp"]
    args = parse_args(
        [
            module,
            "-t",
            f"http://127.0.0.1:{port}{prefix}",
            "--port",
            str(port),
            "--timeout",
            "0.5",
            "--retries",
            "0",
            "--no-color",
            *extra,
        ]
    )
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=port, scheme="http", path=prefix)
    fallback = False
    events: list[str] = []
    started, cpu = time.monotonic(), time.process_time()
    outcome: Any

    async def run_native() -> Any:
        return await runner._run_async_detect_with_state(target.host, port, target, events.append)

    try:
        if mode == "async" and spec.detect_async is not None:
            outcome = asyncio.run(run_native())
        else:
            outcome = None
        if outcome is None:
            fallback = mode == "async"
            outcome = runner._run_detect_with_state(target.host, port, target, events.append)
        record = outcome.record.to_dict()
        return {
            "detected": runner._is_detected(outcome.record),
            "product": record.get("ui_vendor") or record.get("protocol_flavor"),
            "detection_status": record.get("detection_status", record.get("status")),
            "status": record.get("status"),
            "error": record.get("error"),
            "auth_required": record.get("auth_required"),
            "fallback_reasons": [event for event in events if "fallback" in event],
            "version": record.get("version"),
            "fallback": fallback,
            "wall_seconds": time.monotonic() - started,
            "cpu_seconds": time.process_time() - cpu,
        }
    finally:
        runner._close_all_lifecycle_states()


def classify(rows: list[dict[str, Any]], required_ids: set[str] | None = None) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    pairs: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("error_type"):
            counts["errors"] += 1
            continue
        counts[
            "tp"
            if row["expected"] and row["detected"]
            else "fn"
            if row["expected"]
            else "fp"
            if row["detected"]
            else "tn"
        ] += 1
        if row.get("detection_status") in {"probable", "unverified", "transport_failure"}:
            counts["unconfirmed"] += 1
        if row.get("fallback"):
            counts["async_fallbacks"] += 1
        pairs.setdefault(row["id"], []).append(row)
    mismatches = [
        name
        for name, group in pairs.items()
        if len(group) != 2
        or {r["mode"] for r in group} != {"sync", "async"}
        or len({r["detected"] for r in group}) != 1
    ]
    identities = [
        r["id"]
        for r in rows
        if r.get("expected_product") is not None and r.get("detected") and r.get("product") != r["expected_product"]
    ]
    missing = sorted((required_ids or set()) - set(pairs))
    extra = sorted(set(pairs) - required_ids) if required_ids is not None else []
    fail = bool(
        not rows or counts["fp"] or counts["fn"] or counts["errors"] or mismatches or identities or missing or extra
    )
    return {
        "status": "FAIL" if fail else "PASS",
        **{k: counts[k] for k in ("tp", "tn", "fp", "fn", "errors", "unconfirmed", "async_fallbacks")},
        "parity_mismatches": mismatches,
        "missing_cases": missing,
        "identity_mismatches": identities,
        "extra_cases": extra,
    }


def module_cases(module: str) -> list[dict[str, Any]]:
    rows = []
    holdout = load_holdout()
    fixtures: list[tuple[str, str, dict[str, Any], str]] = [
        ("product", module, {}, ""),
        ("foreign-product", "grafana" if module != "grafana" else "postgres", {}, ""),
    ]
    if module in HTTP_PRODUCTS:
        fixtures += [
            ("nginx-prefix", module, {"proxy_headers": True, "prefix": "/edge/app"}, "/edge/app"),
            ("gzip", module, {"compressed": True}, ""),
        ]
    for case_id, product, options, prefix in fixtures:
        for mode in ("sync", "async"):
            row: dict[str, Any] = {
                "id": case_id,
                "module": module,
                "mode": mode,
                "expected": case_id != "foreign-product",
                "provenance": "synthetic-protocol-reference",
            }
            try:
                with _product_server(product, **options) as (port, requests):
                    row.update(detect(module, port, mode, prefix=prefix))
                row["wire_exchanges"] = len(requests)
            except Exception as exc:
                row.update(error_type=type(exc).__name__, error=str(exc))
            rows.append(row)
    for case in holdout["cases"]:
        for mode in ("sync", "async"):
            row = {
                "id": case["id"],
                "module": module,
                "mode": mode,
                "expected": case["expected"],
                "provenance": holdout["split"],
            }
            try:
                with response_peer(
                    {
                        "*": (
                            case["status"],
                            case["body"].encode(),
                            {"Content-Type": case["content_type"], "Server": "nginx"},
                        )
                    }
                ) as (port, requests):
                    row.update(detect(module, port, mode))
                row["wire_exchanges"] = len(requests)
            except Exception as exc:
                row.update(error_type=type(exc).__name__, error=str(exc))
            rows.append(row)
    return rows


async def panel_async(module: str, base: str) -> Any:
    http = AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=262144)
    try:

        async def send(origin: str, path: str, options: Any = None) -> Any:
            return await http.get(origin + path)

        return await run_async_requests(web_panels.fingerprint_requests(module, base), send)
    finally:
        await http.close()


def panel_cases() -> list[dict[str, Any]]:
    rows = []
    expected_modules = {
        "portainer": "portainer",
        "mongodb": "mongodb",
        "elastic_kibana": "elastic",
        "elastic_osd": "elastic",
        "redis": "redis",
        "postgres": "postgres",
        "minio": "minio",
        "postgres_postgrest": "postgres",
        "kubeapi_dashboard": "kubeapi",
    }
    for fixture, routes in _FIXTURES.items():
        raw = {path: (response.status, response.body, response.headers) for path, response in routes.items()}
        for module in web_panels.MODULE_PRODUCTS:
            for mode in ("sync", "async"):
                row: dict[str, Any] = {
                    "id": f"{module}/{fixture}",
                    "module": module,
                    "surface": fixture,
                    "mode": mode,
                    "expected": expected_modules[fixture] == module,
                    "expected_product": PANEL_PRODUCTS[fixture] if expected_modules[fixture] == module else None,
                    "provenance": "synthetic-ui-reference",
                }
                start, cpu = time.monotonic(), time.process_time()
                try:
                    with response_peer(raw) as (port, requests):
                        base = f"http://127.0.0.1:{port}"
                        if mode == "sync":
                            pool = HttpSessionPool(timeout=0.5, insecure=True)
                            try:
                                result = web_panels._fingerprints(module, pool, base)
                            finally:
                                pool.close()
                        else:
                            result = asyncio.run(panel_async(module, base))
                    row.update(
                        detected=result is not None,
                        product=result[0] if result else None,
                        wire_exchanges=len(requests),
                        wall_seconds=time.monotonic() - start,
                        cpu_seconds=time.process_time() - cpu,
                    )
                except Exception as exc:
                    row.update(error_type=type(exc).__name__, error=str(exc))
                rows.append(row)
    return rows


SPECIAL_SURFACES = {
    "provectus-ui": ("kafka", "provectus"),
    "kafbat-ui": ("kafka", "kafbat"),
    "akhq": ("kafka", "akhq"),
    "redpanda-console": ("kafka", "redpanda_console"),
    "rest-proxy": ("kafka", "kafka_rest_proxy"),
    "connect": ("kafka", "kafka_connect"),
    "ksqldb": ("kafka", "ksqldb"),
    "schema-registry": ("kafka", "schema_registry"),
    "clickhouse-http": ("clickhouse", None),
    "grpc-web": ("grpc", "grpc-web"),
}


def special_cases() -> list[dict[str, Any]]:
    from scripts.performance_kafka_http import http_reply
    from scripts.performance_kafka_ui import kafka_ui_reply
    from tests.test_network_fingerprint_matrix import _http_response

    rows = []
    for surface, (module, product) in SPECIAL_SURFACES.items():

        def response(
            method: str, path: str, headers: dict[bytes, bytes], body: bytes, selected: str = surface
        ) -> bytes:
            if selected in {"provectus-ui", "kafbat-ui"}:
                return kafka_ui_reply(
                    method, path, headers, body, surface=selected, origin="http://qa", valid_pair=None, limited=False
                )
            if selected == "grpc-web":
                return _http_response("grpc_web", path)
            if selected == "clickhouse-http":
                payload = b"Code: 516. DB::Exception: default: Authentication failed: password is incorrect. (AUTHENTICATION_FAILED) (version 24.8.14.39)\n"
                return (
                    f"HTTP/1.1 401 Unauthorized\r\nX-ClickHouse-Exception-Code: 516\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                    + payload
                )
            return http_reply(method, path, body, surface=selected, access="open")

        for mode in ("sync", "async"):
            row: dict[str, Any] = {
                "id": surface,
                "module": module,
                "mode": mode,
                "expected": True,
                "expected_product": product,
                "provenance": "synthetic-special-reference",
            }
            try:
                with response_peer({}, response) as (port, requests):
                    row.update(detect(module, port, mode, surface="http" if module == "clickhouse" else None))
                row["wire_exchanges"] = len(requests)
            except Exception as exc:
                row.update(error_type=type(exc).__name__, error=str(exc))
            rows.append(row)
    denied_controls = [
        {
            "id": "generic-auth-required",
            "status": 401,
            "body": '{"error":"authentication required"}',
            "content_type": "application/json",
        },
        {
            "id": "generic-access-denied",
            "status": 403,
            "body": '{"error":"access denied"}',
            "content_type": "application/json",
        },
    ]
    for case in load_holdout()["cases"] + denied_controls:
        for mode in ("sync", "async"):
            row = {
                "id": "clickhouse-http/" + case["id"],
                "module": "clickhouse",
                "mode": mode,
                "expected": False,
                "provenance": "holdout-v1",
            }
            try:
                with response_peer(
                    {"*": (case["status"], case["body"].encode(), {"Content-Type": case["content_type"]})}
                ) as (port, requests):
                    row.update(detect("clickhouse", port, mode, surface="http"))
                row["wire_exchanges"] = len(requests)
            except Exception as exc:
                row.update(error_type=type(exc).__name__, error=str(exc))
            rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module", choices=(*AUDIT_MODULE_NAMES, "ui", "surfaces"))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    load_holdout()
    if set(PRODUCTS) != set(AUDIT_MODULE_NAMES):
        raise ValueError("reference wire corpus no longer covers all audit modules")
    options.output.mkdir(parents=True, exist_ok=options.worker)
    if options.worker:
        started = time.monotonic()
        rows = (
            panel_cases()
            if options.module == "ui"
            else special_cases()
            if options.module == "surfaces"
            else module_cases(options.module)
        )
        required = (
            set(SPECIAL_SURFACES)
            | {"clickhouse-http/" + c["id"] for c in load_holdout()["cases"]}
            | {"clickhouse-http/generic-auth-required", "clickhouse-http/generic-access-denied"}
            if options.module == "surfaces"
            else {f"{module}/{fixture}" for module in web_panels.MODULE_PRODUCTS for fixture in _FIXTURES}
            if options.module == "ui"
            else {"product", "foreign-product"}
            | {c["id"] for c in load_holdout()["cases"]}
            | ({"nginx-prefix", "gzip"} if options.module in HTTP_PRODUCTS else set())
        )
        summary = classify(rows, required)
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        artifact = {
            "component": options.module,
            "summary": summary,
            "rows": rows,
            "wall_seconds": time.monotonic() - started,
            "peak_rss_bytes": rss if sys.platform == "darwin" else rss * 1024,
            "corpus_sha256": CORPUS_SHA256,
            "fixture_sources": {
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in (
                    "tests/test_network_fingerprint_matrix.py",
                    "tests/test_web_panels.py",
                    "tests/application_markup.py",
                )
            },
        }
        (options.output / f"{options.module}.json").write_text(json.dumps(artifact, indent=2) + "\n")
        return 0 if summary["status"] == "PASS" else 1
    components = (options.module,) if options.module else (*AUDIT_MODULE_NAMES, "ui", "surfaces")
    results = []
    for component in components:
        command = [
            sys.executable,
            "-m",
            "scripts.detection_accuracy",
            "--worker",
            "--module",
            component,
            "--output",
            str(options.output.resolve()),
        ]
        started = time.monotonic()
        with (options.output / f"{component}.log").open("w") as log:
            try:
                code: int | str = subprocess.run(
                    command, stdout=log, stderr=subprocess.STDOUT, timeout=120, cwd=ROOT
                ).returncode
            except subprocess.TimeoutExpired:
                code = "TIMEOUT_120S"
        result = {"component": component, "exit": code, "wall_seconds": time.monotonic() - started}
        results.append(result)
        print(json.dumps(result), flush=True)
        (options.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return int(any(x["exit"] != 0 for x in results))


if __name__ == "__main__":
    raise SystemExit(main())
