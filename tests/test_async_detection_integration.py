"""Real HTTP corpus checks prefixes, false positives and legacy fallback."""

from __future__ import annotations

import importlib
import json
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec


class _CorpusHttpServer(ThreadingHTTPServer):
    request_queue_size = 256


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter"])
@pytest.mark.parametrize("large_fingerprint", [False, True])
def test_native_and_sync_detection_match_on_real_http_with_url_prefixes(module, large_fingerprint):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            calls.append(path)
            parts = path.split("/")
            index = int(parts[2])
            endpoint = "/" + "/".join(parts[3:])
            positive = index % 3 == 0
            routes = {
                "/v1/sys/health": (200, {"initialized": True, "sealed": False, "standby": False, "version": "1.21.0"}),
                "/v1/sys/mounts": (403, {}),
                "/v1/agent/self": (200, {"config": {"Version": "1.10.1", "ACL": {"Enabled": False}}, "stats": {}}),
                "/v1/status/leader": (200, "qa:4647"),
                "/v1/jobs": (200, []),
                "/api": (200, {"version": "2.17.0"}),
                "/api/status": (200, {"connections": 0, "kernels": 0, "started": "now", "last_activity": "now"}),
                "/api/kernels": (200, []),
                "/api/terminals": (403, {}),
            }
            status, payload = (
                routes.get(endpoint, (404, {})) if positive else (200, {"service": "ordinary app", "version": "9.9"})
            )
            if large_fingerprint and positive and isinstance(payload, dict):
                payload = {**payload, "padding": "a" * (300 * 1024)}
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = _CorpusHttpServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    try:
        runs = []
        requests = []
        for native in [False, True]:
            args = parse_args(
                [
                    module,
                    "-t",
                    f"http://127.0.0.1:{port}",
                    "--timeout",
                    "1",
                    "--retries",
                    "0",
                    "--workers",
                    "4",
                    "--no-color",
                ]
            )
            args._disable_async_detection = not native
            stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
            specs = tuple(
                ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=port, path=f"/tenant/{i}")
                for i in range(36)
            )
            plan = AuditCommandPlan(target_specs_by_port={port: specs}, ports=(port,), workers=4, output_format="json")
            start = len(calls)
            result = AuditCommandRunner(
                args=args, spec=getattr(stage, f"build_{module}_spec")(args), emit_line=lambda _: None
            ).run_plan(plan)
            assert result.record_count == 36 and result.detected_count == 12
            requests.append(Counter(calls[start:]))
            runs.append(
                Counter(
                    (r["status"], r.get("api_endpoint"), r.get("detection_status"), bool(r.get("is_" + module)))
                    for r in result.records
                )
            )
        assert runs[0] == runs[1]
        if large_fingerprint:
            assert not (requests[0] - requests[1])
            assert sum((requests[1] - requests[0]).values()) == 12
        else:
            assert requests[0] == requests[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_async_collect_uses_one_metrics_get_and_keeps_sync_collection(tmp_path):
    from redposture_core.constants import DISCOVERY_EXPORTERS
    from redposture_core.exporters.collect import collect_exporter_debug_data

    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append(self.path)
            body = b'node_exporter_build_info{version="1"} 1\n' if self.path == "/metrics" else b"qa-profile"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = _CorpusHttpServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        exporters = [{**e, "port": server.server_port} for e in DISCOVERY_EXPORTERS if e["name"] == "node_exporter"]
        stats = {}
        total, success = collect_exporter_debug_data(
            None,
            [],
            timeout=1,
            output_path=str(tmp_path / "out.jsonl"),
            workers=2,
            retries=0,
            collect_exporters=exporters,
            collect_debug_endpoints=("/debug/vars",),
            adaptive_collect=False,
            scan_work_items=iter([("127.0.0.1", server.server_port, "http")] * 40),
            scan_work_items_count=40,
            discovery_exporters=exporters,
            stats_sink=stats,
            emit_line=lambda _: None,
        )
        assert total == success == 40
        assert stats["discovery_checks"] == stats["discovery_found"] == 40
        assert Counter(calls) == Counter({"/metrics": 40, "/debug/vars": 40})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
