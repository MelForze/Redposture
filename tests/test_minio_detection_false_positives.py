"""Unrelated API denials must never start MinIO credential attempts."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.minio_api import MinioClient, MinioResponse
from redposture_core.modules.minio import actions
from redposture_core.modules.minio.stage import build_minio_plan, build_minio_spec
from redposture_core.stage_runtime import AuditCommandRunner

KUBERNETES_STATUS = json.dumps(
    {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": 'forbidden: User "system:anonymous" cannot get path "/"',
        "reason": "Forbidden",
        "details": {},
        "code": 403,
    }
).encode()


class ReplyPool:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def request(self, *args, **kwargs):
        return SimpleNamespace(
            status=self.status, body=self.body, headers={"Content-Type": "application/json"}, error=None
        )


@pytest.mark.parametrize("code", [403, "403", True, [], {}, None, ""])
def test_numeric_or_malformed_json_code_is_not_an_s3_error(code):
    body = json.dumps({"code": code, "message": "Forbidden"}).encode()
    client = MinioClient(ReplyPool(403, body), scheme="https", host="unrelated.invalid", port=8080)
    response = client.get_service_root(signed=False)
    assert response.error is None or not response.error.code


@pytest.mark.parametrize(
    "body",
    [
        b"<Error><Code>403</Code></Error>",
        b'<Error xmlns="urn:unrelated"><Code>AccessDenied</Code></Error>',
        b'<?xml version="1.0" encoding="unknown-encoding"?><Error><Code>AccessDenied</Code></Error>',
        b'{"kind":"Status","apiVersion":"v1","code":"AccessDenied","message":"foreign API envelope"}',
        b'{"Code":"AccessDenied","Message":{"error":"unrelated"}}',
    ],
)
def test_foreign_or_malformed_error_envelope_does_not_confirm_minio(body):
    client = MinioClient(ReplyPool(403, body), scheme="http", host="unrelated.invalid", port=8080)
    response = client.get_service_root(signed=False)
    assert response.error is None or not response.error.code
    assert actions.detect_minio(client).status == "not_minio"


@pytest.mark.parametrize("signal", ["health", "header", "admin-json", "admin-info"])
def test_distinct_minio_signals_still_confirm_the_api(signal):
    class ProductPool:
        def request(self, method, url, **kwargs):
            status, body, headers = 403, b"<Error><Code>AccessDenied</Code></Error>", {}
            if signal == "header":
                headers["Server"] = "MinIO"
            if "/minio/health/" in url:
                status, body = (200, b"") if signal == "health" else (404, b"")
            elif "/minio/admin/" in url:
                if signal == "admin-json":
                    body = b'{"Code":"AccessDenied","Message":"Access Denied"}'
                elif signal == "admin-info":
                    status, body = 200, b'{"mode":"online","servers":[]}'
                else:
                    status, body = 403, b"blocked by gateway"
            return SimpleNamespace(status=status, body=body, headers=headers, error=None)

    client = MinioClient(ProductPool(), scheme="http", host="minio.invalid", port=9000)
    assert actions.detect_minio(client).status == "confirmed"


@pytest.mark.parametrize(
    "status,body",
    [
        (403, KUBERNETES_STATUS),
        (403, b'{"Code":"AccessDenied","Message":"gateway denies every path"}'),
        (403, b"<Error><Code>AccessDenied</Code><Message>gateway denies every path</Message></Error>"),
        (403, b"<html>Forbidden <Error><Code>AccessDenied</Code></Error></html>"),
        (200, b"<html><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult></html>"),
        (200, b"<html>login page</html>"),
    ],
)
def test_same_gateway_reply_on_all_paths_does_not_confirm_minio(status, body):
    client = MinioClient(ReplyPool(status, body), scheme="http", host="unrelated.invalid", port=8080)
    assert actions.detect_minio(client).status not in {"confirmed", "console"}


def test_generic_admin_403_does_not_establish_admin_api_presence():
    response = MinioResponse(http_status=403, headers={}, body=b"Forbidden")
    assert actions._admin_plane(response) is False


@pytest.mark.parametrize("body", [b"<html>login</html>", KUBERNETES_STATUS])
def test_successful_html_or_json_health_reply_is_not_a_minio_health_probe(body):
    assert actions._health_live(MinioResponse(http_status=200, headers={}, body=body)) is False


@pytest.mark.parametrize("body", [KUBERNETES_STATUS, b'{"Code":"AccessDenied","Message":"same gateway denial"}'])
def test_defcreds_does_not_send_pairs_to_foreign_api_or_catchall_gateway(body):
    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_GET(self) -> None:
            calls.append(self.headers.get("Authorization", ""))
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        args = parse_args(
            ["minio", "-t", f"http://127.0.0.1:{server.server_port}", "--defcreds", "--timeout", "1", "--retries", "0"]
        )
        lines: list[str] = []
        runner = AuditCommandRunner(args=args, spec=build_minio_spec(args), emit_line=lines.append)
        runner.run_plan(build_minio_plan(args))
        assert calls and not any(calls), "Unconfirmed product received signed credential attempts"
        assert not any("[*] MinIO (" in line for line in lines)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
