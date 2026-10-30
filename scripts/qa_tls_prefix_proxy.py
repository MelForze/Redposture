"""Loopback TLS and URL-prefix proxy for isolated real-product QA."""

from __future__ import annotations

import http.server
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


@contextmanager
def proxy(upstream: str, material: dict[str, Path] | None) -> Iterator[str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def handle_request(self) -> None:
            if not self.path.startswith("/qa/"):
                self.send_error(404)
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {
                k: v for k, v in self.headers.items() if k.lower() not in {"host", "connection", "content-length"}
            }
            request = urllib.request.Request(
                upstream + self.path[3:], data=body if body else None, headers=headers, method=self.command
            )
            opener = urllib.request.build_opener(
                NoRedirect(), urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
            )
            try:
                response = opener.open(request, timeout=10)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                raw = response.read()
                self.send_response(response.status)
                for k, v in response.headers.items():
                    if k.lower() not in {"transfer-encoding", "content-length", "connection"}:
                        if k.lower() == "location" and v.startswith("/"):
                            v = "/qa" + v
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

        def log_message(self, *_args: Any) -> None:
            pass

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if material:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(material["server_cert"], material["server_key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield f"{'https' if material else 'http'}://127.0.0.1:{server.server_port}/qa"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
