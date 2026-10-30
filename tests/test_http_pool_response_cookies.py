"""Repeated response cookies survive the pooled transport without comma splitting."""

from __future__ import annotations

import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.grafana.actions import _grafana_login_cookie


def test_pool_preserves_session_cookie_before_another_set_cookie() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "grafana_session=opaque-session; Path=/grafana; HttpOnly; Expires=Wed, 30 Oct 2030 12:00:00 GMT",
            )
            self.send_header("set-cookie", "redirect_to=; Path=/grafana; Max-Age=-1")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/grafana/login"
    try:
        with closing(HttpSessionPool(timeout=1)) as pool:
            response = pool.request("GET", url)
        assert response.status == 200 and response.error is None
        session = _grafana_login_cookie(response.headers, url)
        assert session is not None
        assert session["cookie"] == "grafana_session=opaque-session"
        assert session["path"] == "/grafana"
        assert response.headers["Content-Type"] == "application/json"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
