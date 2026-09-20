from __future__ import annotations

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEYCLOAK_URL = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://127.0.0.1:18080").rstrip("/")
REDIRECT_URI = f"{KEYCLOAK_URL}/admin/master/console/"
AUTHORIZE_URL = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/auth?" + urllib.parse.urlencode(
    {
        "client_id": "security-admin-console",
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
    }
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        return

    def _reply(self, status: int, body: bytes = b"", *, location: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.partition("?")[0]
        if path == "/api/v2/version":
            self._reply(404)
            return
        if path == "/api/v1/version":
            self._reply(200, json.dumps({"version": "2.11.1", "git_version": "qa-sso"}).encode())
            return
        if path.startswith("/api/v1/"):
            self._reply(302, location=AUTHORIZE_URL)
            return
        self._reply(404)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
