"""Protected GitLab version retrieval after real token identity verification."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from tests.test_cve_e2e_services import _audit_json


@pytest.mark.parametrize(
    ("version", "token", "expected"),
    [("17.3.1", "valid", True), ("17.3.2", "valid", False), ("17.3.1", "invalid", False)],
)
def test_gitlab_verified_token_fetches_private_version_before_cve(version: str, token: str, expected: bool) -> None:
    calls: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            provided = self.headers.get("Private-Token")
            calls.append((self.path, provided))
            payload: Any
            status, payload = 404, {}
            if self.path == "/users/sign_in":
                status, payload = 200, '<title>GitLab</title><form action="/users/sign_in">Sign in</form>'
            elif self.path == "/api/v4/version":
                status, payload = (
                    (200, {"version": version, "revision": "abc123"})
                    if provided == "valid"
                    else (401, {"message": "401 Unauthorized"})
                )
            elif self.path == "/api/v4/user":
                status, payload = (
                    (200, {"id": 1, "username": "observer", "name": "Observer", "state": "active"})
                    if provided == "valid"
                    else (401, {"message": "401 Unauthorized"})
                )
            elif self.path.startswith("/api/v4/projects"):
                status, payload = 200, []
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        record = _audit_json("gitlab", server.server_port, "--token", token)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert record["is_gitlab"] is True
    assert record["token_valid"] is (token == "valid")
    ids = {finding["id"] for finding in record["cve_enumeration"]["findings"]}
    assert ("CVE-2024-8635" in ids) is expected
    if token == "valid":
        assert record["version"] == version
        assert calls.index(("/api/v4/user", token)) < calls.index(("/api/v4/version", token))
    else:
        assert record["version"] is None
        assert record["cve_enumeration"]["status"] == "version_unknown"
        assert ("/api/v4/version", token) not in calls
