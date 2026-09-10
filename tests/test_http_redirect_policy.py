"""The operator-approved redirect contract across the HTTP transports."""

from __future__ import annotations

import datetime
import hashlib
import shutil
import ssl
import subprocess
import threading
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redposture_core.clients import s3_sigv4
from redposture_core.clients.docker_engine import DockerEngineClient
from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, HttpResponse
from redposture_core.clients.http_redirects import follow_redirects
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.minio_api import MinioClient
from redposture_core.exporters import http_client, http_pool
from redposture_core.modules.elastic.http_session import ElasticHttpSession
from redposture_core.modules.kubeapi.http_session import KubeApiHttpSession

_AUTH = {"Authorization": "Bearer operator", "Cookie": "session=operator", "PRIVATE-TOKEN": "operator-token"}
_TRANSPORTS = ["pool", "api", "kube", "elastic", "docker", "exporter_pool", "exporter_direct", "scanner"]


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is required for the loopback TLS fixture")
    root = tmp_path_factory.mktemp("redirect-tls")
    cert, key, config = root / "cert.pem", root / "key.pem", root / "openssl.cnf"
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
        "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:true\n"
    )
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-config",
            str(config),
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    return server_context, str(cert)


@contextmanager
def _serve(reply, tls_context=None):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            size = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(size)
            headers = {k.lower(): v for k, v in self.headers.items()}
            calls.append((self.command, self.path, headers, body))
            status, response_headers, response_body = reply(self.command, self.path, headers, body)
            self.send_response(status)
            for key, value in response_headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield f"{'https' if tls_context else 'http'}://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _request(kind, url, *, method="GET", body=None, headers=None, ca_file=None):
    parsed = urlsplit(url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    if kind == "api":
        return HttpApiClient(HttpClientConfig(timeout=2, ca_file=ca_file)).request(
            method, url, headers=headers, body=body
        )
    if kind == "pool":
        with closing(HttpSessionPool(timeout=2, ca_file=ca_file)) as pool:
            return pool.request(method, url, headers=headers, body=body)
    if kind == "kube":
        with closing(
            KubeApiHttpSession(
                parsed.hostname,
                parsed.port,
                use_https=parsed.scheme == "https",
                timeout=2,
                insecure=False,
                ca_file=ca_file,
            )
        ) as client:
            return client.request(method, url, headers=headers, body=body)
    if kind == "elastic":
        with ElasticHttpSession(parsed.hostname, parsed.port, timeout=2, ca_file=ca_file) as client:
            return client.request(parsed.scheme, method, path, headers=headers, data=body)
    if kind == "docker":
        with DockerEngineClient(
            parsed.hostname, parsed.port, transport=parsed.scheme, timeout=2, ca_file=ca_file
        ) as client:
            docker_response = client.request(
                method, path, headers=headers, json_body={"payload": True} if body else None
            )
            return HttpResponse(docker_response.status, docker_response.body, docker_response.headers)
    context = ssl.create_default_context(cafile=ca_file) if ca_file else None
    if kind == "exporter_pool":
        with closing(http_pool.HTTPConnectionPool(tls_context=context)) as pool:
            status, raw, _, error, truncated = pool.get(url, 2, max_bytes=1024)
            return HttpResponse(status or 0, raw, {}, error=str(error) if error else None, truncated=truncated)
    with http_client.activate_exporter_tls_context(context):
        if kind == "scanner":
            from redposture_core.scanner import http_get_details

            result = http_get_details(url, 2, retries=0)
        else:
            result = http_client.http_get_details(url, 2, retries=0)
    return HttpResponse(result["status"] or 0, result.raw_body, {}, error=result["error"])


@pytest.mark.parametrize("kind", _TRANSPORTS)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("schemes", [(False, False), (False, True), (True, False)])
def test_transports_follow_host_port_and_scheme_changes(kind, status, schemes, tls_material):
    server_context, cert = tls_material
    source_tls, target_tls = schemes
    with _serve(
        lambda *_: (200, {"Content-Type": "text/plain"}, b"destination"), server_context if target_tls else None
    ) as (destination, received):
        # Change the hostname as well as the port; localhost resolves only to loopback.
        destination = destination.replace("127.0.0.1", "localhost")
        with _serve(
            lambda *_: (status, {"Location": destination + "/final?key=a%2Fb"}, b""),
            server_context if source_tls else None,
        ) as (source, sent):
            response = _request(kind, source + "/start", headers=_AUTH, ca_file=cert)
            assert response.error is None and response.status == 200 and response.body == b"destination"
            assert len(sent) == len(received) == 1
            assert received[0][1] == "/final?key=a%2Fb"
            assert received[0][2]["host"] == urlsplit(destination).netloc
            if not kind.startswith("exporter") and kind != "scanner":
                assert all(received[0][2][k.lower()] == v for k, v in _AUTH.items())


@pytest.mark.parametrize("kind", ["pool", "api", "kube", "elastic", "docker"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
def test_redirect_method_and_body(kind, status, method):
    with _serve(lambda *_: (200, {}, b"ok")) as (destination, received):
        with _serve(lambda *_: (status, {"Location": destination + "/result"}, b"")) as (source, sent):
            response = _request(kind, source + "/start", method=method, headers=_AUTH, body=b"payload")
            assert response.error is None and response.status == 200
            changes_to_get = (status == 303 and method != "HEAD") or (status in {301, 302} and method == "POST")
            assert received[0][0] == ("GET" if changes_to_get else method)
            assert received[0][3] == (b"" if changes_to_get else sent[0][3])
            assert all(received[0][2][k.lower()] == v for k, v in _AUTH.items())


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_minio_resigns_redirected_request(status):
    def validate(method, path, headers, body):
        parsed = urlsplit(path)
        timestamp = datetime.datetime.strptime(headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
        signed_names = headers["authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0].split(";")
        extra = {k: headers[k] for k in signed_names if k not in {"host", "x-amz-date", "x-amz-content-sha256"}}
        expected = s3_sigv4.sign_request(
            method=method,
            host=headers["host"],
            path=parsed.path,
            query=parsed.query,
            headers=extra,
            payload_hash=hashlib.sha256(body).hexdigest(),
            access_key="access",
            secret_key="secret",
            timestamp=timestamp,
        )
        valid = headers["authorization"] == expected["Authorization"]
        return (200 if valid else 403), {}, b"ok" if valid else b"bad signature"

    with _serve(validate) as (destination, received):
        with _serve(lambda *_: (status, {"Location": destination + "/other/key%20name?x=a%2Fb"}, b"")) as (
            source,
            sent,
        ):
            with closing(HttpSessionPool(timeout=2)) as pool:
                parsed = urlsplit(source)
                client = MinioClient(
                    pool,
                    scheme="http",
                    host=parsed.hostname,
                    port=parsed.port,
                    access_key="access",
                    secret_key="secret",
                )
                response = client.put_object("bucket", "key", b"canary")
            assert response.transport_error is None and response.http_status == 200
            assert received[0][2]["authorization"] != sent[0][2]["authorization"]
            assert received[0][3] == (b"" if status == 303 else b"canary")


@pytest.mark.parametrize("kind", ["pool", "api", "kube", "elastic", "exporter_pool", "exporter_direct", "scanner"])
@pytest.mark.parametrize("loop", [False, True])
def test_redirects_are_bounded(kind, loop):
    count = 0

    def reply(*_):
        nonlocal count
        count += 1
        return 302, {"Location": "/start" if loop else f"/hop/{count}"}, b""

    with _serve(reply) as (source, sent):
        response = _request(kind, source + "/start")
        assert response.error and ("loop" if loop else "limit") in response.error
        assert len(sent) == (1 if loop else 6)


def test_redirect_does_not_reapply_target_path_prefix():
    from types import SimpleNamespace

    from redposture_core.clients.http_api import http_target_context

    with _serve(lambda *_: (200, {}, b"ok")) as (destination, received):
        with _serve(lambda *_: (302, {"Location": destination + "/final"}, b"")) as (source, _):
            with http_target_context(SimpleNamespace(scheme="http", path="/proxy")):
                response = _request("kube", source + "/api")
            assert response.error is None
            assert received[0][1] == "/final"


def test_download_follows_redirect_with_credentials(tmp_path):
    with _serve(lambda *_: (200, {}, b"artifact")) as (destination, received):
        with _serve(lambda *_: (302, {"Location": destination}, b"")) as (source, _):
            path = tmp_path / "artifact"
            assert HttpApiClient().download_to_file(source, str(path), headers=_AUTH) == (200, 8, None)
            assert path.read_bytes() == b"artifact"
            assert all(received[0][2][k.lower()] == v for k, v in _AUTH.items())


def test_http_redirects_reject_non_http_destinations():
    calls = []

    def send(method, url, headers, body):
        calls.append(url)
        return HttpResponse(302, b"", {"Location": "file:///tmp/secret"})

    response = follow_redirects(send, "GET", "http://target.example/")
    assert response.error and "unsupported HTTP redirect URL" in response.error
    assert calls == ["http://target.example/"]
