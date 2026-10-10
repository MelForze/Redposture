"""Docker Engine API client helpers used by the Docker audit stage."""

from __future__ import annotations

import base64
import http.client
import json
import ssl
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from ..shell_capture import is_binary
from .http_api import HttpResponse, decode_http_content
from .http_redirects import follow_redirects, http_origin
from .tls_cache import shared_client_ssl_context


class DockerEngineError(RuntimeError):
    """Base Docker Engine client error."""


class DockerEngineHTTPError(DockerEngineError):
    def __init__(
        self,
        status: int,
        reason: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = int(status)
        self.reason = str(reason or "")
        self.body = body
        self.headers = dict(headers or {})
        detail = self.reason or body.decode("utf-8", "replace")[:120]
        super().__init__(f"docker API HTTP {self.status}: {detail}")


class DockerEngineConnectionError(DockerEngineError):
    """Normalized connection/TLS error."""


@dataclass(frozen=True)
class DockerHTTPResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.text())


def normalize_docker_error(exc: BaseException | str | None) -> str:
    text = str(exc or "").strip()
    if not text:
        return "docker API request failed"
    lower = text.lower()
    if "connection refused" in lower or "errno 61" in lower or "errno 111" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "certificate verify failed" in lower or "self-signed" in lower or "self signed" in lower:
        return "tls verification failed"
    if "wrong version number" in lower or "unknown protocol" in lower or "http request" in lower:
        return "tls/plaintext mismatch"
    if "remote end closed connection" in lower or "connection reset" in lower:
        return "connection reset"
    return text


def is_auth_required_error(value: BaseException | str | None) -> bool:
    text = str(value or "").lower()
    return any(
        needle in text
        for needle in (
            "http 401",
            "http 403",
            "unauthorized",
            "forbidden",
            "certificate required",
            "tlsv13 alert certificate required",
            "bad certificate",
            "client certificate",
        )
    )


def build_docker_url(host: str, port: int, *, transport: str, path: str) -> str:
    scheme = "https" if transport == "tls" else "http"
    if not path.startswith("/"):
        path = "/" + path
    normalized_host = str(host).strip()
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    return f"{scheme}://{normalized_host}:{int(port)}{path}"


def _ssl_context(*, insecure: bool, ca_file: str | None, cert_file: str | None, key_file: str | None) -> ssl.SSLContext:
    return shared_client_ssl_context(
        insecure=insecure,
        ca_file=ca_file,
        cert_file=cert_file,
        key_file=key_file,
    )


class DockerEngineClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        transport: str = "plaintext",
        timeout: float = 1.0,
        insecure: bool = False,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
        base_path: str = "",
        http_connection_cls: type[http.client.HTTPConnection] | None = None,
        https_connection_cls: type[http.client.HTTPSConnection] | None = None,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.transport = "tls" if transport in {"tls", "https"} else "plaintext"
        self.timeout = float(timeout)
        self.insecure = bool(insecure)
        self.ca_file = ca_file
        self.cert_file = cert_file
        self.key_file = key_file
        self.base_path = "/" + str(base_path or "").strip("/") if str(base_path or "").strip("/") else ""
        self.http_connection_cls = http_connection_cls or http.client.HTTPConnection
        self.https_connection_cls = https_connection_cls or http.client.HTTPSConnection
        self._connection_origin = ("https" if self.transport == "tls" else "http", self.host, self.port)
        self._active_connection: http.client.HTTPConnection | None = None
        self._connection_lock = threading.Lock()

    def _connection(self) -> http.client.HTTPConnection:
        with self._connection_lock:
            if self._active_connection is not None:
                return self._active_connection
        scheme, host, port = self._connection_origin
        if scheme == "https":
            context = _ssl_context(
                insecure=self.insecure,
                ca_file=self.ca_file,
                cert_file=self.cert_file,
                key_file=self.key_file,
            )
            connection: http.client.HTTPConnection = self.https_connection_cls(
                host, port, timeout=self.timeout, context=context
            )
        else:
            connection = self.http_connection_cls(host, port, timeout=self.timeout)
        with self._connection_lock:
            self._active_connection = connection
        return connection

    def close(self) -> None:
        with self._connection_lock:
            connection = self._active_connection
            self._active_connection = None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass

    def __enter__(self) -> DockerEngineClient:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
        allow_statuses: set[int] | None = None,
        response_size_cap: int = 10 * 1024 * 1024,
    ) -> DockerHTTPResponse:
        body: bytes | None = None
        scheme, current_host, current_port = self._connection_origin
        authority_host = current_host
        if ":" in authority_host and not authority_host.startswith("["):
            authority_host = f"[{authority_host}]"
        req_headers = {
            "Host": f"{authority_host}:{current_port}",
            "User-Agent": "redposture",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        last_reason = ""
        failure: DockerEngineError | None = None

        def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
            nonlocal last_reason, failure
            origin = http_origin(url)
            if origin != self._connection_origin:
                self.close()
                self._connection_origin = origin
            parsed = urlsplit(url)
            path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            try:
                conn = self._connection()
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                try:
                    try:
                        raw = response.read(max(0, int(response_size_cap)) + 1)
                    except TypeError:
                        raw = response.read()
                    if len(raw) > response_size_cap:
                        raise DockerEngineError(f"docker API response exceeds {response_size_cap} bytes")
                    normalized_headers = {str(k).lower(): str(v) for k, v in response.getheaders()}
                    last_reason = str(response.reason)
                    if bool(getattr(response, "will_close", False)):
                        self.close()
                    return HttpResponse(int(response.status), raw, normalized_headers)
                finally:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
            except DockerEngineError as exc:
                self.close()
                failure = exc
                raise
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
                self.close()
                failure = DockerEngineConnectionError(normalize_docker_error(exc))
                raise failure from exc

        endpoint = path if path.startswith("/") else "/" + path
        if self.base_path and endpoint != self.base_path and not endpoint.startswith(self.base_path + "/"):
            endpoint = self.base_path + endpoint
        url = f"{scheme}://{authority_host}:{current_port}{endpoint}"
        result = follow_redirects(send, method, url, headers=req_headers, body=body)
        if failure is not None:
            raise failure
        result = decode_http_content(result, max_bytes=response_size_cap)
        if result.error:
            raise DockerEngineError(result.error)
        if result.redirected and 200 <= result.status < 300 and result.final_url:
            requested_path = urlsplit(path).path or "/"
            final_path = urlsplit(result.final_url).path or "/"
            if requested_path != "/" and final_path.endswith(requested_path):
                self.base_path = final_path[: -len(requested_path)].rstrip("/")
        if result.status not in (allow_statuses or set(range(200, 300))):
            raise DockerEngineHTTPError(result.status, last_reason, result.body, result.headers)
        return DockerHTTPResponse(result.status, last_reason, result.headers, result.body)

    def ping(self) -> bool:
        response = self.request("GET", "/_ping", allow_statuses={200, 204}, response_size_cap=256 * 1024)
        return response.text().strip().upper() in {"OK", ""}

    def version(self) -> dict[str, Any]:
        result = self.request("GET", "/version", response_size_cap=256 * 1024).json()
        return result if isinstance(result, dict) else {}

    def info(self) -> dict[str, Any]:
        result = self.request("GET", "/info", response_size_cap=256 * 1024).json()
        return result if isinstance(result, dict) else {}

    def containers(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/containers/json?all=1").json()
        return result if isinstance(result, list) else []

    def images(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/images/json").json()
        return result if isinstance(result, list) else []

    def networks(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/networks").json()
        return result if isinstance(result, list) else []

    def volumes(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/volumes").json()
        if isinstance(result, dict):
            volumes = result.get("Volumes")
            return volumes if isinstance(volumes, list) else []
        return []

    def system_df(self) -> dict[str, Any]:
        result = self.request("GET", "/system/df?verbose=1").json()
        return result if isinstance(result, dict) else {}

    def create_exec(self, container_id: str, command: str) -> str:
        encoded = quote(container_id, safe="")
        payload = {
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
            "Cmd": ["/bin/sh", "-lc", str(command)],
        }
        result = self.request("POST", f"/containers/{encoded}/exec", json_body=payload).json()
        if not isinstance(result, dict) or not result.get("Id"):
            raise DockerEngineError("exec create response did not contain Id")
        return str(result["Id"])

    def start_exec(self, exec_id: str) -> dict[str, Any]:
        encoded = quote(exec_id, safe="")
        response = self.request("POST", f"/exec/{encoded}/start", json_body={"Detach": False, "Tty": False})
        raw_streams = decode_docker_stream_bytes(response.body)
        streams = {key: value.decode("utf-8", "replace") for key, value in raw_streams.items()}
        binary_fields: dict[str, str] = {}
        for key, value in raw_streams.items():
            if is_binary(value):
                streams[key] = f"[binary {len(value)} B]"
                binary_fields[f"{key}_base64"] = base64.b64encode(value).decode("ascii")
        inspect_result: dict[str, Any] = {}
        try:
            raw_inspect = self.request("GET", f"/exec/{encoded}/json").json()
            inspect_result = raw_inspect if isinstance(raw_inspect, dict) else {}
        except DockerEngineError:
            inspect_result = {}
        return {
            "exec_id": exec_id,
            "stdout": streams.get("stdout", ""),
            "stderr": streams.get("stderr", ""),
            "exit_code": inspect_result.get("ExitCode"),
            "running": inspect_result.get("Running"),
            **binary_fields,
        }

    def exec_command(self, container_id: str, command: str) -> dict[str, Any]:
        exec_id = self.create_exec(container_id, command)
        return self.start_exec(exec_id)


def decode_docker_stream(payload: bytes) -> dict[str, str]:
    """Decode Docker raw multiplexed stream into stdout/stderr text."""

    streams = decode_docker_stream_bytes(payload)
    return {key: value.decode("utf-8", "replace") for key, value in streams.items()}


def decode_docker_stream_bytes(payload: bytes) -> dict[str, bytes]:
    """Decode Docker's framed stream without losing invalid UTF-8 or NUL."""

    if not payload:
        return {"stdout": b"", "stderr": b""}
    stdout = bytearray()
    stderr = bytearray()
    idx = 0
    saw_frame = False
    while idx + 8 <= len(payload):
        stream_type = payload[idx]
        frame_len = int.from_bytes(payload[idx + 4 : idx + 8], "big")
        start = idx + 8
        end = start + frame_len
        if frame_len < 0 or end > len(payload) or stream_type not in {0, 1, 2}:
            break
        saw_frame = True
        chunk = payload[start:end]
        if stream_type == 2:
            stderr.extend(chunk)
        else:
            stdout.extend(chunk)
        idx = end
    if not saw_frame:
        stdout.extend(payload)
    elif idx < len(payload):
        stdout.extend(payload[idx:])
    return {"stdout": bytes(stdout), "stderr": bytes(stderr)}


def find_container_id(containers: list[dict[str, Any]], selector: str) -> str | None:
    target = str(selector or "").strip()
    if not target:
        return None
    for item in containers:
        cid = str(item.get("Id") or "")
        names = [str(name).lstrip("/") for name in item.get("Names") or []]
        if cid == target or (cid and cid.startswith(target)) or target in names:
            return cid
    return None
