"""Docker Engine API client helpers used by the Docker audit stage."""

from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote


class DockerEngineError(RuntimeError):
    """Base Docker Engine client error."""


class DockerEngineHTTPError(DockerEngineError):
    def __init__(self, status: int, reason: str, body: bytes = b"") -> None:
        self.status = int(status)
        self.reason = str(reason or "")
        self.body = body
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
    return f"{scheme}://{host}:{int(port)}{path}"


def _ssl_context(*, insecure: bool, ca_file: str | None, cert_file: str | None, key_file: str | None) -> ssl.SSLContext:
    if insecure:
        context = ssl._create_unverified_context()
    elif ca_file:
        context = ssl.create_default_context(cafile=ca_file)
    else:
        context = ssl.create_default_context()
    if cert_file or key_file:
        context.load_cert_chain(certfile=cert_file or "", keyfile=key_file)
    return context


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
        self.http_connection_cls = http_connection_cls or http.client.HTTPConnection
        self.https_connection_cls = https_connection_cls or http.client.HTTPSConnection

    def _connection(self) -> http.client.HTTPConnection:
        if self.transport == "tls":
            context = _ssl_context(
                insecure=self.insecure,
                ca_file=self.ca_file,
                cert_file=self.cert_file,
                key_file=self.key_file,
            )
            return self.https_connection_cls(self.host, self.port, timeout=self.timeout, context=context)
        return self.http_connection_cls(self.host, self.port, timeout=self.timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
        allow_statuses: set[int] | None = None,
    ) -> DockerHTTPResponse:
        body: bytes | None = None
        req_headers = {"Host": f"{self.host}:{self.port}", "User-Agent": "redposture", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        conn: http.client.HTTPConnection | None = None
        try:
            conn = self._connection()
            conn.request(method.upper(), path, body=body, headers=req_headers)
            response = conn.getresponse()
            raw = response.read()
            normalized_headers = {str(key).lower(): str(value) for key, value in response.getheaders()}
            result = DockerHTTPResponse(int(response.status), str(response.reason), normalized_headers, raw)
            allowed = allow_statuses or set(range(200, 300))
            if result.status not in allowed:
                raise DockerEngineHTTPError(result.status, result.reason, result.body)
            return result
        except DockerEngineHTTPError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            raise DockerEngineConnectionError(normalize_docker_error(exc)) from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def ping(self) -> bool:
        response = self.request("GET", "/_ping", allow_statuses={200, 204})
        return response.text().strip().upper() in {"OK", ""}

    def version(self) -> dict[str, Any]:
        result = self.request("GET", "/version").json()
        return result if isinstance(result, dict) else {}

    def info(self) -> dict[str, Any]:
        result = self.request("GET", "/info").json()
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
        streams = decode_docker_stream(response.body)
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
        }

    def exec_command(self, container_id: str, command: str) -> dict[str, Any]:
        exec_id = self.create_exec(container_id, command)
        return self.start_exec(exec_id)


def decode_docker_stream(payload: bytes) -> dict[str, str]:
    """Decode Docker raw multiplexed stream into stdout/stderr text."""

    if not payload:
        return {"stdout": "", "stderr": ""}
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
    return {
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
    }


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
