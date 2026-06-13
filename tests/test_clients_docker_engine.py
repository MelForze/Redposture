from __future__ import annotations

import pytest

from redposture_core.clients.docker_engine import (
    DockerEngineClient,
    DockerEngineConnectionError,
    DockerEngineError,
    DockerEngineHTTPError,
    DockerHTTPResponse,
    build_docker_url,
    decode_docker_stream,
    find_container_id,
    is_auth_required_error,
    normalize_docker_error,
)


class _Response:
    def __init__(self, status: int, body: bytes, reason: str = "OK") -> None:
        self.status = status
        self.reason = reason
        self._body = body

    def read(self) -> bytes:
        return self._body

    def getheaders(self):
        return [("Content-Type", "application/json")]


class _Connection:
    calls: list[tuple[str, str, bytes | None, dict[str, str]]] = []
    response = _Response(200, b'{"Version":"25.0.5","ApiVersion":"1.45"}')

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def request(self, method, path, body=None, headers=None) -> None:
        self.__class__.calls.append((method, path, body, headers or {}))

    def getresponse(self):
        return self.__class__.response

    def close(self) -> None:
        pass


def test_build_docker_url_and_request_with_fake_connection() -> None:
    _Connection.calls = []
    _Connection.response = _Response(200, b'{"Version":"25.0.5","ApiVersion":"1.45"}')
    assert build_docker_url("127.0.0.1", 2375, transport="plaintext", path="/_ping") == "http://127.0.0.1:2375/_ping"
    client = DockerEngineClient("127.0.0.1", 2375, http_connection_cls=_Connection)
    assert client.version()["ApiVersion"] == "1.45"
    assert _Connection.calls[0][0:2] == ("GET", "/version")


def test_request_raises_http_error_for_denied_status() -> None:
    _Connection.response = _Response(403, b'{"message":"forbidden"}', "Forbidden")
    client = DockerEngineClient("127.0.0.1", 2375, http_connection_cls=_Connection)
    with pytest.raises(DockerEngineHTTPError) as exc:
        client.version()
    assert exc.value.status == 403
    assert is_auth_required_error(exc.value) is True


def test_request_normalizes_connection_factory_errors() -> None:
    class BrokenConnection(_Connection):
        def __init__(self, *args, **kwargs) -> None:
            raise OSError("Connection refused")

    client = DockerEngineClient("127.0.0.1", 2375, http_connection_cls=BrokenConnection)
    with pytest.raises(DockerEngineConnectionError) as exc:
        client.ping()
    assert "connection refused" in str(exc.value)


def test_decode_docker_stream_and_plain_payload() -> None:
    stdout = b"hello\n"
    stderr = b"warn\n"
    payload = bytes([1, 0, 0, 0]) + len(stdout).to_bytes(4, "big") + stdout
    payload += bytes([2, 0, 0, 0]) + len(stderr).to_bytes(4, "big") + stderr
    decoded = decode_docker_stream(payload)
    assert decoded == {"stdout": "hello\n", "stderr": "warn\n"}
    assert decode_docker_stream(b"plain") == {"stdout": "plain", "stderr": ""}


def test_find_container_and_error_normalization() -> None:
    containers = [{"Id": "abcdef123456", "Names": ["/web"]}]
    assert find_container_id(containers, "web") == "abcdef123456"
    assert find_container_id(containers, "abc") == "abcdef123456"
    assert find_container_id(containers, "missing") is None
    assert normalize_docker_error(RuntimeError("certificate verify failed")) == "tls verification failed"
    assert (
        normalize_docker_error(RuntimeError("Connection refused"))
        == "connection refused (service is not listening on target port)"
    )


def test_docker_client_inventory_and_exec_helpers_with_response_queue() -> None:
    class QueueConnection(_Connection):
        responses: list[_Response] = []

        def getresponse(self):
            return self.__class__.responses.pop(0)

    stdout = b"ok\n"
    frame = bytes([1, 0, 0, 0]) + len(stdout).to_bytes(4, "big") + stdout
    QueueConnection.responses = [
        _Response(200, b"OK", "OK"),
        _Response(200, b'[{"Id":"c1"}]'),
        _Response(200, b'[{"Id":"i1"}]'),
        _Response(200, b'[{"Id":"n1"}]'),
        _Response(200, b'{"Volumes":[{"Name":"v1"}]}'),
        _Response(200, b'{"Containers":1}'),
        _Response(200, b'{"LayersSize":1}'),
        _Response(200, b'{"Id":"exec1"}'),
        _Response(200, frame),
        _Response(200, b'{"Running":false,"ExitCode":0}'),
    ]
    client = DockerEngineClient("127.0.0.1", 2375, http_connection_cls=QueueConnection)
    assert client.ping() is True
    assert client.containers() == [{"Id": "c1"}]
    assert client.images() == [{"Id": "i1"}]
    assert client.networks() == [{"Id": "n1"}]
    assert client.volumes() == [{"Name": "v1"}]
    assert client.info() == {"Containers": 1}
    assert client.system_df() == {"LayersSize": 1}
    assert client.exec_command("c1", "id") == {
        "exec_id": "exec1",
        "stdout": "ok\n",
        "stderr": "",
        "exit_code": 0,
        "running": False,
    }


def test_docker_client_tls_connection_uses_context_and_client_cert(monkeypatch) -> None:
    contexts: list[dict[str, object]] = []

    class _Context:
        def load_cert_chain(self, certfile: str, keyfile: str | None = None) -> None:
            contexts.append({"certfile": certfile, "keyfile": keyfile})

    monkeypatch.setattr("redposture_core.clients.docker_engine.ssl._create_unverified_context", lambda: _Context())

    class TLSConnection(_Connection):
        instances: list[TLSConnection] = []

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.__class__.instances.append(self)

    TLSConnection.response = _Response(200, b"OK")
    client = DockerEngineClient(
        "docker.local",
        2376,
        transport="tls",
        insecure=True,
        cert_file="/tmp/client.crt",
        key_file="/tmp/client.key",
        https_connection_cls=TLSConnection,
    )

    assert client.ping() is True
    assert contexts == [{"certfile": "/tmp/client.crt", "keyfile": "/tmp/client.key"}]
    assert TLSConnection.instances[0].kwargs["context"] is not None


def test_docker_client_json_shape_fallbacks_and_exec_error_paths() -> None:
    class QueueConnection(_Connection):
        responses: list[_Response] = []

        def getresponse(self):
            return self.__class__.responses.pop(0)

    QueueConnection.responses = [
        _Response(200, b"[]"),
        _Response(200, b"[]"),
        _Response(200, b"{}"),
        _Response(200, b"{}"),
        _Response(200, b"[]"),
        _Response(200, b"[]"),
        _Response(200, b"{}"),
    ]
    client = DockerEngineClient("127.0.0.1", 2375, http_connection_cls=QueueConnection)

    assert client.version() == {}
    assert client.info() == {}
    assert client.containers() == []
    assert client.images() == []
    assert client.networks() == []
    assert client.volumes() == []
    assert client.system_df() == {}

    QueueConnection.responses = [_Response(200, b"{}")]
    with pytest.raises(DockerEngineError, match="did not contain Id"):
        client.create_exec("c1", "id")


def test_docker_start_exec_tolerates_failed_inspect_and_decodes_trailing_bytes(monkeypatch) -> None:
    client = DockerEngineClient("127.0.0.1", 2375)
    frame = bytes([1, 0, 0, 0]) + (2).to_bytes(4, "big") + b"ok" + b"tail"
    calls: list[str] = []

    def fake_request(method: str, path: str, **_kwargs):
        calls.append(path)
        if path.endswith("/start"):
            return DockerHTTPResponse(200, "OK", {}, frame)
        raise DockerEngineHTTPError(500, "inspect failed", b"")

    monkeypatch.setattr(client, "request", fake_request)

    result = client.start_exec("exec1")

    assert result["stdout"] == "oktail"
    assert result["stderr"] == ""
    assert result["exit_code"] is None
    assert calls == ["/exec/exec1/start", "/exec/exec1/json"]


def test_docker_auth_and_error_helpers_cover_remaining_branches() -> None:
    assert DockerHTTPResponse(200, "OK", {}, b"").json() is None
    assert decode_docker_stream(b"") == {"stdout": "", "stderr": ""}
    assert decode_docker_stream(bytes([9, 0, 0, 0]) + (1).to_bytes(4, "big") + b"x")["stdout"]
    assert find_container_id([{"Id": "abc", "Names": []}], "") is None
    assert is_auth_required_error("tlsv13 alert certificate required") is True
    assert normalize_docker_error(None) == "docker API request failed"
    assert normalize_docker_error("operation timed out") == "connection timeout"
    assert normalize_docker_error("wrong version number") == "tls/plaintext mismatch"
    assert normalize_docker_error("remote end closed connection without response") == "connection reset"
