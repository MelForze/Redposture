"""Direct HTTP clients must reject bodies shorter than Content-Length."""

from __future__ import annotations

import pytest

from redposture_core.clients.docker_engine import DockerEngineClient, DockerEngineError
from redposture_core.modules.elastic.http_session import ElasticHttpSession
from redposture_core.modules.kubeapi.http_session import KubeApiHttpSession


class _Response:
    status = 200
    reason = "OK"
    will_close = True

    def __init__(self, *, remaining: int) -> None:
        self.length = remaining

    def read(self, _size: int = -1) -> bytes:
        return b'{"partial":'

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Content-Length", "111"), ("Content-Type", "application/json")]

    def close(self) -> None:
        return None


class _Connection:
    timeout = 1.0

    def __init__(self, response: _Response) -> None:
        self.response = response

    def request(self, _method: str, _path: str, body: bytes | None = None, headers: object = None) -> None:
        return None

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        return None


@pytest.mark.parametrize("remaining", (0, 100))
def test_elastic_direct_client_rejects_incomplete_body(monkeypatch: pytest.MonkeyPatch, remaining: int) -> None:
    client = ElasticHttpSession("example.test", 9200, timeout=1.0)
    connection = _Connection(_Response(remaining=remaining))
    monkeypatch.setattr(client, "_ensure_connection", lambda _scheme: (connection, False))
    monkeypatch.setattr(client, "_close_connection_unchecked", lambda: None)

    response, error, _reused = client._request_once("http", "GET", "/", {}, None)

    if remaining:
        assert response.status == 0
        assert response.error and "unexpected EOF" in response.error
        assert error is not None
    else:
        assert response.status == 200
        assert error is None


@pytest.mark.parametrize("remaining", (0, 100))
def test_docker_direct_client_rejects_incomplete_body(monkeypatch: pytest.MonkeyPatch, remaining: int) -> None:
    client = DockerEngineClient("example.test", 2375)
    connection = _Connection(_Response(remaining=remaining))
    monkeypatch.setattr(client, "_connection", lambda: connection)

    if remaining:
        with pytest.raises(DockerEngineError, match="unexpected EOF"):
            client.request("GET", "/version")
    else:
        assert client.request("GET", "/version").status == 200


@pytest.mark.parametrize("remaining", (0, 100))
def test_kubeapi_direct_client_rejects_incomplete_body(remaining: int) -> None:
    client = KubeApiHttpSession("example.test", 6443, use_https=False, timeout=1.0, insecure=True, ca_file=None)
    client._connection = _Connection(_Response(remaining=remaining))  # type: ignore[assignment]

    response = client._request_once("GET", "/version", {}, None, timeout=1.0, response_size_cap=1024)

    if remaining:
        assert response.status == 0
        assert response.error and "unexpected EOF" in response.error
    else:
        assert response.status == 200
        assert response.error is None
