from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
from types import SimpleNamespace

import pytest

from redposture_core import stage_kubeapi as kube
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def test_tls_verify_error_detection() -> None:
    assert kube._is_tls_verify_error("tls verification failed") is True
    assert kube._is_tls_verify_error("self signed certificate") is True
    assert kube._is_tls_verify_error("connection timeout") is False


class _ConsoleCapture:
    instances: list[_ConsoleCapture] = []

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.messages: list[tuple[str, str]] = []
        type(self).instances.append(self)

    def error(self, message: str) -> None:
        self.messages.append(("error", message))

    def warn(self, message: str) -> None:
        self.messages.append(("warn", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _kube_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "ports": None,
        "port": 16443,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "https": True,
        "insecure": True,
        "ca_file": None,
        "token": None,
        "username": None,
        "password": None,
        "namespaces": False,
        "pods": False,
        "secrets": False,
        "namespace": None,
        "pod": None,
        "exec_command": None,
        "output": None,
        "output_format": "txt",
        "workers": 1,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_basic_auth_and_header_precedence() -> None:
    basic = kube._basic_auth_value("admin", "admin")
    assert basic.startswith("Basic ")

    token_headers = kube._kube_api_headers("tok", "u", "p")
    assert token_headers == {"Authorization": "Bearer tok"}

    basic_headers = kube._kube_api_headers(None, "u", "p")
    assert basic_headers["Authorization"].startswith("Basic ")


def test_kube_transport_helpers_cover_ws_and_json_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Sock:
        def __init__(self, payload: bytes = b"") -> None:
            self.payload = payload
            self.sent: list[bytes] = []

        def recv(self, size: int) -> bytes:
            if not self.payload:
                return b""
            chunk = self.payload[:size]
            self.payload = self.payload[size:]
            return chunk

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    assert kube._json_loads_bytes(b'{"ok":true}') == {"ok": True}
    with pytest.raises(ConnectionError, match="unexpected EOF"):
        kube._recv_exact(_Sock(), 1)

        masked_payload = bytes([1 ^ 0x01, 2 ^ 0x02, 3 ^ 0x03])
        frame = bytes([0x82, 0x80 | 3]) + b"\x01\x02\x03\x04" + masked_payload
        opcode, payload = kube._ws_recv_frame(_Sock(frame))
        assert opcode == 0x2
        assert payload == b"\x01\x02\x03"

    close_sock = _Sock()
    monkeypatch.setattr(kube.os, "urandom", lambda _n: b"\x01\x02\x03\x04")
    kube._ws_send_close(close_sock)
    assert close_sock.sent and close_sock.sent[0].startswith(b"\x88\x80\x01\x02\x03\x04")

    monkeypatch.setattr(kube, "_http_request", lambda *args, **kwargs: (200, b"not-json", {}, None))
    status, payload, headers, error = kube._api_get_json(
        "127.0.0.1",
        16443,
        "/api",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert (status, payload, headers, error) == (200, None, {}, None)


def test_kube_exec_status_from_error_channel() -> None:
    code, msg, success = kube._kube_exec_status_from_error_channel("")
    assert code is None and msg is None and success is None

    code, msg, success = kube._kube_exec_status_from_error_channel('{"status":"Success"}')
    assert code == 0 and msg is None and success is True

    code, msg, success = kube._kube_exec_status_from_error_channel(
        '{"status":"Failure","message":"boom","details":{"causes":[{"reason":"ExitCode","message":"2"}]}}'
    )
    assert code == 2 and msg == "boom" and success is False


def test_kube_status_message_resolution() -> None:
    assert kube._kube_status_message(403, {}) == "authentication required"
    assert kube._kube_status_message(404, {}) == "endpoint not found"
    assert kube._kube_status_message(500, {"message": "oops"}) == "oops"
    assert kube._kube_status_message(500, {"kind": "Status", "code": 500}) == "kubernetes status code=500"


def test_kube_payload_and_version_helpers() -> None:
    assert kube._looks_like_kube_api_payload({"gitVersion": "v1.31.0"}) is True
    assert kube._looks_like_kube_api_payload({"kind": "NamespaceList"}) is True
    assert kube._looks_like_kube_api_payload({"hello": "world"}) is False

    assert kube._kube_version_text({"gitVersion": "v1.30.2"}) == "v1.30.2"
    assert kube._kube_version_text({"major": "1", "minor": "31"}) == "v1.31"
    assert kube._kube_version_text({"x": 1}) is None


def test_namespace_filters_and_pod_selector() -> None:
    assert kube._normalize_namespace_filters(["default,prod", "default"]) == ["default", "prod"]
    assert kube._parse_pod_selector("ns/pod") == ("ns", "pod")
    assert kube._parse_pod_selector("pod") == (None, "pod")
    assert kube._parse_pod_selector("  ") == (None, None)


def test_resolve_exec_pod_target_variants() -> None:
    ns, pod, err = kube._resolve_exec_pod_target(None, [], None)
    assert ns is None and pod is None and "missing --pod" in str(err)

    ns, pod, err = kube._resolve_exec_pod_target("kube-system/coredns", [], None)
    assert (ns, pod, err) == ("kube-system", "coredns", None)

    ns, pod, err = kube._resolve_exec_pod_target("api", ["default"], None)
    assert (ns, pod, err) == ("default", "api", None)

    ns, pod, err = kube._resolve_exec_pod_target(
        "api",
        [],
        [{"namespace": "a", "name": "api"}, {"namespace": "b", "name": "api"}],
    )
    assert ns is None and pod is None and "multiple pods named 'api'" in str(err)


def test_format_detect_record_and_status_summary() -> None:
    detect = kube._format_detect_record(
        {
            "host": "127.0.0.1",
            "port": 6443,
            "status": "detected",
            "auth_required": False,
            "version": "v1.30.2",
        },
        "txt",
    )
    assert "[*] Kubernetes API" in detect

    summary_anon = kube._status_summary_line(
        {
            "status": "detected",
            "auth_mode": "none",
            "auth_required": False,
            "show_namespaces": True,
            "namespaces": ["default"],
            "show_pods": False,
            "show_secrets": False,
        }
    )
    assert summary_anon == "[+] anonymous access (namespaces:1)"

    summary_token_fail = kube._status_summary_line(
        {
            "status": "auth_failed",
            "auth_mode": "token",
            "auth_valid": False,
            "auth_error": "denied",
            "show_namespaces": False,
            "show_pods": False,
            "show_secrets": False,
        }
    )
    assert summary_token_fail is not None
    assert summary_token_fail.startswith("[-] token auth failed")
    assert "err=denied" in summary_token_fail


def test_audit_kubeapi_targets_json_output_is_machine_readable(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    def fake_audit_kubeapi_host(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        return {
            "timestamp": "2026-03-26T18:01:08Z",
            "host": "127.0.0.1",
            "port": 26443,
            "https": True,
            "insecure_effective": True,
            "tls_auto_insecure": True,
            "is_kubeapi": True,
            "status": "open_no_auth",
            "version": "v1.31.6+k3s1",
            "auth_required": False,
            "auth_mode": "none",
            "auth_valid": None,
            "auth_error": None,
            "show_namespaces": True,
            "show_pods": True,
            "show_secrets": False,
            "namespaces": ["default"],
            "pods": [{"namespace": "default", "name": "hello-demo", "phase": "Running", "containers": 1}],
            "secrets": [],
            "error": None,
        }

    monkeypatch.setattr(kube, "_audit_kubeapi_host", fake_audit_kubeapi_host)
    output_path = tmp_path / "kubeapi.json"

    total, detected, failed = run_module_targets_for_test(
        "kubeapi",
        hosts=["127.0.0.1"],
        port=26443,
        timeout=1.0,
        retries=0,
        workers=1,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=True,
        show_pods=True,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
        output_path=str(output_path),
        output_format="json",
    )

    assert (total, detected, failed) == (1, 1, 0)
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["is_kubeapi"] is True


def test_audit_kubeapi_host_open_no_auth_with_tls_fallback_and_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_api_get_json(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ):  # type: ignore[no-untyped-def]
        _ = (use_https, ca_file, token, username, password)
        if not insecure:
            return 0, None, {}, "tls verification failed"
        if path == "/version":
            return 200, {"gitVersion": "v1.31.6+k3s1"}, {}, None
        return 200, {"versions": ["v1"]}, {}, None

    monkeypatch.setattr(kube, "_api_get_json", fake_api_get_json)
    monkeypatch.setattr(kube, "_list_namespaces", lambda *_args, **_kwargs: (["default"], 200, None))
    monkeypatch.setattr(
        kube,
        "_list_pods",
        lambda *_args, **_kwargs: (
            [{"namespace": "default", "name": "hello-demo", "phase": "Running", "containers": 1}],
            None,
        ),
    )
    monkeypatch.setattr(
        kube,
        "_list_secrets",
        lambda *_args, **_kwargs: (
            [{"namespace": "default", "name": "db-secret", "type": "Opaque", "keys": ["password"]}],
            None,
        ),
    )
    monkeypatch.setattr(kube, "_resolve_exec_pod_target", lambda *_args, **_kwargs: ("default", "hello-demo", None))
    monkeypatch.setattr(
        kube,
        "_kube_exec_ws",
        lambda *_args, **_kwargs: {
            "namespace": "default",
            "pod": "hello-demo",
            "command": "id",
            "ok": True,
            "stdout": "uid=0(root)",
            "stderr": "",
            "error": None,
            "exit_code": 0,
        },
    )

    record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=False,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=True,
        show_pods=True,
        show_secrets=True,
        namespace_filters=["default"],
        exec_pod="hello-demo",
        exec_command="id",
    )

    assert record["status"] == "open_no_auth"
    assert record["tls_auto_insecure"] is True
    assert record["insecure_effective"] is True
    assert record["namespaces"] == ["default"]
    assert record["pods"][0]["name"] == "hello-demo"
    assert record["secrets"][0]["name"] == "db-secret"
    assert record["exec_result"]["ok"] is True


def test_audit_kubeapi_host_uses_token_when_anonymous_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda _host, _port, path, _timeout, **_kwargs: (
            200,
            {"gitVersion": "v1.31.6+k3s1"} if path == "/version" else {"versions": ["v1"]},
            {},
            None,
        ),
    )

    def fake_list_namespaces(*_args, token=None, username=None, password=None, **_kwargs):  # type: ignore[no-untyped-def]
        _ = (username, password)
        if token:
            return ["default", "kube-system"], 200, None
        return None, 403, "authentication required"

    monkeypatch.setattr(kube, "_list_namespaces", fake_list_namespaces)

    record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token="admin-token",
        username=None,
        password=None,
        show_namespaces=True,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
    )

    assert record["status"] == "auth_valid"
    assert record["auth_mode"] == "token"
    assert record["auth_valid"] is True
    assert record["auth_required"] is True
    assert record["namespaces"] == ["default", "kube-system"]


def test_audit_kubeapi_host_handles_non_kubeapi_and_retries_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda *_args, **_kwargs: (200, {"hello": "world"}, {}, None),
    )
    record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
    )
    assert record["status"] == "not_kubeapi"
    assert record["is_kubeapi"] is False

    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    monkeypatch.setattr(kube, "_retry_delay", lambda _attempt: 0.0)
    failed = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        1,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
    )
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_audit_kubeapi_host_basic_auth_failure_and_exec_argument_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda _host, _port, path, _timeout, **_kwargs: (
            200,
            {"gitVersion": "v1.31.6"} if path == "/version" else {"versions": ["v1"]},
            {},
            None,
        ),
    )

    def fake_list_namespaces(*_args, token=None, username=None, password=None, **_kwargs):  # type: ignore[no-untyped-def]
        if token or username or password:
            return None, 403, "forbidden"
        return None, 403, "authentication required"

    monkeypatch.setattr(kube, "_list_namespaces", fake_list_namespaces)
    record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username="alice",
        password="secret",
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
    )
    assert record["status"] == "auth_failed"
    assert record["auth_mode"] == "basic"
    assert record["auth_valid"] is False

    monkeypatch.setattr(
        kube,
        "_list_namespaces",
        lambda *_args, **_kwargs: (["default"], 200, None),
    )
    exec_record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod="api",
        exec_command=None,
    )
    assert exec_record["exec_result"]["error"] == "use --pod together with -X/--exec-command"


def test_kube_list_helpers_and_secret_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    pages: dict[str, tuple[int, object, dict[str, str], str | None]] = {
        "/api/v1/namespaces?limit=500": (
            200,
            {
                "items": [{"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}}],
                "metadata": {"continue": "n2"},
            },
            {},
            None,
        ),
        "/api/v1/namespaces?limit=500&continue=n2": (
            200,
            {"items": [{"metadata": {"name": "kube-system"}}], "metadata": {}},
            {},
            None,
        ),
        "/api/v1/pods?limit=500": (
            200,
            {
                "items": [
                    {
                        "metadata": {"namespace": "default", "name": "api"},
                        "spec": {"containers": [{}, {}]},
                        "status": {"phase": "Running"},
                    }
                ],
                "metadata": {},
            },
            {},
            None,
        ),
        "/api/v1/namespaces/default/secrets?limit=500": (
            200,
            {
                "items": [
                    {
                        "metadata": {"namespace": "default", "name": "db-secret"},
                        "type": "Opaque",
                        "data": {"password": "c2VjcmV0", "empty": "", "bad": "////"},
                    }
                ],
                "metadata": {},
            },
            {},
            None,
        ),
    }

    def fake_api_get_json(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ):  # type: ignore[no-untyped-def]
        _ = (use_https, insecure, ca_file, token, username, password)
        return pages[path]

    monkeypatch.setattr(kube, "_api_get_json", fake_api_get_json)

    assert kube._kube_list_path("/api/v1/namespaces", limit=100, continue_token="next") == (
        "/api/v1/namespaces?limit=100&continue=next"
    )
    assert kube._metadata_name({"metadata": {"name": "api"}}) == "api"
    assert kube._metadata_namespace({"metadata": {"namespace": "default"}}) == "default"
    assert kube._decode_secret_data_value("c2VjcmV0") == "secret"
    assert kube._decode_secret_data_value("") == "<empty>"
    assert kube._decode_secret_data_value("%%%") == "<empty>"
    assert kube._auth_label("tok", None, None) == "token auth"
    assert kube._auth_label(None, "alice", "secret") == "alice:secret"
    assert kube._auth_label(None, None, None) == "anonymous access"

    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/namespaces",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert error is None
    assert status == 200
    assert items is not None and len(items) == 3

    namespaces, ns_status, ns_error = kube._list_namespaces(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert ns_error is None
    assert ns_status == 200
    assert namespaces == ["default", "kube-system", "prod"]

    pods, pods_error = kube._list_pods(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=[],
    )
    assert pods_error is None
    assert pods == [{"namespace": "default", "name": "api", "phase": "Running", "containers": 2}]

    secrets, secrets_error = kube._list_secrets(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=["default"],
    )
    assert secrets_error is None
    assert secrets == [
        {
            "namespace": "default",
            "name": "db-secret",
            "type": "Opaque",
            "data": {"bad": "<binary:3B>", "empty": "<empty>", "password": "secret"},
        }
    ]


def test_format_detail_records_and_target_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    record = {
        "host": "127.0.0.1",
        "port": 16443,
        "status": "auth_valid",
        "show_namespaces": True,
        "show_pods": True,
        "show_secrets": True,
        "namespace_filters": ["default"],
        "namespaces": ["default"],
        "pods": [{"namespace": "default", "name": "api", "phase": "Running", "containers": 2}],
        "secrets": [{"namespace": "default", "name": "db-secret", "type": "Opaque", "data": {"password": "secret"}}],
        "exec_result": {
            "namespace": "default",
            "pod": "api",
            "command": "id",
            "ok": False,
            "stdout": "",
            "stderr": "permission denied",
            "error": "exit 126",
            "exit_code": 126,
        },
    }
    lines = kube._format_detail_records(record, "txt")
    joined = "\n".join(lines)
    assert "[*] Namespaces" in joined
    assert "[*] Pods (namespace:default)" in joined
    assert "[*] Secrets (namespace:default)" in joined
    assert "default/db-secret (type:Opaque) (keys:1)" in joined
    assert "[-] exec failed (exit:126) err=exit 126" in joined
    assert "[*] STDERR" in joined

    def fake_audit_kubeapi_host(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 16443,
            "https": True,
            "insecure_effective": True,
            "tls_auto_insecure": False,
            "is_kubeapi": True,
            "status": "auth_valid",
            "version": "v1.31.6",
            "auth_required": True,
            "auth_mode": "token",
            "auth_valid": True,
            "auth_error": None,
            "namespace_filters": ["default"],
            "show_namespaces": True,
            "show_pods": False,
            "show_secrets": False,
            "exec_pod": None,
            "exec_command": None,
            "exec_result": None,
            "namespaces": ["default"],
            "pods": [],
            "secrets": [],
            "namespaces_error": None,
            "pods_error": None,
            "secrets_error": None,
            "error": None,
            "elapsed_ms": 1,
        }

    monkeypatch.setattr(kube, "_audit_kubeapi_host", fake_audit_kubeapi_host)
    output_path = tmp_path / "kubeapi.txt"
    total, detected, failed = run_module_targets_for_test(
        "kubeapi",
        hosts=["127.0.0.1"],
        port=16443,
        timeout=1.0,
        retries=0,
        workers=1,
        use_https=True,
        insecure=True,
        ca_file=None,
        token="tok",
        username=None,
        password=None,
        show_namespaces=True,
        show_pods=False,
        show_secrets=False,
        namespace_filters=["default"],
        exec_pod=None,
        exec_command=None,
        output_path=str(output_path),
        output_format="txt",
    )
    assert (total, detected, failed) == (1, 1, 0)
    text = output_path.read_text(encoding="utf-8")
    assert "Kubernetes API" in text
    assert "token auth" in text
    assert "Namespaces" in text


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"ports": "bad"}, "failed to parse --port"),
        ({"targets": None, "hosts": None}, "kubeapi requires -t/--targets"),
    ],
)
def test_run_kubeapi_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_message: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kube, "Console", _ConsoleCapture)
    rc = kube.run_kubeapi_stage(_kube_args(**overrides), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(expected_message in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error")


def test_run_kubeapi_stage_warns_on_token_override_and_all_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kube, "Console", _ConsoleCapture)
    monkeypatch.setattr(kube, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        kube,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return 1, 0, 1

    patch_runner_for_legacy_target_fake(monkeypatch, "kubeapi", fake_audit_targets)
    rc = kube.run_kubeapi_stage(
        _kube_args(token="tok", username="alice", password="secret"),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert captured and captured[0]["username"] is None and captured[0]["password"] is None
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--token is set; Basic auth credentials are ignored" in msg for msg in warnings)
    assert any("all kubeapi targets are unreachable" in msg for msg in warnings)


def test_run_kubeapi_stage_debug_flow_passes_logger_and_append_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kube, "Console", _ConsoleCapture)
    monkeypatch.setattr(kube, "collect_scan_ports", lambda *_args, **_kwargs: [16443, 26443])
    monkeypatch.setattr(
        kube,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("KUBEAPI\t127.0.0.1\t16443\t[*] Kubernetes API")
        return 1, 1, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "kubeapi", fake_audit_targets)
    rc = kube.run_kubeapi_stage(
        _kube_args(debug=True, output="kube.json", output_format="json", namespaces=True, pod="api", exec_command="id"),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert len(captured) == 2
    assert captured[0]["append_output"] is False
    assert captured[1]["append_output"] is True
    assert captured[0]["logger"] is not None


def test_run_kubeapi_stage_multi_group_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kube, "Console", _ConsoleCapture)
    monkeypatch.setattr(kube, "collect_scan_ports", lambda *_args, **_kwargs: [16443, 26443])
    monkeypatch.setattr(
        kube,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme="", explicit_port=None)],
    )
    monkeypatch.setattr(
        kube,
        "build_scan_execution_groups",
        lambda *_args, **_kwargs: [
            SimpleNamespace(hosts=["127.0.0.1"], port=16443, scheme_hint=None),
            SimpleNamespace(hosts=["127.0.0.1"], port=26443, scheme_hint=None),
        ],
    )

    class _FakeProgress:
        instances: list[_FakeProgress] = []

        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            self.total = total
            self.advances: list[int] = []
            self.closed = False
            type(self).instances.append(self)

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        kube,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (len(kwargs["hosts"]), 1, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "kubeapi", fake_audit_targets)
    rc = kube.run_kubeapi_stage(_kube_args(), logger=object())  # type: ignore[arg-type]
    assert rc == 0
    assert len(captured) == 2
    assert all(call["show_progress"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 2
    assert progress.advances == [1, 1]
    assert progress.closed is True


def test_run_kubeapi_stage_txt_emit_line_and_error_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kube, "Console", _ConsoleCapture)
    monkeypatch.setattr(kube, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        kube,
        "collect_scan_target_specs",
        lambda targets: (
            [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)]
            if "hosts.txt" not in str(targets)
            else [
                SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None),
                SimpleNamespace(host="127.0.0.2", scheme=None, explicit_port=None),
            ]
        ),
    )

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        kwargs["emit_line"]("KUBEAPI\t127.0.0.1\t16443\tpayload only")
        return 1, 1, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "kubeapi", fake_audit_targets)
    rc = kube.run_kubeapi_stage(
        _kube_args(
            debug=True,
            output_format="txt",
            namespaces=True,
            pod="api",
            exec_command="id",
            targets=None,
            hosts_file="hosts.txt",
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    plains = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "plain"]
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("payload only" in msg for msg in plains)
    assert any("auth=none format=txt" in msg for msg in infos)

    patch_runner_for_legacy_target_fake(
        monkeypatch, "kubeapi", lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full"))
    )
    rc = kube.run_kubeapi_stage(_kube_args(output="kube.json"), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(
        "failed to process kubeapi output: disk full" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_audit_kubeapi_host_debug_stage_telemetry_and_passive_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda _host, _port, path, _timeout, **_kwargs: (
            200,
            {"gitVersion": "v1.31.6"} if path == "/version" else {"versions": ["v1"]},
            {},
            None,
        ),
    )
    monkeypatch.setattr(kube, "_list_namespaces", lambda *_args, **_kwargs: (["default"], 200, None))

    record = kube._audit_kubeapi_host(
        "127.0.0.1",
        16443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
        debug=True,
    )

    assert record["status"] == "open_no_auth"
    assert record["can_list_namespaces"] is True
    assert record["can_list_pods"] is None
    assert record["can_list_secrets"] is None
    assert record["can_exec_pod"] is None
    assert isinstance(record.get("stages"), list)
    stage_names = [str(item.get("stage_name") or "") for item in record["stages"] if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" in stage_names
    assert "data" in stage_names
    debug_events = record.get("debug_events") or []
    assert any("stage_timing_summary" in str(item) for item in debug_events)


def test_audit_kubeapi_targets_two_pass_gate_and_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []

    def fake_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        token: str | None,
        username: str | None,
        password: str | None,
        show_namespaces: bool,
        show_pods: bool,
        show_secrets: bool,
        namespace_filters: list[str],
        exec_pod: str | None,
        exec_command: str | None,
        debug: bool,
        run_deep_checks: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (
            port,
            timeout,
            retries,
            use_https,
            insecure,
            ca_file,
            token,
            username,
            password,
            show_namespaces,
            show_pods,
            show_secrets,
            namespace_filters,
            exec_pod,
            exec_command,
            debug,
            debug_emit,
        )
        calls.append((host, run_deep_checks))
        status = "open_no_auth" if host == "10.0.0.1" else "auth_required"
        return {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": host,
            "port": 16443,
            "https": True,
            "insecure_effective": True,
            "tls_auto_insecure": False,
            "is_kubeapi": True,
            "status": status,
            "version": "v1.31.6",
            "auth_required": status == "auth_required",
            "auth_mode": "none",
            "auth_valid": None,
            "auth_error": None,
            "namespace_filters": [],
            "show_namespaces": False,
            "show_pods": False,
            "show_secrets": False,
            "exec_pod": None,
            "exec_command": None,
            "exec_result": None,
            "namespaces": [],
            "pods": [],
            "secrets": [],
            "namespaces_error": None,
            "pods_error": None,
            "secrets_error": None,
            "error": None,
            "elapsed_ms": 1,
            "can_list_namespaces": True,
            "can_list_pods": None,
            "can_list_secrets": None,
            "can_exec_pod": None,
            "stages": [],
            "stage_failed_at": None,
            "stage_durations_ms": {},
            "stage_attempts": {},
            "debug_events": [],
            "debug_events_streamed": False,
        }

    monkeypatch.setattr(kube, "_call_audit_kubeapi_host_with_thread_debug", fake_call)

    text_lines: list[str] = []
    debug_lines: list[str] = []
    total, detected, failed = run_module_targets_for_test(
        "kubeapi",
        hosts=["10.0.0.1", "10.0.0.2"],
        port=16443,
        timeout=1.0,
        retries=0,
        workers=1,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
        output_path=None,
        output_format="txt",
        emit_line=text_lines.append,
        debug_emit=debug_lines.append,
    )

    assert (total, detected, failed) == (2, 2, 0)
    assert calls == [
        ("10.0.0.1", False),
        ("10.0.0.2", False),
        ("10.0.0.1", True),
    ]
    assert any("pass=1 detect start total=2" in line for line in debug_lines)
    assert any("pass=2 deep start total=1" in line for line in debug_lines)
    assert any("10.0.0.1:16443 stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("10.0.0.2:16443 stage2_gate=skip reason=status=auth_required" in line for line in debug_lines)


def test_http_request_and_ws_exec_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def __init__(self, status: int, payload: bytes, headers: dict[str, str]) -> None:
            self.status = status
            self._payload = payload
            self.headers = headers

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            _ = (exc_type, exc, tb)
            return None

    monkeypatch.setattr(
        kube.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Resp(200, b'{"ok":true}', {"Content-Type": "application/json"}),
    )
    status, payload, headers, error = kube._http_request(
        "127.0.0.1",
        16443,
        "GET",
        "/api",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert (status, payload, headers, error) == (200, b'{"ok":true}', {"content-type": "application/json"}, None)

    monkeypatch.setattr(
        kube.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError(OSError("operation not permitted"))),
    )
    status, payload, headers, error = kube._http_request(
        "127.0.0.1",
        16443,
        "GET",
        "/api",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
    )
    assert status == 0
    assert payload == b""
    assert headers == {}
    assert "operation not permitted" in str(error or "").lower()

    class _Sock:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks
            self.sent: list[bytes] = []
            self.closed = False

        def recv(self, size: int) -> bytes:
            if not self.chunks:
                return b""
            current = self.chunks[0]
            chunk = current[:size]
            rest = current[size:]
            if rest:
                self.chunks[0] = rest
            else:
                self.chunks.pop(0)
            return chunk

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    def _ws_frame(opcode: int, payload: bytes) -> bytes:
        header = bytes([0x80 | opcode])
        size = len(payload)
        if size < 126:
            return header + bytes([size]) + payload
        return header + bytes([126]) + size.to_bytes(2, "big") + payload

    monkeypatch.setattr(kube.os, "urandom", lambda n: b"a" * n)
    sec_key = "YWFhYWFhYWFhYWFhYWFhYQ=="
    accept = "3SC6TZx4582OZaOogPVxMx5CGS0="
    handshake = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode("ascii")
    success_sock = _Sock(
        [
            handshake,
            _ws_frame(0x2, b"\x01hello\n"),
            _ws_frame(0x2, b"\x02warn\n"),
            _ws_frame(0x2, b'\x03{"status":"Success"}'),
            _ws_frame(0x8, b""),
        ]
    )
    monkeypatch.setattr(kube.socket, "create_connection", lambda *_args, **_kwargs: success_sock)
    result = kube._kube_exec_ws(
        "127.0.0.1",
        16443,
        "default",
        "api",
        "id",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
    )
    assert result["ok"] is True
    assert result["stdout"] == "hello\n"
    assert result["stderr"] == "warn\n"
    assert result["exit_code"] == 0
    assert "GET /api/v1/namespaces/default/pods/api/exec?" in success_sock.sent[0].decode("utf-8", errors="replace")
    assert sec_key in success_sock.sent[0].decode("utf-8", errors="replace")

    bad_handshake = _Sock([b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nunauthorized"])
    monkeypatch.setattr(kube.socket, "create_connection", lambda *_args, **_kwargs: bad_handshake)
    denied = kube._kube_exec_ws(
        "127.0.0.1",
        16443,
        "default",
        "api",
        "id",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
    )
    assert denied["ok"] is False
    assert "handshake failed" in str(denied.get("error") or "")
    assert "unauthorized" in str(denied.get("error") or "")


def test_kube_low_level_error_context_and_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    assert kube._clip("abcdef", 3) == "abc"
    assert kube._clip("abcdef", 2) == "ab"
    assert kube._clip("abcdef", 0) == ""

    assert kube._friendly_error_text("") == "connection failed"
    assert kube._friendly_error_text("<urlopen error [Errno 111] Connection refused>") == (
        "connection refused (service is not listening on target port)"
    )
    assert kube._friendly_error_text("[Errno 60] timeout") == "connection timeout"
    assert kube._friendly_error_text("[Errno -2] Name or service not known") == "dns lookup failed"
    assert kube._friendly_error_text("[Errno 101] No route to host") == "network unreachable"
    assert kube._friendly_error_text("[Errno 1] custom detail") == "custom detail"

    assert kube._friendly_error_from_exception(TimeoutError()) == "connection timeout"
    assert kube._friendly_error_from_exception(urllib.error.URLError(OSError("operation not permitted"))) == (
        "operation not permitted by local environment"
    )
    assert (
        kube._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout after retry"}) is True
    )
    assert kube._is_connection_timeout_fail_record({"status": "fail", "error": "connection refused by peer"}) is True
    assert kube._is_connection_timeout_fail_record({"status": "open_no_auth", "error": "connection timeout"}) is False
    assert kube._is_connection_timeout_fail_record({"status": "fail", "error": "tls verification failed"}) is False

    default_ctx = ssl.create_default_context()
    monkeypatch.setattr(kube.ssl, "create_default_context", lambda cafile=None: default_ctx)
    monkeypatch.setattr(kube.ssl, "_create_unverified_context", lambda: "UNVERIFIED")
    assert kube._ssl_context(use_https=False, insecure=False, ca_file=None) is None
    assert kube._ssl_context(use_https=True, insecure=True, ca_file=None) == "UNVERIFIED"
    assert kube._ssl_context(use_https=True, insecure=False, ca_file="/tmp/ca.pem") is default_ctx

    events: list[str] = []
    kube._THREAD_LOCAL_DEBUG_EMIT.callback = events.append
    callback = kube._get_thread_debug_emitter()
    assert callable(callback)
    callback("evt")
    assert events == ["evt"]
    kube._THREAD_LOCAL_DEBUG_EMIT.callback = "not-callable"
    assert kube._get_thread_debug_emitter() is None
    kube._THREAD_LOCAL_DEBUG_EMIT.callback = None


def test_kube_list_items_error_and_pagination_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: (0, None, {}, "transport error"))
    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert items is None
    assert status == 0
    assert error == "transport error"

    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: (403, {"message": "forbidden"}, {}, None))
    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert items is None
    assert status == 403
    assert "forbidden" in str(error or "").lower()

    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: (200, ["not-dict"], {}, None))
    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert items is None
    assert status == 200
    assert error == "invalid kubernetes list response"

    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: (200, {"items": "bad"}, {}, None))
    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert items is None
    assert status == 200
    assert error == "invalid kubernetes list items payload"

    responses = iter(
        [
            (
                200,
                {"items": [{"metadata": {"name": "p1"}}], "metadata": {"continue": "token-1"}},
                {},
                None,
            ),
            (
                200,
                {"items": [{"metadata": {"name": "p2"}}], "metadata": {"continue": "token-2"}},
                {},
                None,
            ),
        ]
    )
    monkeypatch.setattr(kube, "_KUBE_MAX_LIST_PAGES", 2)
    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: next(responses))
    items, status, error = kube._kube_list_items(
        "127.0.0.1",
        16443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert status == 200
    assert isinstance(items, list)
    assert len(items) == 2
    assert error == "pagination limit exceeded"

    assert kube._decode_secret_data_value("Zm9v") == "foo"
    assert kube._decode_secret_data_value("AAECAw==").startswith("<binary-text:")
    assert kube._decode_secret_data_value("AA==") == "<binary-text:1B>"
    assert kube._decode_secret_data_value("%%%") == "<empty>"


def test_kube_list_pods_and_secrets_namespace_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_kube_list_items",
        lambda *_args, **_kwargs: (
            [
                {
                    "metadata": {"namespace": "ns-a", "name": "pod-a"},
                    "status": {"phase": "Running"},
                    "spec": {"containers": [{"name": "c1"}, "skip"]},
                }
            ],
            200,
            None,
        ),
    )
    pods, pods_error = kube._list_pods(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=[],
    )
    assert pods_error is None
    assert pods == [{"namespace": "ns-a", "name": "pod-a", "phase": "Running", "containers": 1}]

    monkeypatch.setattr(kube, "_kube_list_items", lambda *_args, **_kwargs: (None, 403, "forbidden"))
    pods, pods_error = kube._list_pods(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=["finance"],
    )
    assert pods is None
    assert pods_error == "finance: forbidden"

    state = {"calls": 0}

    def list_items_ns(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> tuple[list[dict[str, object]] | None, int, str | None]:
        _ = (use_https, insecure, ca_file, token, username, password)
        state["calls"] += 1
        if "/pods" in path:
            namespace = "finance" if "finance" in path else "ops"
            return (
                [
                    {
                        "metadata": {"name": f"pod-{namespace}"},
                        "status": {"phase": "Pending"},
                        "spec": {"containers": [{"name": "c1"}, {"name": "c2"}]},
                    }
                ],
                200,
                None,
            )
        if "/secrets" in path:
            namespace = "finance" if "finance" in path else "ops"
            return (
                [
                    {
                        "metadata": {"name": f"sec-{namespace}"},
                        "type": "Opaque",
                        "data": {"password": "c2VjcmV0"},
                    }
                ],
                200,
                None,
            )
        raise AssertionError(path)

    monkeypatch.setattr(kube, "_kube_list_items", list_items_ns)
    pods, pods_error = kube._list_pods(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=["finance", "ops"],
    )
    assert pods_error is None
    assert isinstance(pods, list)
    assert len(pods) == 2
    assert {item["namespace"] for item in pods} == {"finance", "ops"}
    assert all(item["containers"] == 2 for item in pods)

    secrets, secrets_error = kube._list_secrets(
        "127.0.0.1",
        16443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=["finance", "ops"],
    )
    assert secrets_error is None
    assert isinstance(secrets, list)
    assert len(secrets) == 2
    assert all(item["type"] == "Opaque" for item in secrets)
    assert all(item["data"]["password"] == "secret" for item in secrets)
    assert state["calls"] >= 4


def test_kube_status_summary_detail_and_renderer_branches() -> None:
    assert kube._status_summary_line({"status": "fail"}) is None
    assert kube._status_summary_line({"status": "not_kubeapi"}) is None
    assert kube._status_summary_line({"status": "open_no_auth", "auth_mode": "none", "auth_required": True}) == (
        "[-] authentication required"
    )
    assert "[+] anonymous access" in str(
        kube._status_summary_line(
            {
                "status": "open_no_auth",
                "auth_mode": "none",
                "auth_required": False,
                "show_namespaces": True,
                "namespaces": ["a"],
            }
        )
    )
    assert "[+] token auth" in str(
        kube._status_summary_line({"status": "auth_valid", "auth_mode": "token", "auth_valid": True})
    )
    assert "u:p auth failed" in str(
        kube._status_summary_line(
            {
                "status": "auth_failed",
                "auth_mode": "basic",
                "auth_valid": False,
                "auth_error": "forbidden",
                "_username_display": "u",
                "_password_display": "p",
            }
        )
    )
    assert "authentication check unavailable" in str(
        kube._status_summary_line(
            {"status": "auth_unknown", "auth_mode": "basic", "auth_valid": None, "auth_error": "unknown"}
        )
    )

    detail_lines = kube._format_detail_records(
        {
            "host": "127.0.0.1",
            "port": 16443,
            "status": "auth_valid",
            "show_namespaces": True,
            "namespaces": [],
            "namespaces_error": "",
            "show_pods": True,
            "pods": [],
            "pods_error": "denied",
            "show_secrets": True,
            "secrets": [],
            "secrets_error": "",
            "namespace_filters": ["finance"],
            "exec_result": {
                "namespace": "finance",
                "pod": "toolbox",
                "command": "id",
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": "forbidden",
                "exit_code": 126,
            },
        },
        "txt",
    )
    assert any("<no namespaces>" in line for line in detail_lines)
    assert any("pods unavailable" in line for line in detail_lines)
    assert any("<no secrets>" in line for line in detail_lines)
    assert any("exec failed" in line for line in detail_lines)
    assert any("<no exec output>" in line for line in detail_lines)

    class _Console:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def plain(self, line: str) -> None:
            self.lines.append(line)

    console = _Console()
    assert kube._render_colored_kubeapi_line(console, "OTHER\tline") is False
    assert (
        kube._render_colored_kubeapi_line(
            console,
            "KUBEAPI\t127.0.0.1\t16443\t [+] token auth (namespaces:7) (pods:5) (secrets:2)",
        )
        is True
    )
    assert console.lines


def test_kube_run_stage_and_audit_output_branches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    class _Console:
        instances: list[_Console] = []

        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []
            self.infos: list[str] = []
            self.plains: list[str] = []
            type(self).instances.append(self)

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.plains.append(message)

        def render_tagged_payload_line(self, _line: str, _tag: str, payload_color: str | None = None) -> bool:
            _ = payload_color
            return False

    monkeypatch.setattr(kube, "Console", _Console)
    monkeypatch.setattr(kube, "collect_scan_ports", lambda _ports: [16443])
    monkeypatch.setattr(
        kube,
        "collect_scan_target_specs",
        lambda _targets: [SimpleNamespace(host="127.0.0.1", scheme="https", explicit_port=16443)],
    )
    monkeypatch.setattr(
        kube,
        "build_scan_execution_groups",
        lambda _specs, _ports, include_scheme_in_key=True: [
            SimpleNamespace(hosts=["127.0.0.1"], port=16443, scheme_hint="https")
        ],
    )

    emitted: list[str] = []

    def fake_audit(**kwargs):
        kwargs["emit_line"]("KUBEAPI\t127.0.0.1\t16443\tpayload-line")
        emitted.append("called")
        return 1, 0, 1

    patch_runner_for_legacy_target_fake(monkeypatch, "kubeapi", fake_audit)
    args = _kube_args(
        debug=True, output=str(tmp_path / "kube.jsonl"), output_format="json", token="tok", username="u", password="p"
    )
    rc = kube.run_kubeapi_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 0
    console = _Console.instances[-1]
    assert any("--token is set; Basic auth credentials are ignored" in msg for msg in console.warns)
    assert any("format=json output=" in msg for msg in console.infos)
    assert emitted == ["called"]

    patch_runner_for_legacy_target_fake(
        monkeypatch, "kubeapi", lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full"))
    )
    rc = kube.run_kubeapi_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 2
    assert any("failed to process kubeapi output" in msg for msg in _Console.instances[-1].errors)
