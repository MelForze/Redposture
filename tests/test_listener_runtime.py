from __future__ import annotations

import threading
from argparse import Namespace

import pytest

from redposture_core.listener_runtime import (
    _autodetect_cert_key_files,
    _build_bind_error,
    _start_servers,
    parse_services,
    run_listeners,
    stop_started_listeners,
)
from redposture_core.logger import AttemptLogger
from redposture_core.servers import RunningServer


def test_autodetect_cert_key_prefers_cert_pem_pair(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy-cert", encoding="utf-8")
    key.write_text("dummy-key", encoding="utf-8")
    (tmp_path / "server.crt").write_text("dummy-cert2", encoding="utf-8")
    (tmp_path / "server.key").write_text("dummy-key2", encoding="utf-8")

    cert_path, key_path = _autodetect_cert_key_files(str(tmp_path))
    assert cert_path == str(cert)
    assert key_path == str(key)


def test_autodetect_cert_key_finds_server_pair(tmp_path) -> None:
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("dummy-cert", encoding="utf-8")
    key.write_text("dummy-key", encoding="utf-8")

    cert_path, key_path = _autodetect_cert_key_files(str(tmp_path))
    assert cert_path == str(cert)
    assert key_path == str(key)


def test_autodetect_cert_key_requires_complete_pair(tmp_path) -> None:
    (tmp_path / "cert.pem").write_text("dummy-cert", encoding="utf-8")
    (tmp_path / "unrelated.key").write_text("dummy-key", encoding="utf-8")

    cert_path, key_path = _autodetect_cert_key_files(str(tmp_path))
    assert cert_path is None
    assert key_path is None


def test_parse_services_normalizes_and_validates() -> None:
    assert parse_services(" postgres,REDIS, blackbox ") == {"postgres", "redis", "blackbox"}

    with pytest.raises(ValueError, match="unsupported services"):
        parse_services("postgres,unknown")

    with pytest.raises(ValueError, match="at least one service"):
        parse_services(" , ")


def test_build_bind_error_distinguishes_address_in_use() -> None:
    in_use = OSError("Address already in use")
    in_use.errno = 48  # type: ignore[attr-defined]
    assert (
        _build_bind_error("postgres", "127.0.0.1", 5432, in_use) == "postgres listener 127.0.0.1:5432 is already in use"
    )

    other = OSError("permission denied")
    assert _build_bind_error("redis", "127.0.0.1", 6379, other) == (
        "redis listener 127.0.0.1:6379 failed to start: permission denied"
    )


class _DummyConsole:
    def __init__(self) -> None:
        self.messages: dict[str, list[str]] = {"warn": [], "info": [], "success": [], "debug": [], "error": []}

    def warn(self, message: str) -> None:
        self.messages["warn"].append(message)

    def info(self, message: str) -> None:
        self.messages["info"].append(message)

    def success(self, message: str) -> None:
        self.messages["success"].append(message)

    def debug(self, message: str) -> None:
        self.messages["debug"].append(message)

    def error(self, message: str) -> None:
        self.messages["error"].append(message)


def test_start_servers_builds_selected_services_with_tls_autodetect(monkeypatch: pytest.MonkeyPatch) -> None:
    console = _DummyConsole()
    logger = AttemptLogger()
    calls: list[tuple[str, int, bool]] = []

    args = Namespace(
        bind="127.0.0.1",
        services="postgres,redis,proxmox,blackbox",
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        postgres_tls=True,
        proxmox_tls=False,
        cert_file=None,
        key_file=None,
    )

    monkeypatch.setattr(
        "redposture_core.listener_runtime._autodetect_cert_key_files", lambda _cwd: ("/tmp/cert.pem", "/tmp/key.pem")
    )
    monkeypatch.setattr(
        "redposture_core.listener_runtime.prepare_cert_files",
        lambda cert, key, generate_local_selfcert=False: (str(cert), str(key), None),
    )
    monkeypatch.setattr(
        "redposture_core.listener_runtime.build_ssl_context",
        lambda cert, key: {"cert": cert, "key": key},
    )
    monkeypatch.setattr("redposture_core.listener_runtime.make_postgres_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("redposture_core.listener_runtime.make_redis_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("redposture_core.listener_runtime.make_proxmox_handler", lambda logger: object())
    monkeypatch.setattr("redposture_core.listener_runtime.make_http_server", lambda *args, **kwargs: object())

    def fake_start_server(name: str, bind: str, port: int, server: object, tls: bool = False) -> RunningServer:
        _ = server
        calls.append((name, port, tls))
        return RunningServer(name=name, bind=bind, port=port, server=object(), thread=threading.Thread(), tls=tls)

    monkeypatch.setattr("redposture_core.listener_runtime.start_server", fake_start_server)

    running, temp_cert_dir = _start_servers(args, logger, {"postgres", "redis", "proxmox", "blackbox"}, console)
    logger.close()

    assert temp_cert_dir is None
    assert [(item.name, item.port, item.tls) for item in running] == [
        ("postgres", 15432, True),
        ("redis", 16379, False),
        ("proxmox", 18006, False),
        ("blackbox", 19115, False),
    ]
    assert calls == [
        ("postgres", 15432, True),
        ("redis", 16379, False),
        ("proxmox", 18006, False),
        ("blackbox", 19115, False),
    ]
    assert console.messages["success"] == ["listeners started"]
    assert any("auto-detected cert/key" in message for message in console.messages["info"])
    assert any("postgres: tcp://127.0.0.1:15432" in message for message in console.messages["info"])
    assert any("proxmox: http://127.0.0.1:18006" in message for message in console.messages["info"])
    assert any("blackbox: http://127.0.0.1:19115" in message for message in console.messages["info"])
    assert console.messages["debug"] == ["services=blackbox,postgres,proxmox,redis"]


def test_stop_started_listeners_ignores_shutdown_errors(tmp_path) -> None:
    temp_cert_dir = tmp_path / "certs"
    temp_cert_dir.mkdir()

    class _BrokenServer:
        def shutdown(self) -> None:
            raise RuntimeError("boom")

        def server_close(self) -> None:
            raise RuntimeError("boom")

    running = [
        RunningServer(
            name="postgres",
            bind="127.0.0.1",
            port=5432,
            server=_BrokenServer(),
            thread=threading.Thread(),
            tls=False,
        )
    ]

    stop_started_listeners(running, str(temp_cert_dir))
    assert not temp_cert_dir.exists()


def test_run_listeners_handles_invalid_services_and_runtime_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger = AttemptLogger()
    try:
        bad_args = Namespace(services="invalid", debug=False)
        assert run_listeners(bad_args, logger) == 2

        stopped: list[tuple[list[RunningServer], str | None]] = []
        monkeypatch.setattr(
            "redposture_core.listener_runtime.stop_started_listeners",
            lambda running, temp_dir: stopped.append((running, temp_dir)),
        )

        args = Namespace(services="postgres", debug=False)
        monkeypatch.setattr(
            "redposture_core.listener_runtime._start_servers",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("bind failed")),
        )
        assert run_listeners(args, logger) == 1

        monkeypatch.setattr(
            "redposture_core.listener_runtime._start_servers",
            lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad value")),
        )
        assert run_listeners(args, logger) == 2

        running = [
            RunningServer(
                name="postgres",
                bind="127.0.0.1",
                port=5432,
                server=object(),
                thread=threading.Thread(),
                tls=False,
            )
        ]
        monkeypatch.setattr(
            "redposture_core.listener_runtime._start_servers", lambda *args, **kwargs: (running, "/tmp/certs")
        )
        monkeypatch.setattr(
            "redposture_core.listener_runtime.time.sleep",
            lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        assert run_listeners(args, logger) == 0
        assert stopped[-1] == (running, "/tmp/certs")
    finally:
        logger.close()
