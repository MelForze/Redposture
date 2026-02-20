from __future__ import annotations

from redposture_core.listener_runtime import _autodetect_cert_key_files


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

