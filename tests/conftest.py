from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

from redposture_core.clients.tls_cache import clear_tls_context_cache


class ExternalDnsBlockedError(RuntimeError):
    """Raised when a unit test attempts real non-loopback DNS resolution."""


@pytest.fixture(scope="session")
def mtls_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Generate a short-lived CA, server identity, client identity and wrong CA."""

    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for real TLS integration tests")
    root = tmp_path_factory.mktemp("mtls-material")

    def run(*args: str) -> None:
        subprocess.run([openssl, *args], check=True, capture_output=True, timeout=20)

    ca_cert, ca_key = root / "ca.pem", root / "ca.key"
    wrong_ca_cert, wrong_ca_key = root / "wrong-ca.pem", root / "wrong-ca.key"
    for cert, key, common_name in (
        (ca_cert, ca_key, "RedPosture QA CA"),
        (wrong_ca_cert, wrong_ca_key, "RedPosture Wrong QA CA"),
    ):
        run(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            "authorityKeyIdentifier=keyid:always",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        )

    def signed_identity(name: str, common_name: str, extensions: str) -> tuple[Path, Path]:
        cert, key, csr, ext = (
            root / f"{name}.pem",
            root / f"{name}.key",
            root / f"{name}.csr",
            root / f"{name}.ext",
        )
        ext.write_text(
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n" + extensions,
            encoding="utf-8",
        )
        run(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        )
        run(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(ext),
            "-out",
            str(cert),
        )
        return cert, key

    server_cert, server_key = signed_identity(
        "server",
        "localhost",
        "subjectAltName=DNS:localhost,DNS:service.test,DNS:secure.service.test\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
    )
    client_cert, client_key = signed_identity(
        "client",
        "redposture-client",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",
    )
    return {
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "wrong_ca_cert": wrong_ca_cert,
        "wrong_ca_key": wrong_ca_key,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
    }


@pytest.fixture(autouse=True)
def _isolate_shared_tls_context_cache() -> Iterable[None]:
    clear_tls_context_cache()
    try:
        yield
    finally:
        clear_tls_context_cache()


@pytest.fixture(autouse=True)
def _block_external_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    original_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        host_text = str(host or "").strip().strip("[]")
        if host_text and host_text.lower() != "localhost":
            try:
                ipaddress.ip_address(host_text)
            except ValueError:
                raise ExternalDnsBlockedError(f"external DNS resolution blocked in unit test: {host_text}") from None
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


@pytest.fixture(autouse=True, scope="session")
def _force_color_in_tests() -> Iterable[None]:
    """Color output is now gated on ``isatty()``; pytest captures stdout to a
    non-tty, so force color on for the suite (mirrors a real terminal) and clear
    any inherited ``NO_COLOR`` so the color-assertion tests stay deterministic."""
    prev_force = os.environ.get("FORCE_COLOR")
    prev_no = os.environ.get("NO_COLOR")
    os.environ["FORCE_COLOR"] = "1"
    os.environ.pop("NO_COLOR", None)
    try:
        yield
    finally:
        if prev_force is None:
            os.environ.pop("FORCE_COLOR", None)
        else:
            os.environ["FORCE_COLOR"] = prev_force
        if prev_no is not None:
            os.environ["NO_COLOR"] = prev_no


@pytest.fixture
def write_json_payload(tmp_path: Path) -> Callable[[str, object], Path]:
    def _write(name: str, payload: object) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def write_jsonl_payload(tmp_path: Path) -> Callable[[str, Iterable[object]], Path]:
    def _write(name: str, payloads: Iterable[object]) -> Path:
        path = tmp_path / name
        lines = [json.dumps(item, ensure_ascii=False) for item in payloads]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    return _write


# Lab-stand fixtures live in `lab_tests/conftest.py` — the whole `lab_tests/`
# suite is opt-in and gitignored, symmetric with `lab/` itself. `tests/` is
# CI-scope: pure unit + integration, zero dependency on a running lab.
