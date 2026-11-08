#!/usr/bin/env python3
"""Sequential real-client profiles for every registered audit module.

Servers are protocol fixtures, not real products. Distinct Linux loopback IPs
represent logical targets; they do not represent distinct physical machines.
The actual module plans, detectors, authentication, scheduler and output run.
Use a fresh resource-limited Linux container per sample to isolate ephemeral
ports and peak RSS. This tool neither starts real product stands nor executes
commands on a real service.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import importlib
import importlib.metadata
import ipaddress
import json
import os
import platform
import random
import resource
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))
MODELS = ("positive", "foreign", "closed", "mixed", "slow")
BASE_IP = int(ipaddress.IPv4Address("127.32.0.1"))
AUTH_SURFACE_CHOICES = (
    "default",
    "user",
    "org",
    "ping",
    "user-orgs",
    "preferences",
    "permissions",
    "teams",
    "org-users",
    "web-login",
    "basic-proxy",
    "digest-acl",
    "grpc-auth",
    "grpc-bearer",
    "provectus-ui",
    "kafbat-ui",
    "akhq",
    "redpanda-console",
    "rest-proxy",
    "connect",
    "ksqldb",
    "schema-registry",
)
PAIR_WIRE_SURFACES = {
    "gitlab": "web-login",
    "kubeapi": "basic-proxy",
    "rabbitmq": "default",
    "harbor": "default",
    "nexus": "default",
    "portainer": "default",
    "elastic": "default",
    "etcd": "default",
}


def is_http_profile(module: str, auth_surface: str = "default") -> bool:
    from scripts.performance_kafka_http import SURFACES as READONLY_SURFACES
    from scripts.performance_kafka_ui import SURFACES
    from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS

    return module in HTTP_PRODUCTS or module == "kafka" and auth_surface in SURFACES | READONLY_SURFACES


PROFILE_FILES = (
    "scripts/profile_module_performance.py",
    "scripts/performance_contracts.py",
    "scripts/performance_http_fixtures.py",
    "scripts/performance_portainer.py",
    "scripts/performance_elastic.py",
    "scripts/performance_etcd.py",
    "scripts/performance_readonly.py",
    "scripts/performance_compute.py",
    "scripts/performance_grpc.py",
    "scripts/performance_kafka_ui.py",
    "scripts/performance_kafka_http.py",
    "scripts/performance_keycloak.py",
    "scripts/performance_http_server.py",
    "scripts/performance_fixture_process.py",
    "scripts/performance_native_fixtures.py",
    "scripts/performance_native_server.py",
    "tests/test_network_fingerprint_matrix.py",
    "tests/application_markup.py",
    "tests/fixtures/detection_pages/application-markup.json",
)


def case_roles(count: int, model: str, seed: int) -> dict[int, str]:
    if count < 1 or count > 1_000_000 or model not in MODELS:
        raise ValueError("1..1000000 targets and a known model are required")
    indices = list(range(count))
    random.Random(seed).shuffle(indices)
    if model in {"positive", "foreign", "closed"}:
        return dict.fromkeys(indices, model)
    positives = set(indices[: max(1, count // 20)]) if model == "mixed" else set(indices)
    return {i: ("positive" if i in positives else "foreign" if i % 2 else "closed") for i in indices}


def source_hash(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((source / "redposture_core").rglob("*.py")):
        digest.update(str(path.relative_to(source)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def activate_source(source: Path) -> None:
    """Changing sys.path cannot replace an already imported source snapshot."""
    source = source.resolve()
    existing = sys.modules.get("redposture_core")
    if existing is not None:
        location = existing.__file__
        if location is None:
            raise RuntimeError("cannot verify imported source; use a fresh process")
        actual = Path(location).resolve().parent
        if actual != source / "redposture_core":
            raise RuntimeError("source already imported from another snapshot; use a fresh process")
    sys.path.insert(0, str(source))


def profile_hash() -> str:
    digest = hashlib.sha256()
    for name in PROFILE_FILES:
        digest.update(name.encode())
        digest.update((ROOT / name).read_bytes())
    return digest.hexdigest()


def environment_evidence() -> dict[str, Any]:
    packages: dict[str, str | None] = {}
    for name in (
        "pytest",
        "pymongo",
        "h2",
        "oracledb",
        "clickhouse-driver",
        "clickhouse-connect",
        "grpcio",
        "protobuf",
    ):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    details = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.system(),
        "architecture": platform.machine(),
        "packages": packages,
    }
    return {
        "details": details,
        "sha256": hashlib.sha256(json.dumps(details, sort_keys=True).encode()).hexdigest(),
    }


def save_instrument_snapshot(parent: Path) -> Path:
    """Retain the actual fixture/tool source, not just a hash of mutable files."""
    fingerprint = profile_hash()
    destination = parent / ("instrument-" + fingerprint)
    destination.mkdir(exist_ok=True)
    files = {}
    for name in PROFILE_FILES:
        payload = (ROOT / name).read_bytes()
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != payload:
                raise ValueError("instrument snapshot changed after creation")
        else:
            with target.open("xb") as handle:
                handle.write(payload)
        files[name] = hashlib.sha256(payload).hexdigest()
    manifest = destination / "MANIFEST.json"
    expected = {"profile_sha256": fingerprint, "files": files}
    if manifest.exists():
        if json.loads(manifest.read_text()) != expected:
            raise ValueError("instrument manifest changed after creation")
    else:
        manifest.write_text(json.dumps(expected, indent=2) + "\n")
    return destination


def fd_count() -> int:
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            return len(os.listdir(directory))
        except OSError:
            pass
    raise RuntimeError("no FD counter available")


def thread_family(name: str) -> str:
    """Static resource attribution: never keep a target or arbitrary label."""
    if name.startswith("pymongo"):
        return "pymongo_monitor" if "monitor" in name else "pymongo_cursor" if "cursor" in name else "pymongo_other"
    if "process_request_thread" in name:
        return "fixture_client"
    if name.startswith(("module-profile-server", "workflow-fixture-loop", "native-fixture-loop")):
        return "fixture_control"
    if name.startswith("module-profile-sampler"):
        return "measurement"
    if name.startswith("redposture-"):
        return "runtime"
    return "main" if name == "MainThread" else "other"


class Fixture:
    """One bounded server; distinct destination IPs select independent cases."""

    def __init__(
        self,
        module: str,
        roles: dict[int, str],
        delay_ms: float,
        slow: bool,
        *,
        mode: str = "detect",
        auth_case: str = "invalid",
        auth_surface: str = "default",
        access_case: str | None = None,
        bind_host: str = "0.0.0.0",
        http_peer: str = "async",
        native_peer: str = "threaded",
    ):
        from scripts.performance_contracts import (
            CoordinationWireLedger,
            GrpcWireLedger,
            HttpPairWireLedger,
            HttpRouteStats,
            S3WireLedger,
        )
        from tests.test_network_fingerprint_matrix import (
            H2ProtocolError,
            InvalidBSON,
        )

        self._closed = False
        self.stats: collections.Counter[str] = collections.Counter()
        self.lock = threading.Lock()
        self.routes = HttpRouteStats()
        self.errors: list[str] = []
        self._token_identities: dict[int, str | None] = {}
        self._grpc_wire = GrpcWireLedger() if module == "grpc" and mode != "detect" else None
        if module == "grpc" and mode != "detect" and auth_surface in {"grpc-auth", "grpc-bearer"}:
            from scripts.performance_grpc import GrpcPayloadLedger

            self._grpc_wire = GrpcPayloadLedger()
        self._s3_wire = S3WireLedger() if module == "minio" and mode != "detect" else None
        from scripts.performance_kafka_http import SURFACES as READONLY_SURFACES
        from scripts.performance_kafka_ui import SURFACES, KafkaUIWireLedger
        from scripts.performance_readonly import ReadOnlyWireLedger

        self._kafka_ui = module == "kafka" and auth_surface in SURFACES | READONLY_SURFACES
        self._read_wire = (
            (KafkaUIWireLedger() if self._kafka_ui else ReadOnlyWireLedger())
            if mode != "detect" and (self._kafka_ui or module in {"docker", "spark", "yarn"})
            else None
        )
        self.access_case = access_case or "open"
        from scripts.performance_elastic import ElasticModel, ElasticWireLedger
        from scripts.performance_etcd import EtcdWireLedger
        from scripts.performance_portainer import PortainerWireLedger

        self._pair_wire = (
            (
                PortainerWireLedger()
                if module == "portainer"
                else ElasticWireLedger()
                if module == "elastic"
                else EtcdWireLedger()
                if module == "etcd"
                else HttpPairWireLedger()
            )
            if mode != "detect" and PAIR_WIRE_SURFACES.get(module) == auth_surface
            else None
        )
        self._coordination_wire = (
            CoordinationWireLedger()
            if mode != "detect" and module in {"zookeeper", "keeper"} and auth_surface == "digest-acl"
            else None
        )
        self._elastic_model = None
        if module == "elastic" and mode != "detect":
            from scripts.performance_http_fixtures import profile_pair

            self._elastic_model = ElasticModel(
                valid_pair=None if auth_case == "invalid" else profile_pair(module, mode, auth_case),
                limited=auth_case == "limited",
            )
        self.module, self.mode, self.auth_case, self.auth_surface = module, mode, auth_case, auth_surface
        self.roles = roles
        self.http_peer: Any = None
        if not is_http_profile(module, auth_surface) and native_peer == "async":
            from scripts.performance_native_server import AsyncNativeFixture

            def native_role(host: str) -> str:
                return roles.get(int(ipaddress.IPv4Address(host)) - BASE_IP, "foreign")

            def native_delay(host: str) -> float:
                index = int(ipaddress.IPv4Address(host)) - BASE_IP
                return delay_ms * (10 if slow and index % 20 == 0 else 1) / 1000

            program_factory: Any = None
            if module == "grpc" and mode != "detect" and auth_surface in {"grpc-auth", "grpc-bearer"}:
                from scripts.performance_grpc import grpc_auth_steps
                from scripts.performance_http_fixtures import profile_pair

                def full_grpc_program(host: str, initial: bytes, message: Any) -> Any:
                    def observe(headers: Any, body: bytes, status: int, reply: bytes) -> None:
                        from scripts.performance_grpc import GrpcPayloadLedger

                        index = int(ipaddress.IPv4Address(host)) - BASE_IP
                        with self.lock:
                            if isinstance(self._grpc_wire, GrpcPayloadLedger):
                                self._grpc_wire.record_exchange(index, headers, body, status, reply)

                    return grpc_auth_steps(
                        initial,
                        message,
                        valid_pair=None if auth_case == "invalid" else profile_pair(module, mode, auth_case),
                        limited=auth_case == "limited",
                        observer=observe,
                    )

                program_factory = full_grpc_program

            self.http_peer = AsyncNativeFixture(
                module,
                mode=mode,
                role=native_role,
                host=bind_host,
                delay=native_delay,
                grpc_observer=self._observe_grpc if self._grpc_wire is not None else None,
                coordination_observer=self._observe_coordination if self._coordination_wire is not None else None,
                program_factory=program_factory,
            )
            self.http_peer.start()
            self.port = self.http_peer.port
            self.stats, self.lock, self.errors = self.http_peer.stats, self.http_peer.lock, self.http_peer.errors
            self.closed = socket.socket()
            self.closed.bind((bind_host, 0))
            self.closed_port = int(self.closed.getsockname()[1])
            self.thread = self.http_peer.thread
            return
        if is_http_profile(module, auth_surface) and http_peer == "async":
            from scripts.performance_http_server import AsyncHttpFixture

            def delay(host: str, path: str) -> float:
                index = int(ipaddress.IPv4Address(host)) - BASE_IP
                return delay_ms * (10 if slow and index % 20 == 0 else 1) / 1000

            def non_http(host: str) -> bytes:
                index = int(ipaddress.IPv4Address(host)) - BASE_IP
                if roles.get(index, "foreign") == "positive":
                    return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                return b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nforeign"

            self.http_peer = AsyncHttpFixture(
                self._http_reply, host=bind_host, delay=delay, keep_alive=False, non_http_response=non_http
            )
            self.http_peer.start()
            self.port = self.http_peer.port
            self.stats, self.lock, self.errors = self.http_peer.stats, self.http_peer.lock, self.http_peer.errors
            self.closed = socket.socket()
            self.closed.bind((bind_host, 0))
            self.closed_port = int(self.closed.getsockname()[1])
            self.thread = self.http_peer.thread
            return
        owner = self

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False
            block_on_close = True
            request_queue_size = 2048

            def handle_error(self, request: Any, client_address: Any) -> None:
                with owner.lock:
                    if len(owner.errors) < 16:
                        owner.errors.append(repr(sys.exc_info()[1]))

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(1)
                index = int(ipaddress.IPv4Address(self.request.getsockname()[0])) - BASE_IP
                role = roles.get(index, "foreign")
                with owner.lock:
                    owner.stats["connections"] += 1
                try:
                    delay = delay_ms * (10 if slow and index % 20 == 0 else 1)
                    if delay:
                        time.sleep(delay / 1000)
                    # Read complete initial bytes even when TCP fragments them.
                    initial = bytearray()
                    while len(initial) < 4:
                        portion = self.request.recv(4 - len(initial))
                        if not portion:
                            return
                        initial.extend(portion)
                    if role != "positive":
                        self.request.sendall(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nforeign"
                        )
                    elif is_http_profile(module, auth_surface):
                        request = bytes(initial)
                        if bytes(initial) not in {b"GET ", b"HEAD", b"POST", b"PUT ", b"DELE", b"OPTI", b"PATC"}:
                            self.request.sendall(
                                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            )
                            return
                        while b"\r\n\r\n" not in request and len(request) < 65536:
                            portion = self.request.recv(4096)
                            if not portion:
                                return
                            request += portion
                        if b"\r\n\r\n" not in request:
                            return
                        head, _, body = request.partition(b"\r\n\r\n")
                        fields = {}
                        for header in head.split(b"\r\n")[1:]:
                            name, _, value = header.partition(b":")
                            fields[name.strip().lower()] = value.strip()
                        length = int(fields.get(b"content-length", b"0"))
                        if not 0 <= length <= 65536:
                            return
                        while len(body) < length:
                            portion = self.request.recv(min(4096, length - len(body)))
                            if not portion:
                                return
                            body += portion
                        with owner.lock:
                            owner.stats["http_requests"] += 1
                        path = request.split(b" ", 2)[1].decode("ascii", "replace")
                        reply = owner._http_reply(
                            bytes(initial).decode().strip(), path, fields, body[:length], self.request.getsockname()[0]
                        )
                        self.request.sendall(reply)
                    else:
                        # The shared wire corpus validates these native frames.
                        # Count sessions, not HTTP requests or guessed SQL calls.
                        with owner.lock:
                            owner.stats["native_sessions"] += 1
                        from scripts.performance_native_fixtures import (
                            serve_detection_response,
                            serve_invalid_credentials,
                        )

                        def message(name: str) -> None:
                            with owner.lock:
                                owner.stats["native_messages"] += 1
                                category = (
                                    name
                                    if name
                                    in {
                                        "hello",
                                        "ismaster",
                                        "buildinfo",
                                        "listdatabases",
                                        "saslstart",
                                        "saslcontinue",
                                        "connectionstatus",
                                        "ping",
                                        "auth",
                                        "info",
                                        "quit",
                                        "startup",
                                        "sslrequest",
                                        "password",
                                        "grpc_call",
                                        "kafka_api_18",
                                        "kafka_api_17",
                                        "kafka_api_36",
                                        "kafka_sasl_raw",
                                    }
                                    else "other"
                                )
                                owner.stats["command." + category] += 1

                        if mode == "detect" or not serve_invalid_credentials(
                            module,
                            self.request,
                            bytes(initial),
                            message,
                            grpc_observer=(
                                lambda headers, status: owner._observe_grpc(
                                    self.request.getsockname()[0], headers, status
                                )
                            )
                            if owner._grpc_wire is not None
                            else None,
                            coordination_observer=(
                                lambda kind, username, password, path, error: owner._observe_coordination(
                                    self.request.getsockname()[0], kind, username, password, path, error
                                )
                            )
                            if owner._coordination_wire is not None
                            else None,
                        ):
                            serve_detection_response(module, self.request, bytes(initial), message)
                except (OSError, EOFError, ValueError, struct.error, H2ProtocolError, InvalidBSON):
                    return

        self.server = Server((bind_host, 0), Handler)
        self.port = int(self.server.server_address[1])
        # Bound but not listening: reserves an actual connection-refused port.
        self.closed = socket.socket()
        self.closed.bind((bind_host, 0))
        self.closed_port = int(self.closed.getsockname()[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, name="module-profile-server"
        )
        self.thread.start()

    def _http_reply(self, method: str, path: str, fields: dict[bytes, bytes], body: bytes, host: str) -> bytes:
        from tests.test_network_fingerprint_matrix import _http_response

        module, mode, auth_case, auth_surface = self.module, self.mode, self.auth_case, self.auth_surface
        index = int(ipaddress.IPv4Address(host)) - BASE_IP
        origin = f"http://{host}:{self.port}"
        with self.lock:
            self.routes.record(
                method,
                path,
                fields,
                body,
                body_group=(
                    "nexus-script-endpoint"
                    if module == "nexus"
                    else "gitlab-web-session"
                    if module == "gitlab" and auth_surface == "web-login"
                    else "portainer-exec-endpoint"
                    if module == "portainer"
                    else "elastic-probe-index"
                    if module == "elastic"
                    else "kafka-ui-auth"
                    if self._kafka_ui
                    else None
                )
                if mode != "detect"
                else None,
            )
            if self._s3_wire is not None:
                self._s3_wire.record(index, method, path, fields, body)
        if self.roles.get(index, "foreign") != "positive":
            reply = b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nforeign"
            self._record_http_pair_reply(index, module, method, path, fields, body, reply)
            return reply
        from scripts.performance_etcd import etcd_reply
        from scripts.performance_http_fixtures import (
            TOKEN_PRODUCTS,
            airflow_reply,
            gitlab_web_reply,
            grafana_reply,
            harbor_reply,
            jenkins_reply,
            kube_basic_proxy_reply,
            minio_reply,
            nexus_reply,
            profile_pair,
            profile_token,
            proxmox_reply,
            rabbitmq_reply,
            registry_reply,
            token_from_headers,
            token_reply,
        )
        from scripts.performance_portainer import portainer_reply

        controlled = None
        if self._kafka_ui:
            from scripts.performance_kafka_http import SURFACES as READONLY_SURFACES
            from scripts.performance_kafka_http import http_reply
            from scripts.performance_kafka_ui import kafka_ui_reply

            controlled = (
                http_reply(method, path, body, surface=auth_surface, access=self.access_case)
                if auth_surface in READONLY_SURFACES
                else kafka_ui_reply(
                    method,
                    path,
                    fields,
                    body,
                    surface=auth_surface,
                    origin=origin,
                    valid_pair=None if auth_case == "invalid" else profile_pair(module, mode, auth_case),
                    limited=auth_case == "limited",
                )
            )
        elif self._pair_wire is not None:
            valid_pair = None if auth_case == "invalid" else profile_pair(module, mode, auth_case)
            controlled = (
                self._elastic_model.reply(method, path, fields, body, host)
                if self._elastic_model is not None
                else etcd_reply(method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited")
                if module == "etcd"
                else portainer_reply(method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited")
                if module == "portainer"
                else gitlab_web_reply(
                    method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited", origin=origin
                )
                if module == "gitlab"
                else nexus_reply(
                    method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited", origin=origin
                )
                if module == "nexus"
                else harbor_reply(method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited")
                if module == "harbor"
                else rabbitmq_reply(method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited")
                if module == "rabbitmq"
                else kube_basic_proxy_reply(
                    method, path, fields, body, valid_pair=valid_pair, limited=auth_case == "limited"
                )
            )
        elif mode != "detect" and module == "docker":
            from scripts.performance_readonly import docker_reply

            controlled = docker_reply(method, path, access=self.access_case)
        elif mode != "detect" and module in {"spark", "yarn"}:
            from scripts.performance_compute import compute_reply

            controlled = compute_reply(module, method, path, access=self.access_case)
        elif mode != "detect" and module in TOKEN_PRODUCTS:
            valid_token = (
                None
                if auth_case == "invalid"
                else "root"
                if module == "vault" and mode == "defcreds"
                else profile_token(module, auth_case)
            )
            controlled = token_reply(
                method,
                path,
                fields,
                body,
                module=module,
                valid_token=valid_token,
                limited=auth_case == "limited",
                origin=origin,
            )
            verifier_paths = {
                "vault": {"/v1/auth/token/lookup-self"},
                "nomad": {"/v1/acl/token/self"},
                "jupyter": {"/api/status", "/api/me"},
                "consul": {"/v1/acl/token/self"},
                "kubeapi": {"/api/v1/namespaces", "/apis/authentication.k8s.io/v1/selfsubjectreviews"},
                "qdrant": {"/collections"},
                "gitlab": {"/api/v4/user"},
                "keycloak": {"/admin/serverinfo", "/admin/realms", "/realms/master/protocol/openid-connect/userinfo"},
            }
            supplied = token_from_headers(module, fields)
            if supplied is not None and urlsplit(path).path in verifier_paths[module]:
                with self.lock:
                    if index not in self._token_identities:
                        self._token_identities[index] = supplied
                    elif self._token_identities[index] != supplied:
                        self._token_identities[index] = None  # Ambiguous, never guessed.
        elif mode != "detect" and module in {"grafana", "jenkins", "docker-registry", "proxmox", "airflow", "minio"}:
            valid_pair = None if auth_case == "invalid" else profile_pair(module, mode, auth_case)
            reply_options: dict[str, Any] = {
                "valid_pair": valid_pair,
                "limited": auth_case == "limited",
            }
            if module == "airflow":
                controlled = airflow_reply(method, path, fields, body, **reply_options)
            elif module == "minio":
                controlled = minio_reply(method, path, fields, body, **reply_options)
            elif module == "grafana":
                controlled = grafana_reply(
                    method,
                    path,
                    fields,
                    body,
                    auth_surface="user" if auth_surface == "default" else auth_surface,
                    **reply_options,
                )
            elif module == "jenkins":
                controlled = jenkins_reply(
                    method,
                    path,
                    fields,
                    body,
                    origin=origin,
                    **reply_options,
                )
            elif module == "docker-registry":
                controlled = registry_reply(method, path, fields, body, **reply_options)
            else:
                controlled = proxmox_reply(method, path, fields, body, **reply_options)
        invalid_auth = (
            bool(
                set(fields).intersection(
                    {
                        b"authorization",
                        b"private-token",
                        b"x-vault-token",
                        b"x-nomad-token",
                        b"x-consul-token",
                        b"api-key",
                    }
                )
            )
            or method == "POST"
        )
        if controlled is not None:
            reply = controlled
        elif invalid_auth:
            reply = (
                b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n"
                b'Content-Length: 24\r\nConnection: close\r\n\r\n{"error":"Unauthorized"}'
            )
        else:
            reply = _http_response(module, path, origin=origin)
        self._record_http_pair_reply(index, module, method, path, fields, body, reply)
        return reply

    def _record_http_pair_reply(
        self, index: int, module: str, method: str, path: str, fields: dict[bytes, bytes], body: bytes, reply: bytes
    ) -> None:
        from scripts.performance_elastic import ElasticWireLedger
        from scripts.performance_etcd import EtcdWireLedger
        from scripts.performance_portainer import PortainerWireLedger

        read_wire = getattr(self, "_read_wire", None)
        if read_wire is not None:
            with self.lock:
                read_wire.record_response(index, method, path, fields, body, reply)

        if self._pair_wire is not None:
            with self.lock:
                if isinstance(self._pair_wire, (PortainerWireLedger, ElasticWireLedger, EtcdWireLedger)):
                    self._pair_wire.record_response(index, method, path, fields, body, reply)
                else:
                    self._pair_wire.record(index, module, method, path, fields, body, int(reply.split(b" ", 2)[1]))

    def model_summary(self) -> dict[str, int] | None:
        return self._elastic_model.summary() if self._elastic_model is not None else None

    def pop_read_calls(self, index: int) -> dict[str, Any] | None:
        with self.lock:
            return self._read_wire.pop(index) if self._read_wire is not None else None

    def read_wire_summary(self) -> dict[str, int] | None:
        with self.lock:
            return self._read_wire.snapshot() if self._read_wire is not None else None

    def pop_token_identity(self, index: int) -> str | None:
        with self.lock:
            return self._token_identities.pop(index, None)

    def pop_s3_calls(self, index: int) -> dict[str, Any] | None:
        with self.lock:
            return self._s3_wire.pop(index) if self._s3_wire is not None else None

    def pop_pair_calls(self, index: int) -> dict[str, Any] | None:
        with self.lock:
            return self._pair_wire.pop(index) if self._pair_wire is not None else None

    def _observe_coordination(
        self, host: str, kind: str, username: str | None, password: str | None, path: str | None, error: int
    ) -> None:
        index = int(ipaddress.IPv4Address(host)) - BASE_IP
        with self.lock:
            if self._coordination_wire is not None:
                self._coordination_wire.record(index, kind, username, password, path, error)

    def pop_coordination_calls(self, index: int) -> dict[str, Any] | None:
        with self.lock:
            return self._coordination_wire.pop(index) if self._coordination_wire is not None else None

    def coordination_wire_summary(self) -> dict[str, int] | None:
        with self.lock:
            return self._coordination_wire.snapshot() if self._coordination_wire is not None else None

    def pair_wire_summary(self) -> dict[str, int] | None:
        with self.lock:
            return self._pair_wire.snapshot() if self._pair_wire is not None else None

    def s3_wire_summary(self) -> dict[str, int] | None:
        with self.lock:
            return self._s3_wire.snapshot() if self._s3_wire is not None else None

    def _observe_grpc(self, host: str, headers: list[tuple[bytes, bytes]] | None, status: int) -> None:
        index = int(ipaddress.IPv4Address(host)) - BASE_IP
        with self.lock:
            if self._grpc_wire is not None:
                self._grpc_wire.record(index, headers, status)

    def pop_grpc_calls(self, index: int) -> dict[str, Any] | None:
        with self.lock:
            return self._grpc_wire.pop(index) if self._grpc_wire is not None else None

    def grpc_wire_summary(self) -> dict[str, int] | None:
        with self.lock:
            return self._grpc_wire.snapshot() if self._grpc_wire is not None else None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.http_peer is not None:
            try:
                self.http_peer.close()
            finally:
                self.closed.close()
                if self._grpc_wire is not None:
                    self._grpc_wire.close()
                if self._s3_wire is not None:
                    self._s3_wire.close()
                if self._pair_wire is not None:
                    self._pair_wire.close()
                if self._coordination_wire is not None:
                    self._coordination_wire.close()
                if self._read_wire is not None:
                    self._read_wire.close()
            return
        self.server.shutdown()
        self.server.server_close()
        self.closed.close()
        self.thread.join(2)
        if self._grpc_wire is not None:
            self._grpc_wire.close()
        if self._s3_wire is not None:
            self._s3_wire.close()
        if self._pair_wire is not None:
            self._pair_wire.close()
        if self._coordination_wire is not None:
            self._coordination_wire.close()
        if self._read_wire is not None:
            self._read_wire.close()
        if self.thread.is_alive():
            raise RuntimeError("fixture did not stop")


def configure_profile_debug(options: Any, *, public: bool, sink: Any = None) -> None:
    """Keep public CLI ownership; detect-only logs use a real flushed file."""
    options.debug_emit = None
    if not bool(options.debug) or public:
        return
    if sink is None:
        raise ValueError("debug measurement requires a real output sink")
    lock = threading.Lock()

    def emit(message: str) -> None:
        with lock:
            sink.write(str(message) + "\n")
            sink.flush()

    options.debug_emit = emit


def profile_output_files(paths: list[Path]) -> list[dict[str, Any]]:
    """Hash measured files in bounded chunks after timed writers have closed."""
    records = []
    for path in paths:
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        size = lines = 0
        with path.open("rb") as reader:
            while chunk := reader.read(65536):
                digest.update(chunk)
                size += len(chunk)
                lines += chunk.count(b"\n")
        records.append({"path": path.name, "bytes": size, "newlines": lines, "sha256": digest.hexdigest()})
    return records


def module_options(module: str, mode: str, target: str, timeout: float, *, auth_case: str = "invalid") -> list[str]:
    options = [module, "-t", target, "--timeout", str(timeout), "--retries", "0", "--no-color"]
    if module == "clickhouse":
        options += ["--protocol", "native"]
    elif module == "grpc":
        options += ["--plaintext"]
    elif module == "oracle":
        options += ["--service", "FREEPDB1", "--protocol", "tcp"]
    if mode == "credentials" or (mode == "actions" and auth_case != "invalid"):
        if module in {"vault", "nomad", "jupyter", "keycloak", "gitlab", "consul", "kubeapi"}:
            from scripts.performance_http_fixtures import TOKEN_PRODUCTS, profile_token

            options += [
                "--token",
                profile_token(module, auth_case) if module in TOKEN_PRODUCTS else "profile-invalid-token",
            ]
        elif module == "qdrant":
            from scripts.performance_http_fixtures import profile_token

            options += ["--api-key", profile_token(module, auth_case)]
        elif module not in {"docker", "spark", "yarn"}:
            from scripts.performance_http_fixtures import profile_pair

            pair = profile_pair(module, mode, auth_case)
            options += ["-u", pair[0], "-p", pair[1]]
    elif mode == "defcreds":
        options += ["--defcreds"]
    return options


def expected_credential_identities(module: str, options: Any, plan: Any) -> list[tuple[Any, Any, Any]]:
    """Respect a module's prepared identity when its internal plan is redacted.

    Keycloak keeps its actual token in _keycloak_token and uses a marker for
    the common runtime's PR:L gate. Never substitute CLI values, shorten a
    catalogue or change the public record to make wire observations agree.
    """
    identities = [(row.username, row.password, row.token) for row in plan.credential_runs]
    if module == "keycloak" and identities == [(None, None, "<redacted>")]:
        prepared = getattr(options, "_keycloak_token", None)
        if isinstance(prepared, str) and prepared:
            return [(None, None, prepared)]
    return identities


def inventory(source: Path) -> dict[str, Any]:
    """Read current parser/spec contracts; never contact a target."""
    activate_source(source)
    from redposture_core import web_panels
    from redposture_core.cli_args import build_parser, parse_args
    from redposture_core.module_registry import AUDIT_MODULE_NAMES
    from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS, NATIVE_PRODUCTS

    parser = build_parser()
    choices = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    rows = []
    for module in AUDIT_MODULE_NAMES:
        options = parse_args(module_options(module, "detect", "127.0.0.1:43123", 0.5))
        package = module.replace("-", "_")
        stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
        spec = getattr(stage, f"build_{package}_spec")(options)
        flags = sorted({flag for action in choices[module]._actions for flag in action.option_strings})
        additional = []
        if module == "kafka":
            from redposture_core.modules.kafka.http_surfaces import _PRODUCTS

            additional = ["provectus", "kafbat", *_PRODUCTS]
        elif module == "grpc":
            additional = ["grpc_web"]
        elif module == "clickhouse":
            additional = ["clickhouse_http"]
        rows.append(
            {
                "module": module,
                "family": "http" if module in HTTP_PRODUCTS else "native",
                "native_async_detect": spec.detect_async is not None,
                "lifecycle": "explicit_hooks" if spec.detect is not None else "host_stage",
                "companion_surfaces": list(web_panels.MODULE_PRODUCTS.get(module, ())),
                "additional_surfaces": additional,
                "default_port": spec.default_port,
                "default_ports": getattr(stage, "_DEFAULT_PORTS", None),
                "auth_flags": [
                    flag for flag in flags if flag in {"-u", "-p", "--token", "--api-key", "--defcreds", "--tls-cert"}
                ],
                "defcreds": "--defcreds" in flags,
                "discover": "--discover" in flags,
                "inventory_flags": sorted(
                    {
                        flag
                        for action in choices[module]._actions
                        if action.dest.startswith("show_")
                        or action.dest in {"namespaces", "pods", "containers", "images", "analyze"}
                        for flag in action.option_strings
                    }
                ),
                "execution_flags": [
                    flag for flag in flags if flag in {"--execute", "--exec", "--os-cmd", "--os-shell"}
                ],
                "all_flags": flags,
                "measurement_status": "PENDING",
            }
        )
    if set(AUDIT_MODULE_NAMES) != set(HTTP_PRODUCTS) | set(NATIVE_PRODUCTS):
        raise ValueError("wire fixtures do not cover the current registry")
    return {
        "source_sha256": source_hash(source),
        "audit_modules": rows,
        "other_workflows": [
            {"name": name, "measurement_status": "PENDING"}
            for name in ("spray", "exporters collect", "exporters trigger")
        ],
    }


def unsupported_auth_reason(module: str, mode: str) -> str | None:
    """Check the actual CLI, not whether this fixture implements a protocol."""
    if mode not in {"credentials", "defcreds"}:
        return None
    from redposture_core.cli_args import build_parser

    choices = next(a.choices for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    flags = {flag for action in choices[module]._actions for flag in action.option_strings}
    if mode == "defcreds" and "--defcreds" not in flags:
        return "module has no --defcreds option"
    if mode == "credentials" and not (
        flags.intersection({"--token", "--api-key"})
        or (flags.intersection({"-u", "--username"}) and flags.intersection({"-p", "--password"}))
    ):
        return (
            "module has no supplied pair/token CLI; client-certificate authentication requires a separate TLS scenario"
        )
    return None


def measure(args: argparse.Namespace) -> dict[str, Any]:
    if sys.platform != "linux":
        raise RuntimeError("distinct loopback targets require Linux; use --container-image")
    source = Path(args.source).resolve()
    activate_source(source)
    args._profile_environment = environment_evidence()
    reason = unsupported_auth_reason(args.module, args.mode)
    if reason is not None:
        return {
            "module": args.module,
            "mode": args.mode,
            "model": args.model,
            "quality": "NOT_APPLICABLE",
            "reason": reason,
            "source_sha256": source_hash(source),
            "profile_sha256": profile_hash(),
            "environment": args._profile_environment["details"],
            "environment_sha256": args._profile_environment["sha256"],
            "wall_seconds": None,
            "cleanup": "NOT_APPLICABLE",
            "fixture_started": False,
        }
    roles = case_roles(args.targets, args.model, args.seed)
    start_fd, start_threads = fd_count(), threading.active_count()
    from scripts.performance_fixture_process import ProcessHttpFixture

    http_profile = is_http_profile(args.module, args.auth_surface)
    fixture_factory = ProcessHttpFixture if args.http_peer == "process" and http_profile else Fixture
    native_peer = getattr(args, "native_peer", "threaded")
    if not http_profile and native_peer == "process":
        fixture_factory = ProcessHttpFixture
    fixture = fixture_factory(
        args.module,
        roles,
        args.delay_ms,
        args.model == "slow",
        mode=args.mode,
        auth_case=args.auth_case,
        auth_surface=args.auth_surface,
        access_case=getattr(args, "access_case", None),
        http_peer=args.http_peer,
        native_peer="async" if native_peer == "process" else native_peer,
    )
    try:
        return _measure_fixture(args, source, roles, fixture, start_fd, start_threads)
    finally:
        # Setup errors must also stop a non-daemon fixture thread.
        fixture.close()


def _measure_fixture(
    args: argparse.Namespace,
    source: Path,
    roles: dict[int, str],
    fixture: Any,
    start_fd: int,
    start_threads: int,
) -> dict[str, Any]:
    from redposture_core.async_detection import AsyncDetectScheduler
    from redposture_core.audit_models import AuditRecord
    from redposture_core.cli_args import parse_args
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner
    from redposture_core.targeting import ScanTargetSpec
    from scripts.performance_contracts import SchedulerAdmissionProbe
    from scripts.performance_http_fixtures import TOKEN_PRODUCTS

    expected = {i for i, role in roles.items() if role == "positive"}

    http_target = is_http_profile(args.module, args.auth_surface) or args.target_style == "http"
    initial_target = ("http://" if http_target else "") + f"127.32.0.1:{fixture.port}"
    public = args.mode != "detect"
    verify_credential_catalogue = args.mode in {"credentials", "defcreds"} or (
        args.mode == "actions" and args.auth_case != "invalid"
    )
    arguments = module_options(args.module, args.mode, initial_target, args.timeout, auth_case=args.auth_case)
    from scripts.performance_kafka_http import SURFACES as KAFKA_HTTP_SURFACES
    from scripts.performance_kafka_ui import SURFACES as KAFKA_UI_SURFACES

    kafka_readonly_mode = args.module == "kafka" and args.auth_surface in KAFKA_HTTP_SURFACES
    kafka_ui_mode = args.module == "kafka" and args.auth_surface in KAFKA_UI_SURFACES | KAFKA_HTTP_SURFACES
    if kafka_ui_mode and not kafka_readonly_mode and args.mode == "actions" and args.auth_case == "invalid":
        arguments += ["-u", "profile-invalid-user", "-p", "profile-invalid-password"]
        verify_credential_catalogue = True
    grpc_payload_mode = args.module == "grpc" and args.auth_surface in {"grpc-auth", "grpc-bearer"}
    if grpc_payload_mode and args.mode == "actions":
        verify_credential_catalogue = True
        if args.auth_case == "invalid" and args.auth_surface == "grpc-auth":
            arguments += ["-u", "profile-invalid-user", "-p", "profile-invalid-password"]
    if grpc_payload_mode and args.auth_surface == "grpc-bearer" and args.mode in {"credentials", "actions"}:
        for flag in ("-u", "-p"):
            if flag in arguments:
                offset = arguments.index(flag)
                del arguments[offset : offset + 2]
        arguments += ["--token", "profile-invalid-token" if args.auth_case == "invalid" else "admin"]
    pair_mode = PAIR_WIRE_SURFACES.get(args.module) == args.auth_surface
    coordination_mode = args.module in {"zookeeper", "keeper"} and args.auth_surface == "digest-acl"
    if pair_mode and args.mode == "credentials" and args.module in {"gitlab", "kubeapi"}:
        from scripts.performance_http_fixtures import profile_pair

        token_index = arguments.index("--token")
        arguments[token_index : token_index + 2] = [
            "-u",
            profile_pair(args.module, args.mode, args.auth_case)[0],
            "-p",
            profile_pair(args.module, args.mode, args.auth_case)[1],
        ]
    arguments += ["--workers", str(args.workers), "--format", args.format, *args.action]
    options = parse_args(arguments)
    if not args.auto_concurrency:
        options._async_detect_concurrency = args.concurrency
    options._disable_async_detection = args.engine == "sync"
    options.debug = args.debug
    options.debug_emit = None
    if args.debug and (source / "redposture_core/runtime_diagnostics.py").exists():
        from redposture_core.runtime_diagnostics import RuntimeDiagnostics

        options._runtime_observer = RuntimeDiagnostics()
    package = args.module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    # Keep the module's own preparation/credential catalogue rather than
    # fabricating candidates or bypassing token validation.
    prepare = getattr(stage, f"_validate_and_prepare_{package}_args", None)
    if callable(prepare) and not public:

        class Console:
            def error(self, value: str) -> None:
                raise ValueError(value)

            def info(self, value: str) -> None:
                pass

        result = prepare(options, Console())
        if result is not None:
            raise ValueError(f"module preparation returned {result}")
    elif not public and args.module in {"vault", "nomad", "jupyter"}:
        result = stage.policy.validate_args(options, type("Console", (), {"error": lambda _, v: None})())
        if result is not None:
            raise ValueError(f"token preparation returned {result}")
    original_plan = getattr(stage, f"build_{package}_plan")(options)
    spec = getattr(stage, f"build_{package}_spec")(options)
    if args.mode == "detect":
        # Preserve state/cleanup and the actual detector. Explicit no-op hooks
        # prevent the legacy monolithic path from doing unwanted auth/data.
        spec = replace(
            spec,
            auth=lambda _ctx, row: row,
            capabilities=lambda _ctx, row: row,
            data=lambda _ctx, row: row,
            rce_probe=None,
        )
    spec = replace(spec, record_retention_limit=0)
    groups: dict[int, list[Any]] = collections.defaultdict(list)
    for index in range(args.targets):
        port = fixture.closed_port if roles[index] == "closed" else fixture.port
        host = str(ipaddress.IPv4Address(BASE_IP + index))
        groups[port].append(ScanTargetSpec(host, scheme="http" if http_target else None, explicit_port=port))
    plan = AuditCommandPlan(
        target_specs_by_port={port: tuple(values) for port, values in groups.items()},
        ports=tuple(groups),
        credential_runs=original_plan.credential_runs,
        workers=args.workers,
        output_format=args.format,
        output_path=str(args.output.with_suffix(".results." + args.format)) if args.save else None,
    )
    seen: collections.Counter[int] = collections.Counter()
    transport_outcome_errors: collections.Counter[str] = collections.Counter()
    all_records: collections.Counter[int] = collections.Counter()
    accepted = 0
    credential_counts: collections.Counter[int] = collections.Counter()
    credential_digests: collections.Counter[str] = collections.Counter()
    credential_totals: collections.Counter[str] = collections.Counter()
    credential_verdict_failures: collections.Counter[str] = collections.Counter()
    accepted_targets = 0
    negative_target_credential_verdicts = 0
    malformed_credential_rows = 0
    action_errors: collections.Counter[str] = collections.Counter()
    error_examples: dict[str, Any] = {}
    grpc_wire_errors: collections.Counter[str] = collections.Counter()
    grpc_wire_roots = 0
    grpc_wire_hash = hashlib.sha256()
    grpc_wire_path = args.output.with_suffix(".wire.jsonl") if public and args.module == "grpc" else None
    if grpc_wire_path is not None:
        with grpc_wire_path.open("x"):
            pass
    s3_wire_errors: collections.Counter[str] = collections.Counter()
    s3_wire_roots = 0
    s3_wire_hash = hashlib.sha256()
    s3_wire_path = (
        args.output.with_suffix(".s3-wire.jsonl")
        if public and args.module == "minio" and args.mode != "detect"
        else None
    )
    if s3_wire_path is not None:
        with s3_wire_path.open("x"):
            pass
    pair_wire_errors: collections.Counter[str] = collections.Counter()
    read_wire_errors: collections.Counter[str] = collections.Counter()
    read_wire_roots = 0
    read_wire_hash = hashlib.sha256()
    read_wire_path = (
        args.output.with_suffix(".read-wire.jsonl")
        if public and (kafka_ui_mode or args.module in {"docker", "spark", "yarn"})
        else None
    )
    if read_wire_path is not None:
        with read_wire_path.open("x"):
            pass
    pair_wire_roots = 0
    pair_wire_hash = hashlib.sha256()
    pair_wire_path = args.output.with_suffix(".pair-wire.jsonl") if public and pair_mode else None
    if pair_wire_path is not None:
        with pair_wire_path.open("x"):
            pass
    coordination_errors: collections.Counter[str] = collections.Counter()
    coordination_roots = 0
    coordination_hash = hashlib.sha256()
    coordination_path = args.output.with_suffix(".coordination-wire.jsonl") if public and coordination_mode else None
    if coordination_path is not None:
        with coordination_path.open("x"):
            pass
    first = None
    start = time.monotonic()

    def on_record(row: dict[str, Any]) -> None:
        nonlocal first, accepted, accepted_targets, negative_target_credential_verdicts, malformed_credential_rows
        nonlocal grpc_wire_roots
        nonlocal s3_wire_roots
        nonlocal pair_wire_roots
        nonlocal coordination_roots
        nonlocal read_wire_roots
        index = int(ipaddress.IPv4Address(str(row["host"]))) - BASE_IP
        primary_port = fixture.closed_port if roles.get(index) == "closed" else fixture.port
        if int(row["port"]) != primary_port:
            return  # A companion on another port is not another logical root.
        index = int(ipaddress.IPv4Address(str(row["host"]))) - BASE_IP
        all_records[index] += 1
        if args.module in {"harbor", "nexus"}:
            from scripts.performance_contracts import vendor_transport_errors

            transport_outcome_errors.update(vendor_transport_errors(row, role=roles.get(index, "foreign")))
        if row.get("error"):
            text = str(row["error"]).lower()
            category = next((key for key in ("refused", "timeout", "protocol", "denied") if key in text), "other")
            if category not in error_examples:
                error_examples[category] = {k: row.get(k) for k in ("error", "stages", "debug_events")}
        if runner._is_detected(AuditRecord.from_mapping(row, module=args.module, service=args.module)):
            seen[index] += 1
            if first is None:
                first = time.monotonic() - start
        from scripts.performance_contracts import credential_summary, wire_token_record

        observation = row
        if read_wire_path is not None:
            from scripts.performance_readonly import docker_inventory_errors, readonly_wire_errors

            wire = fixture.pop_read_calls(index)
            receipt = {"index": index, "record": row, "wire": wire}
            line = (json.dumps(receipt, separators=(",", ":")) + "\n").encode()
            with read_wire_path.open("ab") as sink:
                sink.write(line)
            read_wire_hash.update(line)
            read_wire_roots += 1
            if roles.get(index) == "positive":
                if kafka_readonly_mode:
                    from scripts.performance_kafka_http import record_errors

                    errors = record_errors(
                        row, wire, surface=args.auth_surface, topics=bool(getattr(options, "show_topics", False))
                    )
                elif kafka_ui_mode:
                    from scripts.performance_http_fixtures import profile_pair
                    from scripts.performance_kafka_ui import inventory_errors, wire_kafka_ui_record

                    observation, errors = wire_kafka_ui_record(
                        row,
                        wire,
                        surface=args.auth_surface,
                        origin=f"http://{row['host']}:{fixture.port}",
                        valid_pair=None
                        if args.auth_case == "invalid"
                        else profile_pair(args.module, args.mode, args.auth_case),
                    )
                    if args.mode == "actions" and args.auth_case != "invalid":
                        errors += inventory_errors(
                            row,
                            limited=args.auth_case == "limited",
                            categories=[
                                name
                                for name in ("topics", "brokers", "consumer_groups")
                                if getattr(options, "show_" + name, False)
                            ],
                        )
                elif args.module == "docker":
                    errors = docker_inventory_errors(
                        row,
                        wire,
                        access=getattr(args, "access_case", None) or "open",
                        categories=[
                            name
                            for name in ("containers", "images", "networks", "volumes", "system")
                            if getattr(options, name, False)
                        ],
                    )
                else:
                    from scripts.performance_compute import compute_inventory_errors

                    errors = compute_inventory_errors(
                        args.module,
                        row,
                        wire,
                        access=getattr(args, "access_case", None) or "open",
                        categories=[
                            name
                            for name in (
                                ("workers", "apps") if args.module == "spark" else ("apps", "nodes", "metrics")
                            )
                            if getattr(options, "show_" + name, False)
                        ],
                    )
                read_wire_errors.update(errors)
            else:
                if kafka_ui_mode:
                    from scripts.performance_kafka_ui import exchange_errors

                    errors = exchange_errors(wire)
                    if isinstance(wire, dict) and any(
                        c.get("method") in {"POST", "PUT"} or c.get("headers", {}).get("cookie")
                        for c in wire.get("calls", [])
                        if isinstance(c, dict)
                    ):
                        errors.append("credentials or execution on negative Kafka UI target")
                    read_wire_errors.update(errors)
                else:
                    read_wire_errors.update(readonly_wire_errors(wire))
        if s3_wire_path is not None:
            from scripts.performance_contracts import wire_s3_record
            from scripts.performance_http_fixtures import profile_pair

            s3_wire = fixture.pop_s3_calls(index)
            receipt = {"index": index, **(s3_wire or {"complete": False, "calls": []})}
            line = (json.dumps(receipt, separators=(",", ":")) + "\n").encode()
            with s3_wire_path.open("ab") as sink:
                sink.write(line)
            s3_wire_hash.update(line)
            s3_wire_roots += 1
            if roles.get(index) == "positive":
                observation, s3_error = wire_s3_record(
                    row,
                    s3_wire,
                    single_pair=profile_pair("minio", args.mode, args.auth_case) if args.mode != "defcreds" else None,
                )
                if s3_error:
                    s3_wire_errors[s3_error] += 1
            elif receipt["calls"]:
                s3_wire_errors["signed S3 requests on a negative target"] += 1
        if grpc_wire_path is not None:
            from scripts.performance_contracts import wire_grpc_record

            wire = fixture.pop_grpc_calls(index)
            calls = wire["calls"] if isinstance(wire, dict) else []
            audit = {
                "index": index,
                "complete": bool(isinstance(wire, dict) and wire.get("complete") is True),
                "calls": [
                    {
                        **{key: call[key] for key in ("method", "path", "status")},
                        "authorization_sha256": hashlib.sha256(call["authorization"].encode()).hexdigest()
                        if call["authorization"] is not None
                        else None,
                    }
                    for call in calls
                ],
            }
            if grpc_payload_mode:
                audit = {"index": index, "record": row, "wire": wire}
            line = (json.dumps(audit, separators=(",", ":")) + "\n").encode()
            with grpc_wire_path.open("ab") as sink:
                sink.write(line)
            grpc_wire_hash.update(line)
            grpc_wire_roots += 1
            if roles.get(index) == "positive":
                if grpc_payload_mode:
                    from scripts.performance_grpc import wire_grpc_payload_record
                    from scripts.performance_http_fixtures import profile_pair

                    observation, wire_error = wire_grpc_payload_record(
                        row,
                        wire,
                        valid_pair=None
                        if args.auth_case == "invalid"
                        else profile_pair(args.module, args.mode, args.auth_case),
                        limited=args.auth_case == "limited",
                    )
                    if wire_error:
                        grpc_wire_errors[wire_error] += 1
                elif args.mode == "defcreds":
                    observation, wire_error = wire_grpc_record(row, wire)
                    if wire_error:
                        grpc_wire_errors[wire_error] += 1
                elif not calls:
                    grpc_wire_errors["missing grpc wire calls"] += 1
            elif grpc_payload_mode and calls:
                grpc_wire_errors["gRPC payload RPCs on negative target"] += 1
        if args.mode != "detect" and args.module in TOKEN_PRODUCTS and not pair_mode:
            observation = wire_token_record(
                row,
                received_token=fixture.pop_token_identity(index),
                source="default" if args.mode == "defcreds" else "provided",
                module=args.module,
            )
        if pair_wire_path is not None:
            from scripts.performance_contracts import wire_http_pair_record

            pair_wire = fixture.pop_pair_calls(index)
            proof_fields = (
                "service",
                "status",
                "error",
                "is_gitlab",
                "is_kubeapi",
                "is_rabbitmq",
                "is_harbor",
                "is_nexus",
                "is_portainer",
                "is_elastic",
                "is_etcd",
                "key_count",
                "key_count_by_api",
                "key_count_error",
                "dump_error",
                "keys",
                "key_value_entries",
                "query_key_entry",
                "query_key",
                "dump_keys",
                "vendor",
                "scheme",
                "server_version",
                "auth_probe_status",
                "auth_probe_http_status",
                "credential_write_access",
                "credential_delete_access",
                "credential_probe_index",
                "credential_probe_cleanup",
                "ui_product",
                "ui",
                "rce",
                "rce_probe_performed",
                "is_registry",
                "auth_required",
                "auth_mode",
                "auth_valid",
                "auth_verification_method",
                "credential_verification_status",
                "credentials_source",
                "provided_credentials_ok",
                "provided_username",
                "provided_password",
                "credential_state",
                "credential_username",
                "credential_http_status",
                "effective_username",
                "web_credential_reason",
                "attempted_credentials",
                "credential_attempts",
            )
            receipt = {
                "index": index,
                "wire": pair_wire,
                "record": {key: row[key] for key in proof_fields if key in row},
            }
            line = (json.dumps(receipt, separators=(",", ":")) + "\n").encode()
            with pair_wire_path.open("ab") as sink:
                sink.write(line)
            pair_wire_hash.update(line)
            pair_wire_roots += 1
            if roles.get(index) == "positive":
                observation, pair_error = wire_http_pair_record(row, pair_wire, module=args.module)
                if pair_error:
                    pair_wire_errors[pair_error] += 1
            elif pair_wire and pair_wire.get("calls"):
                pair_wire_errors["pair credentials on negative target"] += 1
        if coordination_path is not None:
            from scripts.performance_contracts import wire_coordination_record

            received = fixture.pop_coordination_calls(index)
            fields = (
                "service",
                "is_zookeeper",
                "is_keeper",
                "auth_required",
                "status",
                "credential_verification_status",
                "credential_verification_path",
                "anonymous_auth_probe_results",
                "provided_credentials",
                "provided_username",
                "provided_password",
                "provided_credentials_ok",
                "credential_verdict",
                "credential_auth_probe_results",
                "attempted_credentials",
                "credential_attempts",
            )
            receipt = {"index": index, "wire": received, "record": {k: row[k] for k in fields if k in row}}
            line = (json.dumps(receipt, separators=(",", ":")) + "\n").encode()
            with coordination_path.open("ab") as sink:
                sink.write(line)
            coordination_hash.update(line)
            coordination_roots += 1
            if roles.get(index) == "positive":
                observation, error = wire_coordination_record(row, received, module=args.module)
                if error:
                    coordination_errors[error] += 1
            elif received and received.get("calls"):
                coordination_errors["coordination calls on a negative target"] += 1
        evidence = credential_summary(observation)
        malformed_credential_rows += evidence["malformed_attempts"]
        if roles.get(index) == "positive":
            credential_counts[evidence["attempts_observed"]] += 1
            credential_totals.update(evidence)
            accepted_targets += int(evidence["accepted_claims"] > 0)
            if verify_credential_catalogue:
                from scripts.performance_contracts import credential_digest, credential_verdict_errors

                digest = credential_digest(observation)
                credential_digests[
                    digest if digest in credential_digests or len(credential_digests) < 32 else "overflow"
                ] += 1
                accepted_identities: set[tuple[Any, Any, Any]] = (
                    {
                        ("admin", "admin", None)
                        if args.mode == "defcreds"
                        else ("profile-user", "profile-password", None)
                    }
                    if args.auth_case != "invalid"
                    else set()
                )
                if grpc_payload_mode and args.auth_case != "invalid":
                    accepted_identities.add((None, None, "admin"))
                if args.module == "proxmox" and args.auth_case != "invalid":
                    from scripts.performance_http_fixtures import profile_pair

                    accepted_identities = {(*profile_pair(args.module, args.mode, args.auth_case), None)}
                if args.module in TOKEN_PRODUCTS and args.auth_case != "invalid" and not pair_mode:
                    from scripts.performance_http_fixtures import profile_token

                    accepted_identities = {
                        (
                            None,
                            None,
                            "root"
                            if args.module == "vault" and args.mode == "defcreds"
                            else profile_token(args.module, args.auth_case),
                        )
                    }
                if not coordination_mode:
                    credential_verdict_failures.update(
                        credential_verdict_errors(observation, accepted_identities=accepted_identities)
                    )
            if args.mode == "actions":
                if kafka_ui_mode:
                    pass  # Full paged inventory and ACL checked with wire evidence above.
                elif grpc_payload_mode:
                    from scripts.performance_grpc import grpc_inventory_errors

                    action_errors.update(
                        grpc_inventory_errors(
                            row, authenticated=args.auth_case != "invalid", limited=args.auth_case == "limited"
                        )
                    )
                elif args.module in {"docker", "spark", "yarn"}:
                    # Full requested values and rights already checked against
                    # received exchanges above, including denied-access cases.
                    pass
                elif (
                    args.module == "airflow"
                    and args.auth_case in {"valid", "limited"}
                    and all(getattr(options, flag, False) for flag in ("show_dags", "show_keys", "show_connections"))
                ):
                    from scripts.performance_contracts import airflow_inventory_errors

                    action_errors.update(airflow_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "etcd" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_etcd import etcd_inventory_errors

                    action_errors.update(
                        etcd_inventory_errors(
                            row,
                            limited=args.auth_case == "limited",
                            selected=getattr(options, "key", None),
                            dump=bool(getattr(options, "dump", False)),
                        )
                    )
                elif args.module == "elastic" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_elastic import elastic_inventory_errors

                    action_errors.update(
                        elastic_inventory_errors(
                            row,
                            limited=args.auth_case == "limited",
                            categories=[
                                flag
                                for flag in ("endpoints", "plugins", "cluster", "users")
                                if getattr(options, "user" if flag == "users" else flag, False)
                            ],
                        )
                    )
                elif args.module == "portainer" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_portainer import portainer_inventory_errors

                    action_errors.update(
                        portainer_inventory_errors(
                            row,
                            limited=args.auth_case == "limited",
                            selected=str(getattr(options, "endpoint", "") or ""),
                            categories=[
                                flag
                                for flag in ("containers", "images", "networks", "volumes", "system")
                                if getattr(options, flag, False)
                            ],
                        )
                    )
                elif args.module == "proxmox" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_contracts import proxmox_inventory_errors

                    action_errors.update(proxmox_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "nexus" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_contracts import nexus_inventory_errors

                    action_errors.update(nexus_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "harbor" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_contracts import harbor_inventory_errors

                    action_errors.update(harbor_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "docker-registry" and args.auth_case in {"valid", "limited"}:
                    from scripts.performance_contracts import registry_inventory_errors

                    action_errors.update(registry_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "grafana" and args.auth_case in {"valid", "limited"} and options.show_datasources:
                    from scripts.performance_contracts import grafana_inventory_errors

                    action_errors.update(grafana_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "keycloak" and args.auth_case in {"valid", "limited"}:
                    from redposture_core.show_limits import show_flag_limit
                    from scripts.performance_keycloak import keycloak_inventory_errors

                    action_errors.update(
                        keycloak_inventory_errors(
                            row,
                            limited=args.auth_case == "limited",
                            realms=list(getattr(options, "realm", None) or ["master"]),
                            limit=show_flag_limit(getattr(options, "show_clients", False)),
                            show_realms=bool(getattr(options, "show_realms", False)),
                            show_clients=bool(getattr(options, "show_clients", False)),
                        )
                    )
                elif args.module == "jenkins" and args.auth_case in {"valid", "limited"} and options.show_jobs:
                    from scripts.performance_contracts import jenkins_inventory_errors

                    action_errors.update(jenkins_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "minio" and args.auth_case in {"valid", "limited"} and options.show_buckets:
                    from scripts.performance_contracts import minio_inventory_errors

                    action_errors.update(minio_inventory_errors(row, limited=args.auth_case == "limited"))
                elif args.module == "rabbitmq" and args.auth_case in {"valid", "limited"} and options.show_queues:
                    from scripts.performance_contracts import rabbitmq_inventory_errors

                    action_errors.update(
                        rabbitmq_inventory_errors(row, limited=args.auth_case == "limited", vhost=options.vhost)
                    )
                elif (
                    args.module in {"vault", "nomad", "jupyter"}
                    and args.auth_case in {"valid", "limited"}
                    and getattr(
                        options,
                        {"vault": "show_mounts", "nomad": "show_jobs", "jupyter": "show_kernels"}[args.module],
                        False,
                    )
                ):
                    from scripts.performance_contracts import token_inventory_errors

                    action_errors.update(token_inventory_errors(args.module, row, limited=args.auth_case == "limited"))
                elif (
                    args.module in {"consul", "kubeapi", "qdrant", "gitlab"}
                    and args.auth_case in {"valid", "limited"}
                    and {"consul": "--services", "kubeapi": "--namespaces", "qdrant": "--dump", "gitlab": "--project"}[
                        args.module
                    ]
                    in args.action
                ):
                    from scripts.performance_contracts import platform_inventory_errors

                    action_errors.update(
                        platform_inventory_errors(args.module, row, limited=args.auth_case == "limited")
                    )
                else:
                    action_errors["no seeded action-result matcher implemented for this case"] += 1
        else:
            # A foreign or unreachable root must not produce credential
            # verdicts, even in valid-token profiles. Skipped cancellation
            # ledger entries are plans, not completed verifier decisions.
            # This observes records; it does not claim wire-level evidence.
            negative_target_credential_verdicts += max(
                evidence["accepted_claims"], evidence["attempts_observed"] - evidence["skipped"]
            )
        if args.auth_case == "invalid":
            accepted += evidence["accepted_claims"]

    options._record_callback = on_record
    runner = AuditCommandRunner(args=options, spec=spec, emit_line=lambda _: None)
    stdout_path = args.output.with_suffix(".stdout." + args.format)
    public_exit = None
    if public:
        # Exercise the actual command entrypoint. In particular, MongoDB and
        # several other modules build their default credential catalogue there,
        # rather than in build_*_plan. Do not imitate or truncate that catalogue.
        inputs = args.output.with_suffix(".targets.txt")
        with inputs.open("x") as handle:
            for port, targets in groups.items():
                for target in targets:
                    handle.write(("http://" if http_target else "") + f"{target.host}:{port}\n")
        options.targets = str(inputs)
        options.output = str(args.output.with_suffix(".results." + args.format)) if args.save else None
        from redposture_core.console import set_console_no_color

        set_console_no_color(True)
    peer_resources = getattr(fixture, "process_resources", lambda: {"fd": 0, "threads": 0})
    initial_peer_resources = peer_resources()
    peak = {
        "fd": fd_count() + initial_peer_resources["fd"],
        "threads": threading.active_count() + initial_peer_resources["threads"],
    }
    peak_families: dict[str, int] = {}
    resource_errors: list[str] = []
    stopping = threading.Event()

    def sample() -> None:
        nonlocal peak_families
        while not stopping.wait(0.02):
            try:
                peer = peer_resources()
            except (OSError, ValueError, RuntimeError) as exc:
                if not resource_errors:
                    resource_errors.append(repr(exc))
                return
            peak["fd"] = max(peak["fd"], fd_count() + peer["fd"])
            threads = threading.enumerate()
            total_threads = len(threads) + peer["threads"]
            if total_threads > peak["threads"]:
                peak["threads"] = total_threads
                peak_families = dict(collections.Counter(thread_family(thread.name) for thread in threads))
                if peer["threads"]:
                    peak_families["fixture_process"] = peer["threads"]

    sampler = threading.Thread(target=sample, name="module-profile-sampler")
    sampler.start()
    cpu_start, start = time.process_time(), time.monotonic()
    admission_probe = SchedulerAdmissionProbe(AsyncDetectScheduler)
    admission_probe.__enter__()
    try:
        if public:
            configure_profile_debug(options, public=True)
            from redposture_core.logger import AttemptLogger
            from redposture_core.module_registry import COMMAND_SPECS_BY_NAME, resolve_command_runner

            logger = AttemptLogger()
            with stdout_path.open("x") as stdout, args.output.with_suffix(".stderr.log").open("x") as stderr:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    public_exit = int(resolve_command_runner(COMMAND_SPECS_BY_NAME[args.module])(options, logger))
            record_count = sum(all_records.values())
        else:
            debug_stream = (
                args.output.with_suffix(".debug.log").open("x") if args.debug else contextlib.nullcontext(None)
            )
            with debug_stream as debug_sink:
                configure_profile_debug(options, public=False, sink=debug_sink)
                result = runner.run_plan(plan)
                record_count = result.record_count
        wall, cpu = time.monotonic() - start, time.process_time() - cpu_start
    finally:
        try:
            stopping.set()
            sampler.join(2)
            fixture.close()
        finally:
            admission_probe.__exit__(None, None, None)
    fixture_resources = getattr(fixture, "resource_summary", lambda: {"cpu_seconds": 0, "peak_rss_bytes": 0})()
    from scripts.performance_contracts import public_summary_errors

    summary_errors = public_summary_errors(stdout_path, roles) if public and args.format == "json" else []
    model_summary = getattr(fixture, "model_summary", lambda: None)()
    model_ok = model_summary is None or all(
        model_summary.get(key, 1) == 0 for key in ("active_indices", "unexpected_mutations", "overflows")
    )
    if admission_probe.selected_detect_workers() is None:
        resource_errors.append("actual scheduler capacity observation incomplete or inconsistent")
    deadline = time.monotonic() + 3
    while threading.active_count() > start_threads and time.monotonic() < deadline:
        time.sleep(0.02)
    missing, extra = sorted(expected - set(seen)), sorted(set(seen) - expected)
    grpc_wire_summary = fixture.grpc_wire_summary()
    s3_wire_summary = fixture.s3_wire_summary()
    pair_wire_summary = getattr(fixture, "pair_wire_summary", lambda: None)()
    coordination_summary = getattr(fixture, "coordination_wire_summary", lambda: None)()
    read_summary = getattr(fixture, "read_wire_summary", lambda: None)()
    read_wire_ok = read_wire_path is None or (
        isinstance(read_summary, dict)
        and not any(read_summary.get(key, 1) for key in ("overflow", "malformed", "pending_calls", "pending_targets"))
        and not read_summary.get("storage_errors", 0)
        and (not kafka_ui_mode or read_summary.get("temporary_storage_removed") == 1)
        and not read_wire_errors
        and read_wire_roots == len(roles)
    )
    coordination_ok = coordination_path is None or (
        isinstance(coordination_summary, dict)
        and not any(
            coordination_summary.get(key, 1) for key in ("overflow", "malformed", "pending_calls", "pending_targets")
        )
        and not coordination_errors
        and coordination_roots == len(roles)
    )
    pair_wire_ok = pair_wire_path is None or (
        isinstance(pair_wire_summary, dict)
        and not any(
            pair_wire_summary.get(key, 1) for key in ("overflow", "malformed", "pending_calls", "pending_targets")
        )
        and not pair_wire_errors
        and pair_wire_roots == len(roles)
    )
    s3_wire_ok = s3_wire_path is None or (
        isinstance(s3_wire_summary, dict)
        and not any(
            s3_wire_summary.get(key, 1) for key in ("overflow", "malformed", "pending_calls", "pending_targets")
        )
        and not s3_wire_errors
        and s3_wire_roots == len(roles)
    )
    grpc_wire_ok = grpc_wire_path is None or (
        isinstance(grpc_wire_summary, dict)
        and not any(
            grpc_wire_summary.get(key, 1) for key in ("overflow", "malformed", "pending_calls", "pending_targets")
        )
        and not grpc_wire_errors
        and grpc_wire_roots == len(roles)
    )
    duplicates = sum(max(0, n - 1) for n in all_records.values())
    fd_after, threads_after = fd_count(), threading.active_count()
    cleanup = fd_after <= start_fd + 2 and threads_after <= start_threads
    exact = not missing and not extra and not duplicates and set(all_records) == set(roles)
    credential_expectation = None
    expected_digest: str | None = None
    credential_catalogue_errors = 0
    credential_quality = True
    if verify_credential_catalogue:
        prepared_plan = getattr(stage, f"build_{package}_plan")(options)
        from scripts.performance_contracts import identity_digest

        expected_digest = identity_digest(expected_credential_identities(args.module, options, prepared_plan))
        credential_catalogue_errors = sum(
            count for digest, count in credential_digests.items() if digest != expected_digest
        )
        credential_expectation = len(prepared_plan.credential_runs)
        credential_quality = (
            bool(credential_expectation)
            and all(count == credential_expectation for count in credential_counts)
            and sum(credential_counts.values()) == len(expected)
            and not credential_catalogue_errors
            and not credential_totals["duplicate_attempts"]
            and not credential_verdict_failures
        )
        if args.auth_case != "invalid":
            credential_quality = credential_quality and accepted_targets == len(expected)
        if coordination_mode:
            credential_quality = (
                credential_quality
                and coordination_ok
                and credential_totals["unverified"] == credential_expectation * len(expected)
                and credential_totals["invalid"]
                == credential_totals["accepted_claims"]
                == credential_totals["skipped"]
                == 0
            )
    fd_types: collections.Counter[str] = collections.Counter()
    if not cleanup:
        for entry in Path("/proc/self/fd").iterdir():
            try:
                kind = os.readlink(entry)
            except OSError:
                continue
            fd_types[kind.split(":", 1)[0] if ":" in kind else "file"] += 1
    # Diagnostic only: cleanup is judged before GC. A cycle holding sockets is
    # not silently counted as successful explicit close.
    import gc

    collected = gc.collect() if not cleanup else 0
    fd_after_gc = fd_count()

    return {
        "module": args.module,
        "mode": args.mode,
        "model": args.model,
        "engine": args.engine,
        "engine_is_request": True,
        "engine_note": "runtime keeps its small-batch sync gate (<32 roots) and compatibility fallback",
        "target_style": args.target_style,
        "auth_case": args.auth_case,
        "auth_surface": args.auth_surface,
        "fixture_access_case": (getattr(args, "access_case", None) or "open")
        if read_wire_path is not None and not kafka_ui_mode
        else None,
        "credential_scenario_applicable": verify_credential_catalogue,
        "read_wire_summary": read_summary,
        "read_wire_storage_policy": "sqlite_pending_disk256MiB_cache512KiB_perroot8MiB"
        if kafka_ui_mode
        else "bounded_memory"
        if read_wire_path is not None
        else None,
        "read_wire_errors": dict(read_wire_errors),
        "read_wire_evidence": {
            "path": read_wire_path.name,
            "roots": read_wire_roots,
            "sha256": read_wire_hash.hexdigest(),
        }
        if read_wire_path is not None
        else None,
        "credential_verdict_model": "not_applicable_readonly_api"
        if kafka_readonly_mode
        else "form_session_identity"
        if kafka_ui_mode
        else "not_applicable_readonly_api"
        if read_wire_path is not None
        else "digest_ack_noauth_unverified"
        if coordination_mode
        else "explicit_valid_invalid",
        "actions": list(args.action),
        "source_sha256": source_hash(source),
        "coordination_wire_summary": coordination_summary,
        "coordination_wire_errors": dict(coordination_errors),
        "coordination_wire_evidence": {
            "path": coordination_path.name,
            "roots": coordination_roots,
            "sha256": coordination_hash.hexdigest(),
        }
        if coordination_path is not None
        else None,
        "http_pair_wire_summary": pair_wire_summary,
        "http_pair_wire_errors": dict(pair_wire_errors),
        "http_pair_wire_evidence": {
            "path": pair_wire_path.name,
            "roots": pair_wire_roots,
            "sha256": pair_wire_hash.hexdigest(),
        }
        if pair_wire_path is not None
        else None,
        "profile_sha256": profile_hash(),
        "environment": args._profile_environment["details"],
        "environment_sha256": args._profile_environment["sha256"],
        "container_image_id": None,
        "seed": args.seed,
        "targets": args.targets,
        "timeout": args.timeout,
        "delay_ms": args.delay_ms,
        "retries": 0,
        "detect_concurrency": admission_probe.selected_detect_workers(),
        "requested_detect_concurrency": None if args.auto_concurrency else args.concurrency,
        "detect_concurrency_source": "actual_scheduler_constructor",
        "detect_policy": "automatic" if args.auto_concurrency else "explicit",
        "scheduler_admission": admission_probe.snapshot(),
        "http_peer": args.http_peer
        if is_http_profile(fixture.module, args.auth_surface)
        else "native_" + getattr(args, "native_peer", "threaded"),
        "native_peer": getattr(args, "native_peer", "threaded")
        if not is_http_profile(fixture.module, args.auth_surface)
        else None,
        "deep_workers": args.workers,
        "debug": args.debug,
        "debug_io_policy": "public CLI owns stdout/stderr"
        if public
        else "owned flushed file"
        if args.debug
        else "disabled",
        "measured_output_files": profile_output_files(
            [stdout_path, args.output.with_suffix(".stderr.log"), args.output.with_suffix(".debug.log")]
        ),
        "format": args.format,
        "save": args.save,
        "fixture": "protocol emulation, not a real product",
        "fixture_process_included_in_metrics": True,
        "wall_seconds": wall,
        "cpu_seconds": cpu + fixture_resources["cpu_seconds"],
        "main_cpu_seconds": cpu,
        "fixture_cpu_seconds": fixture_resources["cpu_seconds"],
        "throughput": args.targets / wall,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        + fixture_resources["peak_rss_bytes"],
        "fixture_separate_process": hasattr(fixture, "process_resources"),
        "resource_errors": resource_errors,
        "fd_peak": peak["fd"],
        "fd_before": start_fd,
        "fd_after": fd_after,
        "threads_before": start_threads,
        "threads_after": threads_after,
        "remaining_thread_names": [t.name for t in threading.enumerate()] if not cleanup else [],
        "threads_peak": peak["threads"],
        "threads_at_sampled_peak": peak_families,
        "resource_peak_method": (
            "RSS sum of main/fixture OS high-water marks (conservative, not necessarily simultaneous); "
            "combined FD/threads sampled every 20 ms; child CPU included; resource-tracker process excluded"
            if hasattr(fixture, "process_resources")
            else "RSS OS high-water; FD/threads sampled every 20 ms; fixture included"
        ),
        "first_finding_seconds": first,
        "requests": dict(fixture.stats),
        "http_route_counts": fixture.routes.snapshot(),
        "grpc_wire_summary": grpc_wire_summary,
        "s3_wire_summary": s3_wire_summary,
        "s3_wire_errors": dict(s3_wire_errors),
        "s3_wire_evidence": {
            "path": s3_wire_path.name,
            "sha256": s3_wire_hash.hexdigest(),
            "roots": s3_wire_roots,
            "note": "Complete received signed S3 root GETs. Retained canonical headers/signature contain no secret; attribution requires independent HMAC verification. Public product records remain unchanged.",
        }
        if s3_wire_path is not None
        else None,
        "grpc_wire_errors": dict(grpc_wire_errors),
        "grpc_wire_evidence": {
            "path": grpc_wire_path.name,
            "sha256": grpc_wire_hash.hexdigest(),
            "roots": grpc_wire_roots,
            "note": "Complete received RPC headers; response receipt independently confirmed by product verdict. Authorization hashed, no expected identity inserted.",
        }
        if grpc_wire_path is not None
        else None,
        "native_message_count": fixture.stats.get("native_messages"),
        "native_message_definition": "complete request frames counted by the shared wire program; implementation-only replies do not invent command counts"
        if "native_messages" in fixture.stats
        else None,
        "fallbacks": runner._fallback_stats.snapshot() if not public else None,
        "fallback_surfaces": (
            runner._fallback_stats.surface_snapshot()
            if not public and hasattr(runner._fallback_stats, "surface_snapshot")
            else None
        ),
        "fallback_surface_note": "debug/observer only; mixed means an unsplit backend/UI tree; sync-worker time is aggregate",
        "runtime_diagnostics": options._runtime_observer.snapshot() if hasattr(options, "_runtime_observer") else None,
        "debug_sink": "public CLI owns stdout/stderr" if public else "owned flushed file" if args.debug else "disabled",
        "error_examples": error_examples,
        "invalid_credentials_accepted": accepted,
        "negative_target_credential_verdicts": negative_target_credential_verdicts,
        "malformed_credential_rows": malformed_credential_rows,
        "credential_expectation_per_positive": credential_expectation,
        "credential_count_histogram": dict(credential_counts),
        "credential_catalogue_errors": credential_catalogue_errors,
        "credential_identity_digests": dict(credential_digests),
        "credential_expected_sha256": expected_digest,
        "credential_observations": dict(credential_totals),
        "credential_verdict_errors": dict(credential_verdict_failures),
        "credential_quality": "NOT_APPLICABLE"
        if read_wire_path is not None and not verify_credential_catalogue
        else "PASS"
        if credential_quality
        else "FAIL",
        "accepted_targets": accepted_targets,
        "action_errors": dict(action_errors),
        "transport_outcome_errors": dict(transport_outcome_errors),
        "missing": missing,
        "extra": extra,
        "duplicates": duplicates,
        "records": record_count,
        "public_command_entrypoint": public,
        "public_exit": public_exit,
        "public_summary_errors": summary_errors,
        "public_summary_quality": "FAIL"
        if summary_errors
        else "PASS"
        if public and args.format == "json"
        else "NOT_APPLICABLE",
        "result_sha256": hashlib.sha256(json.dumps(sorted(seen)).encode()).hexdigest(),
        "cleanup": "PASS" if cleanup else "FAIL",
        "fd_types_after": dict(fd_types),
        "gc_collected": collected,
        "fd_after_gc": fd_after_gc,
        "fixture_errors": fixture.errors,
        "fixture_model_summary": model_summary,
        "quality": "PASS"
        if exact
        and model_ok
        and cleanup
        and credential_quality
        and not action_errors
        and not transport_outcome_errors
        and (not (kafka_ui_mode or args.module in {"nexus", "harbor"}) or fixture.routes.snapshot()["complete"])
        and not fixture.errors
        and not accepted
        and not negative_target_credential_verdicts
        and not malformed_credential_rows
        and not summary_errors
        and not resource_errors
        and grpc_wire_ok
        and s3_wire_ok
        and pair_wire_ok
        and read_wire_ok
        and coordination_ok
        and public_exit in {None, 0, 1}
        else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module")
    parser.add_argument(
        "--inventory", action="store_true", help="Write current module/UI/action coverage matrix without network IO"
    )
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--model", choices=MODELS, default="mixed")
    parser.add_argument("--mode", choices=("detect", "run", "credentials", "defcreds", "actions"), default="detect")
    parser.add_argument(
        "--access-case",
        choices=("open", "limited", "denied"),
        default=None,
        help="Explicit read-only Docker/Spark/YARN API access model; not a credential result",
    )
    parser.add_argument("--auth-case", choices=("invalid", "valid", "limited"), default="invalid")
    parser.add_argument(
        "--auth-surface",
        choices=AUTH_SURFACE_CHOICES,
        default="default",
        help="Explicit identity API, web/Basic proxy or inconclusive digest ACK/ACL control",
    )
    parser.add_argument(
        "--action", action="append", default=[], help="Explicit module argument; repeat as --action=--show-jobs"
    )
    parser.add_argument("--engine", choices=("native", "sync"), default="native")
    parser.add_argument("--target-style", choices=("auto", "http"), default="auto")
    parser.add_argument("--seed", type=int, default=20261107)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--auto-concurrency", action="store_true", help="Use the product's unmodified startup scale")
    parser.add_argument("--http-peer", choices=("async", "threaded", "process"), default="async")
    parser.add_argument("--native-peer", choices=("threaded", "async", "process"), default="threaded")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--delay-ms", type=float, default=2)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--format", choices=("txt", "json"), default="txt")
    parser.add_argument("--container-image")
    args = parser.parse_args()
    if args.inventory:
        if args.output.exists():
            parser.error("output already exists")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(inventory(args.source), indent=2) + "\n")
        return 0
    if not args.module:
        parser.error("--module is required for a measurement")
    if args.mode == "detect" and args.auth_case != "invalid":
        parser.error("detect-only mode does not test valid/limited authentication; choose credentials or actions")
    if args.access_case is not None and (
        args.module not in {"docker", "spark", "yarn"} or args.mode not in {"run", "actions"}
    ):
        parser.error("access-case requires Docker/Spark/YARN run/actions; credential/mTLS scenarios are separate")
    if args.module == "spark" and args.access_case == "denied":
        parser.error("generic denied Spark API is not product proof; use a separate negative control")
    if args.auth_case != "invalid" and args.module not in {
        "minio",
        "grafana",
        "airflow",
        "jenkins",
        "vault",
        "nomad",
        "jupyter",
        "keycloak",
        "consul",
        "kubeapi",
        "qdrant",
        "gitlab",
        "docker-registry",
        "proxmox",
        "rabbitmq",
        "harbor",
        "nexus",
        "portainer",
        "elastic",
        "etcd",
        "grpc",
        "kafka",
    }:
        parser.error(
            "valid/limited fixtures require a seeded HTTP auth product; unsupported products must stay explicit"
        )
    from scripts.performance_kafka_http import SURFACES as KAFKA_HTTP_SURFACES

    if args.auth_surface in KAFKA_HTTP_SURFACES and (
        args.module != "kafka" or args.mode not in {"detect", "run", "actions"} or args.auth_case != "invalid"
    ):
        parser.error(
            "read-only Kafka HTTP surfaces support detect/run/actions only; credential verification is not implemented by the product"
        )
    if args.auth_surface in KAFKA_HTTP_SURFACES and args.mode == "actions" and args.action != ["--show-topics"]:
        parser.error(
            "read-only Kafka HTTP action profile supports only --show-topics; other actions need independent seeded matchers"
        )
    if (
        args.auth_surface != "default"
        and args.auth_surface not in KAFKA_HTTP_SURFACES
        and (
            args.mode
            not in (
                {"detect", "run", "credentials", "defcreds", "actions"}
                if args.auth_surface in {"provectus-ui", "kafbat-ui"}
                else {"credentials", "defcreds", "actions"}
                if args.auth_surface in {"grpc-auth", "grpc-bearer", "provectus-ui", "kafbat-ui"}
                else {"credentials", "defcreds"}
            )
            or not (
                args.module == "grafana"
                and args.auth_surface
                not in {
                    "web-login",
                    "basic-proxy",
                    "digest-acl",
                    "grpc-auth",
                    "grpc-bearer",
                    "provectus-ui",
                    "kafbat-ui",
                }
                or {"gitlab": "web-login", "kubeapi": "basic-proxy"}.get(args.module) == args.auth_surface
                or args.module in {"zookeeper", "keeper"}
                and args.auth_surface == "digest-acl"
                or args.module == "grpc"
                and args.auth_surface in {"grpc-auth", "grpc-bearer"}
                or args.module == "kafka"
                and args.auth_surface in {"provectus-ui", "kafbat-ui"}
            )
        )
    ):
        parser.error(
            "explicit auth surface requires a matching module and credentials/defcreds or supported actions mode"
        )
    if args.module == "grpc" and args.auth_case != "invalid" and args.auth_surface not in {"grpc-auth", "grpc-bearer"}:
        parser.error("valid/limited gRPC requires explicit full-payload auth surface")
    if (
        args.module == "kafka"
        and args.auth_case != "invalid"
        and args.auth_surface not in {"provectus-ui", "kafbat-ui"}
    ):
        parser.error("valid/limited Kafka UI requires an explicit HTTP surface; native SASL has separate controls")
    if (
        args.module == "grpc"
        and args.auth_surface in {"grpc-auth", "grpc-bearer"}
        and args.native_peer not in {"async", "process"}
    ):
        parser.error("full-payload gRPC requires the owned async/process native peer")
    if args.mode == "actions" and not args.action:
        parser.error("actions mode requires explicit --action arguments")
    case_roles(args.targets, args.model, args.seed)
    if args.timeout <= 0 or args.delay_ms < 0 or args.workers < 1 or args.concurrency < 1:
        parser.error("positive timeout/workers/concurrency and nonnegative delay required")
    if args.output.exists():
        parser.error("output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.container_image:
        image_id = subprocess.check_output(
            ["docker", "image", "inspect", "--format", "{{.Id}}", args.container_image], text=True, timeout=30
        ).strip()
        if not image_id.startswith("sha256:"):
            raise ValueError("cannot pin the local measurement image")
        name = "redposture-module-profile-" + uuid.uuid4().hex
        lease_path = args.output.with_suffix(".container.json")
        lease = {"name": name, "image_id": image_id, "output": str(args.output.resolve()), "cleanup": "PENDING"}
        lease_path.write_text(json.dumps(lease, indent=2) + "\n")
        command = [
            "docker",
            "run",
            "--pull",
            "never",
            "--rm",
            "--name",
            name,
            "--label",
            "redposture.qa.profile-output=" + str(args.output.resolve()),
            "--network",
            "none",
            "--cpus",
            "2",
            "--memory",
            "1g",
            "--pids-limit",
            "512",
            "--mount",
            f"type=bind,src={args.source.resolve()},dst=/profile-source,readonly",
            "--mount",
            f"type=bind,src={ROOT},dst=/profile-tools,readonly",
            "--mount",
            f"type=bind,src={args.output.parent.resolve()},dst=/profile-output",
            image_id,
            "python",
            "/profile-tools/scripts/profile_module_performance.py",
            "--source",
            "/profile-source",
            "--output",
            "/profile-output/" + args.output.name,
            "--module",
            args.module,
            "--targets",
            str(args.targets),
            "--model",
            args.model,
            "--mode",
            args.mode,
            "--auth-case",
            args.auth_case,
            "--auth-surface",
            args.auth_surface,
            "--engine",
            args.engine,
            "--seed",
            str(args.seed),
            "--target-style",
            args.target_style,
            "--concurrency",
            str(args.concurrency),
            "--http-peer",
            args.http_peer,
            "--native-peer",
            args.native_peer,
            "--workers",
            str(args.workers),
            "--timeout",
            str(args.timeout),
            "--delay-ms",
            str(args.delay_ms),
            "--format",
            args.format,
        ]
        for flag in ("debug", "save", "auto_concurrency"):
            if getattr(args, flag):
                command.append("--" + flag.replace("_", "-"))
        if args.access_case is not None:
            command.extend(["--access-case", args.access_case])
        for action in args.action:
            command.append("--action=" + action)
        try:
            completed = subprocess.run(command, timeout=600, check=False)
        finally:
            cleanup = subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, timeout=30, check=False)
            lease["cleanup"] = (
                "PASS" if cleanup.returncode == 0 or b"no such container" in cleanup.stderr.lower() else "FAIL"
            )
            lease_path.write_text(json.dumps(lease, indent=2) + "\n")
            if lease["cleanup"] != "PASS":
                raise RuntimeError("profile container cleanup failed; do not start another sample")
        if not args.output.exists():
            raise RuntimeError(f"measurement exited {completed.returncode} without artifact")
        result = json.loads(args.output.read_text())
        result["container_image_id"] = image_id
        result["container_limits"] = {"cpus": 2, "memory_bytes": 1024**3, "pids": 512, "network": "none"}
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        return completed.returncode
    save_instrument_snapshot(args.output.parent)
    result = measure(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("module", "mode", "model", "quality", "wall_seconds")}))
    return 0 if result["quality"] in {"PASS", "NOT_APPLICABLE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
