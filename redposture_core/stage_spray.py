"""Bounded, credential-only verification on confirmed audit products."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from itertools import groupby
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .audit_models import AuditRecord
from .cli_args import build_parser
from .console import Console
from .module_registry import AUDIT_MODULE_NAMES
from .network_proxy import RuntimeNetworkConfig
from .rendering import BooleanColorRule, collect_boolean_spans, format_report_line_for_console
from .scheduler import BoundedScheduler
from .spray_render import render_spray_line
from .stage_runtime import (
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    render_record_with_module,
)
from .targeting import TargetParsePolicy, stream_scan_target_specs

_PAIR_MODULES = frozenset(AUDIT_MODULE_NAMES) - {"docker", "keycloak", "qdrant"}
_TOKEN_MODULES = frozenset(
    {
        "consul",
        "docker-registry",
        "harbor",
        "nexus",
        "elastic",
        "gitlab",
        "grafana",
        "grpc",
        "keycloak",
        "kubeapi",
        "proxmox",
        "qdrant",
    }
)
# These keys are auth/transport settings only.  Never copy arbitrary JSON keys
# onto a module Namespace: that would expose inventory or mutating operations.
_COMMON_CONFIG = frozenset({"tls", "secure", "ca_file", "tls_ca", "tls_cert", "tls_key", "cert_file", "key_file"})
_MODULE_CONFIG: dict[str, frozenset[str]] = {
    "keycloak": frozenset({"realm"}),
    "oracle": frozenset({"sid", "service", "protocol", "wallet", "ssl_server_dn"}),
    "kafka": frozenset({"plaintext", "tls_server_name", "sasl_mechanism", "security_protocol"}),
    "mongodb": frozenset({"auth_db"}),
    "zookeeper": frozenset({"znode"}),
    "keeper": frozenset({"znode"}),
    "grpc": frozenset({"plaintext", "tls_server_name"}),
    "proxmox": frozenset({"realm"}),
}
_LOCK_MARKERS = ("captcha", "account locked", "account has been locked", "too many requests", "too many login attempts")
_SPRAY_READ_ONLY_DATA_MODULES = frozenset({"grafana", "redis"})
_DISPLAY_NAMES = {
    "clickhouse": "ClickHouse",
    "docker": "Docker Engine",
    "docker-registry": "Docker Registry",
    "elastic": "Elasticsearch/OpenSearch",
    "etcd": "etcd",
    "gitlab": "GitLab",
    "grafana": "Grafana",
    "grpc": "gRPC",
    "jenkins": "Jenkins",
    "keeper": "ClickHouse Keeper",
    "kubeapi": "Kubernetes API",
    "minio": "MinIO",
    "mongodb": "MongoDB",
    "postgres": "PostgreSQL",
    "qdrant": "Qdrant",
    "rabbitmq": "RabbitMQ",
    "zookeeper": "ZooKeeper",
}


@dataclass(frozen=True)
class Candidate:
    kind: str
    username: str | None = None
    password: str | None = None
    token: str | None = None

    @property
    def display(self) -> str:
        return (self.token or "") if self.kind == "token" else f"{self.username}:{self.password}"

    @property
    def account(self) -> str:
        return self.username or hashlib.sha256((self.token or "").encode()).hexdigest()


def _read_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig") as stream:
        return [line.rstrip("\r\n") for line in stream if line.rstrip("\r\n") and not line.startswith("#")]


def _source_file(value: str) -> Path | None:
    """Accept a literal, an existing legacy file, or an explicit @file."""
    if value.startswith("@"):
        path = Path(value[1:])
        if not path.is_file():
            raise ValueError(f"credential source file does not exist: {path}")
        return path
    try:
        path = Path(value)
        return path if path.is_file() else None
    except (OSError, ValueError):
        # An unusually long or non-path credential is still a literal.
        return None


def _source_values(value: str, *, passwords: bool = False) -> list[str]:
    path = _source_file(value)
    if path is None:
        return [value]
    if not passwords:
        return _read_lines(str(path))
    with path.open(encoding="utf-8-sig") as stream:
        return [line.rstrip("\r\n") for line in stream if not line.startswith("#")]


def load_candidates(args: Any) -> tuple[Candidate, ...]:
    if bool(args.users) != bool(args.passwords):
        raise ValueError("--users and --passwords must be supplied together")
    if not any((args.pairs, args.users, args.tokens)):
        raise ValueError("at least one of --pairs, --users/--passwords or --tokens is required")
    values: list[Candidate] = []
    if args.pairs:
        for line in _read_lines(args.pairs):
            if ":" not in line:
                raise ValueError("--pairs requires user:password on each line")
            user, password = line.split(":", 1)
            if not user:
                raise ValueError("--pairs contains an empty username")
            values.append(Candidate("pair", user, password))
    if args.users:
        users = _source_values(args.users)
        passwords = _source_values(args.passwords, passwords=True)
        for password in passwords:
            for user in users:
                values.append(Candidate("pair", user, password))
    if args.tokens:
        values.extend(Candidate("token", token=value) for value in _read_lines(args.tokens))
    return tuple(dict.fromkeys(values))


def _modules(raw: str) -> tuple[str, ...]:
    if raw.strip().lower() == "all":
        return AUDIT_MODULE_NAMES
    names = tuple(dict.fromkeys(item.strip().lower() for item in raw.split(",") if item.strip()))
    if not names or any(name not in AUDIT_MODULE_NAMES for name in names):
        raise ValueError(f"--modules must be all or a comma-separated subset of: {', '.join(AUDIT_MODULE_NAMES)}")
    return names


def _config(path: str | None, modules: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    if not path:
        return {}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or any(name not in modules for name in value):
        raise ValueError("--module-config must map selected module names to settings")
    for name, settings in value.items():
        if not isinstance(settings, dict):
            raise ValueError(f"--module-config {name} must be an object")
        invalid = set(settings) - (_COMMON_CONFIG | _MODULE_CONFIG.get(name, frozenset()))
        if invalid:
            raise ValueError(f"--module-config {name} rejects: {', '.join(sorted(invalid))}")
        for key, item in settings.items():
            if key in {"tls", "secure", "plaintext"}:
                if not isinstance(item, bool):
                    raise ValueError(f"--module-config {name}.{key} must be a boolean")
            elif not isinstance(item, str) or not item:
                raise ValueError(f"--module-config {name}.{key} must be a nonempty string")
    return value


def _input_fingerprint(args: Any, modules: tuple[str, ...], config: dict[str, Any]) -> str:
    files: dict[str, str] = {}
    literals: dict[str, str] = {}
    for name in ("targets", "pairs", "users", "passwords", "tokens", "module_config"):
        value = getattr(args, name, None)
        if value:
            if name in {"users", "passwords"}:
                path = _source_file(str(value))
                if path is None:
                    literals[name] = hashlib.sha256(str(value).encode()).hexdigest()
                    continue
            else:
                path = Path(str(value))
            if path.is_file():
                files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    payload = {
        "targets": args.targets,
        "modules": modules,
        "files": files,
        "literals": literals,
        "config": config,
        "timeout": args.timeout,
        "retries": args.retries,
        "workers": getattr(args, "workers", None),
        "output_format": getattr(args, "output_format", None),
        "origin_rate": args.origin_rate,
        "account_interval": args.account_interval,
        "proxy": args.proxy,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _private_file(path: str) -> None:
    parent = Path(path).expanduser().parent
    parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


class AttemptJournal:
    def __init__(self, path: str, fingerprint: str, resume: bool) -> None:
        existed = Path(path).exists()
        if resume and not existed:
            raise ValueError("--resume requires an existing --checkpoint")
        if existed and not resume:
            raise ValueError("checkpoint already exists; use --resume or another path")
        _private_file(path)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        self.closed = False
        self.on_result: Any = None
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, module TEXT NOT NULL, host TEXT NOT NULL, "
            "port INTEGER NOT NULL, candidate INTEGER, status TEXT NOT NULL, evidence TEXT NOT NULL, "
            "detail TEXT NOT NULL DEFAULT '')"
        )
        if not any(row[1] == "detail" for row in self.db.execute("PRAGMA table_info(results)")):
            self.db.execute("ALTER TABLE results ADD COLUMN detail TEXT NOT NULL DEFAULT ''")
        previous = self.db.execute("SELECT value FROM meta WHERE key='fingerprint'").fetchone()
        if previous and previous[0] != fingerprint:
            self.db.close()
            raise ValueError("checkpoint inputs or settings changed; refusing resume")
        if not previous:
            self.db.execute("INSERT INTO meta VALUES ('fingerprint', ?)", (fingerprint,))
            self.db.commit()
        elif resume:
            self.db.execute(
                "UPDATE results SET status='inconclusive', evidence='request began before interruption; not retried' "
                "WHERE status='started'"
            )
            self.db.commit()

    def get(self, key: str) -> tuple[str, str] | None:
        with self.lock:
            if self.closed:
                return None
            row = self.db.execute("SELECT status, evidence FROM results WHERE id=?", (key,)).fetchone()
            return (row[0], row[1]) if row else None

    def put(
        self,
        key: str,
        module: str,
        host: str,
        port: int,
        candidate: int | None,
        status: str,
        evidence: str,
        detail: str = "",
    ) -> None:
        with self.lock:
            if self.closed:
                return
            self.db.execute(
                "INSERT OR REPLACE INTO results (id, module, host, port, candidate, status, evidence, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (key, module, host, port, candidate, status, evidence, detail),
            )
            self.db.commit()
            if self.on_result is not None:
                self.on_result(module, host, port, candidate, status, evidence, detail)

    def rows(self) -> list[tuple[str, str, int, int | None, str, str, str]]:
        with self.lock:
            return self.db.execute(
                "SELECT module, host, port, candidate, status, evidence, detail FROM results ORDER BY rowid"
            ).fetchall()

    def close(self) -> None:
        with self.lock:
            if not self.closed:
                self.closed = True
                self.db.close()


class RateGate:
    def __init__(self, origin_rate: float, account_interval: float) -> None:
        self.origin_interval = 1 / origin_rate
        self.account_interval = account_interval
        self.next_origin: dict[str, float] = {}
        self.next_account: dict[tuple[str, str], float] = {}
        self.stopped: dict[str, str] = {}
        self.lock = threading.Lock()
        self.cancelled = threading.Event()

    def reserve(self, origin: str, account: str) -> tuple[bool, str | float]:
        with self.lock:
            if self.cancelled.is_set():
                return False, "interrupted"
            if origin in self.stopped:
                return False, self.stopped[origin]
            now = time.monotonic()
            start = max(now, self.next_origin.get(origin, now), self.next_account.get((origin, account), now))
            self.next_origin[origin] = start + self.origin_interval
            self.next_account[(origin, account)] = start + self.account_interval
            return True, max(0.0, start - now)

    def stop(self, origin: str, reason: str) -> None:
        with self.lock:
            self.stopped[origin] = reason

    def cancel(self) -> None:
        self.cancelled.set()

    def paused(self, delay: float) -> bool:
        return not self.cancelled.wait(delay)


def _clean(value: Any) -> str:
    return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in str(value))


def classify(record: AuditRecord, credential: AuditCredentialRun, runner: AuditCommandRunner) -> tuple[str, str]:
    payload = record.to_dict()
    status = str(record.status or "").lower()
    detail = " ".join(
        str(payload.get(name) or "")
        for name in (
            "error",
            "auth_error",
            "login_error",
            "auth_error_detail",
            "credential_verification_reason",
            "reason",
        )
    ).lower()
    if (
        status in {"rate_limited", "account_locked", "locked_out", "captcha"}
        or any(
            str(payload.get(name) or "") == "429"
            for name in ("http_status", "auth_http_status", "auth_probe_http_status", "auth_probe_status")
        )
        or any(marker in detail for marker in _LOCK_MARKERS)
    ):
        return "rate_limited", "server rate limit, CAPTCHA, or account lockout"
    if status in {"access_denied", "forbidden"} and (
        payload.get("identity_verified") is True or record.extra.get("auth_valid") is True
    ):
        return "access_denied", "identity verified; resource denied"
    # A module-specific credential gate is the authoritative positive proof.
    accepted, why = runner._credential_gate(credential, record)
    if accepted and (
        record.extra.get("provided_credentials_ok") is True
        or record.extra.get("auth_valid") is True
        or record.extra.get("token_valid") is True
        or status in {"valid_credentials", "auth_valid"}
    ):
        return "valid", why
    if (
        record.extra.get("provided_credentials_ok") is False
        or status == "invalid_credentials"
        or str(payload.get("credential_state") or "").lower() == "invalid"
    ):
        return "invalid", "credential rejected by product verifier"
    if status == "auth_required" and why == "status=auth_required":
        return "inconclusive", "credential not verified; authentication still required"
    return "inconclusive", _clean(why or status or "verification unavailable")


def _supported(module: str, candidate: Candidate, detection: AuditRecord) -> bool:
    if candidate.kind == "pair":
        if module == "kubeapi":
            return detection.extra.get("credential_verification_status") == "available"
        return module in _PAIR_MODULES
    return module in _TOKEN_MODULES


def _attempt_id(module: str, target: Any, port: int, candidate: int | None) -> str:
    value = f"{module}\0{target.raw or target.host}\0{port}\0{candidate}"
    return hashlib.sha256(value.encode()).hexdigest()


def _effective_origin(record: AuditRecord, target: Any, host: str, port: int) -> str:
    for key in ("api_endpoint", "base_url", "resolved_origin"):
        value = record.extra.get(key)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            parsed = urlsplit(value)
            if parsed.hostname:
                return f"{parsed.scheme}://{parsed.netloc}"
    return f"{target.scheme or 'tcp'}://{host}:{port}"


def _module_runtime_args(module: str, args: Any, config: dict[str, Any]) -> Any:
    ns = build_parser().parse_args([module, "-t", args.targets])
    ns.timeout = args.timeout
    ns.retries = args.retries
    ns.workers = args.workers
    ns.proxy = args.proxy
    ns.debug = args.debug
    ns.no_color = args.no_color
    ns.enum_cve = False
    ns._spray_capabilities = module in {"grafana", "postgres", "redis"}
    # KubeAPI advertises Basic only when its detect hook is asked to inspect
    # the WWW-Authenticate challenge. No default credentials are attempted.
    ns.defcreds = module == "kubeapi"
    ns.output = None
    ns.output_format = "txt"
    ns._proxy_config = getattr(args, "_proxy_config", None)
    for key, value in config.items():
        if module == "kafka" and key == "sasl_mechanism":
            if value.upper() != "PLAIN":
                raise ValueError("--module-config kafka.sasl_mechanism supports PLAIN only")
            continue
        if module == "kafka" and key == "security_protocol":
            if value not in {"SASL_SSL", "SASL_PLAINTEXT"}:
                raise ValueError("--module-config kafka.security_protocol supports SASL_SSL or SASL_PLAINTEXT")
            continue
        if not hasattr(ns, key):
            raise ValueError(f"--module-config {module}.{key} is not supported by this module")
        if module == "keycloak" and key == "realm":
            if not isinstance(value, str) or not value:
                raise ValueError("--module-config keycloak.realm must be a nonempty string")
            value = [value]
        setattr(ns, key, value)
    if module == "kafka" and "security_protocol" in config:
        use_tls = config["security_protocol"] == "SASL_SSL"
        if "tls" in config and config["tls"] != use_tls:
            raise ValueError("--module-config kafka.tls conflicts with security_protocol")
        if "plaintext" in config and config["plaintext"] == use_tls:
            raise ValueError("--module-config kafka.plaintext conflicts with security_protocol")
        ns.tls = use_tls
        ns.plaintext = not use_tls
    ns._runtime_network = RuntimeNetworkConfig.from_args(ns, proxy=ns._proxy_config)
    return ns


def _job_targets(module: str, ns: Any) -> Iterator[tuple[str, int, Any]]:
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    plan = getattr(stage, f"build_{module.replace('-', '_')}_plan")(ns)
    for _, host, port, target in plan.iter_target_specs():
        if target is not None:
            yield host, port, target


def _readonly_keeper_detection(ctx: AuditHookContext, args: Any) -> AuditRecord:
    from .modules.keeper.stage import _build_keeper_lifecycle_options
    from .modules.zookeeper import engine

    options = _build_keeper_lifecycle_options(args)
    payload = engine.enforce_expected_implementation(
        engine.detect_zookeeper_implementation(ctx, options), expected_is_keeper=True
    )
    payload.update(module="keeper", service="keeper")
    return AuditRecord.from_mapping(payload, module="keeper", service="keeper")


def _oracle_spray_preflight(host: str, port: int, args: Any) -> bool:
    """Avoid the Oracle driver on unrelated ports; its connect can outlive --timeout."""
    from .clients.oracle import tns_listener_command, tns_service_fingerprint
    from .modules.oracle.actions import _protocols, _status_confirms_oracle, _target_candidates

    protocols = _protocols(str(getattr(args, "protocol", "auto")), port)
    candidates = _target_candidates(
        getattr(args, "service", None),
        getattr(args, "sid", None),
        getattr(args, "service_list", None),
        getattr(args, "sid_list", None),
    )
    timeout = min(max(float(getattr(args, "timeout", 1.0)), 0.1), 1.0)
    insecure = not bool(getattr(args, "secure", False))
    for protocol in protocols:
        status = tns_listener_command(host, port, "status", timeout=timeout, protocol=protocol, insecure=insecure)
        if _status_confirms_oracle(status):
            return True
        if candidates:
            candidate = candidates[0]
            if tns_service_fingerprint(
                host,
                port,
                service=candidate.get("service"),
                sid=candidate.get("sid"),
                timeout=timeout,
                protocol=protocol,
                insecure=insecure,
            ):
                return True
    return False


def _credential_detail(spec: ModuleAuditSpec, record: AuditRecord, candidate: Candidate) -> str:
    """Reuse only the matching credential suffix from the module's normal TXT row."""
    try:
        if spec.render_module is not None:
            lines = render_record_with_module(spec.render_module, record, "txt")
        elif spec.render is not None:
            lines = list(spec.render(record))
        else:
            return ""
    except Exception:
        return ""
    for line in lines:
        body = str(line).split("\t", 3)[-1].strip()
        if not body.startswith("[+] "):
            continue
        credential = body[4:]
        if not credential.startswith(candidate.display):
            continue
        suffix = credential[len(candidate.display) :]
        if not suffix.startswith(" ("):
            continue
        detail = suffix.strip()
        for secret in (candidate.password, candidate.token):
            if secret:
                detail = detail.replace(secret, "<redacted>")
        return _clean(detail[:512])
    return ""


def _record_version(record: AuditRecord) -> str | None:
    fields = record.extra
    for key in ("version", "server_version", "redis_version", "valkey_version"):
        value = fields.get(key)
        if isinstance(value, str) and value.strip().lower() not in {"", "-", "unknown", "none"}:
            return _clean(value.strip()[:80])
    for key, version_keys in (
        ("harbor_info", ("harbor_version", "version")),
        ("nexus_info", ("version", "release")),
        ("gitlab_info", ("version", "release")),
    ):
        info = fields.get(key)
        if isinstance(info, dict):
            for version_key in version_keys:
                value = info.get(version_key)
                if isinstance(value, str) and value.strip().lower() not in {"", "-", "unknown", "none"}:
                    return _clean(value.strip()[:80])
    return None


def _spray_credential_detail(module: str, record: AuditRecord, detail: str) -> str:
    error = str(record.extra.get("error") or "").lower()
    if module == "grafana" and "(datasources:unknown)" in detail and "authentication required" in error:
        return detail.replace("(datasources:unknown)", "(datasources:Access Denied)")
    if (
        module == "redis"
        and "(keys:unknown)" in detail
        and any(marker in error for marker in ("noperm", "noauth", "permission denied"))
    ):
        return detail.replace("(keys:unknown)", "(keys:Access Denied)")
    return detail


def _run_target(
    module: str,
    base_ns: Any,
    host: str,
    port: int,
    target: Any,
    candidates: tuple[Candidate, ...],
    journal: AttemptJournal,
    gate: RateGate,
    logger: Any,
) -> None:
    ns = copy.copy(base_ns)
    if module == "oracle" and not _oracle_spray_preflight(host, port, ns):
        return
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(ns)
    runner = AuditCommandRunner(args=ns, spec=spec, logger=logger, emit_line=lambda _line: None)
    anonymous = AuditCredentialRun(source="anonymous")
    context = AuditHookContext(ns, logger, host, port, anonymous, target=target, run_deep_checks=False, phase="detect")
    state = None
    try:
        if spec.lifecycle_state_factory is not None:
            state = spec.lifecycle_state_factory(context)
            context = replace(context, lifecycle_state=state)
        try:
            detection = _readonly_keeper_detection(context, ns) if module == "keeper" else runner._detect(context)
        except Exception as exc:
            if getattr(ns, "debug", False):
                print(f"[d] spray detection {module} {host}:{port}: {type(exc).__name__}", file=sys.stderr)
            return
        if not runner._is_detected(detection):
            return
        detection_key = _attempt_id(module, target, port, None)
        prior_detection = journal.get(detection_key)
        detection_version = _record_version(detection)
        if prior_detection is None or prior_detection[0] != "confirmed":
            version = detection_version or "unknown"
            auth_required = detection.auth_required
            evidence = f"auth required:{auth_required if auth_required is not None else 'unknown'}; version:{version}"
            journal.put(detection_key, module, host, port, None, "confirmed", _clean(evidence))
        origin = _effective_origin(detection, target, host, port)
        for index, candidate in enumerate(candidates):
            key = _attempt_id(module, target, port, index)
            if journal.get(key) is not None:
                continue
            if not _supported(module, candidate, detection):
                journal.put(
                    key, module, host, port, index, "unsupported", "no trustworthy verifier for this credential type"
                )
                continue
            allowed, delay_or_reason = gate.reserve(origin, candidate.account)
            if not allowed:
                journal.put(key, module, host, port, index, "rate_limited", str(delay_or_reason))
                continue
            if delay_or_reason and not gate.paused(float(delay_or_reason)):
                return
            if gate.cancelled.is_set():
                return
            with gate.lock:
                stopped_reason = gate.stopped.get(origin)
            if stopped_reason:
                journal.put(key, module, host, port, index, "rate_limited", stopped_reason)
                continue
            credential = AuditCredentialRun(candidate.username, candidate.password, candidate.token, "provided")
            ns.username = candidate.username
            ns.password = candidate.password
            for name in ("token", "api_token", "apitoken", "api_key", "pve_api_token", "_keycloak_token"):
                if hasattr(ns, name):
                    setattr(ns, name, candidate.token)
            journal.put(key, module, host, port, index, "started", "request begun; no automatic retry")
            detail = ""
            try:
                result = runner._auth(replace(context, credential=credential, phase="auth"), detection)
                status, evidence = classify(result, credential, runner)
                if status == "valid":
                    if spec.capabilities is not None:
                        try:
                            result = runner._capabilities(
                                replace(context, credential=credential, phase="capabilities"), result
                            )
                        except Exception:
                            pass  # The verified authentication result remains valid.
                    if module in _SPRAY_READ_ONLY_DATA_MODULES and spec.data is not None:
                        try:
                            result = runner._data(
                                replace(context, credential=credential, phase="data", run_deep_checks=True), result
                            )
                        except Exception:
                            pass  # A capability read must not erase a verified credential.
                    detail = _credential_detail(spec, result, candidate)
                    detail = _spray_credential_detail(module, result, detail)
                    auth_version = _record_version(result)
                    if auth_version and not detection_version and "(version:" not in detail:
                        detail = f"(version:{auth_version}) {detail}".strip()
            except Exception as exc:  # an individual verifier must not abort other products
                status, evidence = "inconclusive", f"verifier error: {type(exc).__name__}"
            safe_evidence = _clean(evidence)
            for secret in (candidate.password, candidate.token):
                if secret:
                    safe_evidence = safe_evidence.replace(secret, "<redacted>")
            journal.put(key, module, host, port, index, status, safe_evidence, detail)
            if status == "rate_limited":
                gate.stop(origin, evidence)
    finally:
        if state is not None and spec.lifecycle_state_close is not None:
            spec.lifecycle_state_close(state)


def _render_rows(
    rows: Iterable[tuple[str, str, int, int | None, str, str] | tuple[str, str, int, int | None, str, str, str]],
    candidates: tuple[Candidate, ...],
    fmt: str,
    *,
    debug: bool = False,
) -> list[str]:
    lines: list[str] = []
    markers = {
        "valid": "[+]",
        "invalid": "[-]",
        "access_denied": "[-]",
        "rate_limited": "[!]",
        "inconclusive": "[-]",
        "unsupported": "[*]",
    }
    for row in rows:
        module, host, port, index, status, evidence = row[:6]
        detail = _clean(row[6]) if len(row) == 7 else ""
        if status == "started":
            status, evidence = "inconclusive", "request began before interruption; not retried"
        elif status == "inconclusive" and evidence == "status=auth_required":
            evidence = "credential not verified; authentication still required"
        if index is None:
            if status == "confirmed":
                fields = dict(part.split(":", 1) for part in evidence.split("; ") if ":" in part)
                name = _DISPLAY_NAMES.get(module, module.title())
                text = f"[*] {name} (auth required:{fields.get('auth required', 'unknown')}) (version:{fields.get('version', 'unknown')})"
            else:
                text = f"[!] {module} detection {status} (evidence:{_clean(evidence)})"
            payload = {"module": module, "host": host, "port": port, "status": status, "evidence": evidence}
        else:
            candidate = candidates[index]
            payload = {
                "module": module,
                "host": host,
                "port": port,
                "status": status,
                "evidence": evidence,
                "credential_type": candidate.kind,
                "username": candidate.username,
                "password": candidate.password,
                "token": candidate.token,
            }
            if status == "valid" and detail:
                payload["credential_detail"] = detail
            suffix = f" {detail}" if status == "valid" and detail else ""
            diagnostic = f" (evidence:{_clean(evidence)})" if debug else ""
            text = f"{markers.get(status, '[!]')} {_clean(candidate.display)}{suffix}{diagnostic}"
        lines.append(
            json.dumps(payload, ensure_ascii=False) if fmt == "json" else f"{module.upper()}\t{host}\t{port}\t {text}"
        )
    return lines


class SpraySink:
    """Live JSON output and target-grouped TXT output, replayed on resume."""

    def __init__(
        self,
        output: str | None,
        fmt: str,
        candidates: tuple[Candidate, ...],
        console: Console,
        *,
        debug: bool = False,
        group_targets: bool = False,
    ) -> None:
        self.output = output
        self.fmt = fmt
        self.candidates = candidates
        self.console = console
        self.debug = debug
        self.group_targets = group_targets
        self.lock = threading.Lock()
        self._target_buffer = threading.local()
        self._deferred_rows: dict[tuple[str, str, int], list[tuple[str, str, int, int | None, str, str, str]]] = {}
        self.closed = False
        self.handle: Any = None
        if output:
            _private_file(output)
            self.handle = open(output, "w", encoding="utf-8")

    def defer_replay_rows(
        self,
        key: tuple[str, str, int],
        rows: list[tuple[str, str, int, int | None, str, str, str]],
    ) -> None:
        self._deferred_rows[key] = rows

    def begin_target(self, module: str = "", host: str = "", port: int = 0) -> None:
        if self.fmt == "txt" and self.group_targets:
            # Large password lists spill to a private temporary file instead
            # of retaining every pending row for every concurrent target.
            self._target_buffer.stream = tempfile.SpooledTemporaryFile(
                max_size=256 * 1024, mode="w+t", encoding="utf-8"
            )
            for row in self._deferred_rows.pop((module, host, port), ()):
                self._buffer_row(self._target_buffer.stream, row)

    @staticmethod
    def _buffer_row(stream: Any, row: tuple[str, str, int, int | None, str, str, str]) -> None:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    def end_target(self) -> None:
        stream = getattr(self._target_buffer, "stream", None)
        if stream is None:
            return
        del self._target_buffer.stream
        try:
            stream.seek(0)
            with self.lock:
                for line in stream:
                    self._emit_locked(*json.loads(line))
        finally:
            stream.close()

    def emit(
        self, module: str, host: str, port: int, index: int | None, status: str, evidence: str, detail: str = ""
    ) -> None:
        if status == "started":
            return
        if index is None and status != "confirmed" and self.fmt == "txt":
            return
        stream = getattr(self._target_buffer, "stream", None)
        if stream is not None:
            self._buffer_row(stream, (module, host, port, index, status, evidence, detail))
            return
        with self.lock:
            self._emit_locked(module, host, port, index, status, evidence, detail)

    def _emit_locked(
        self, module: str, host: str, port: int, index: int | None, status: str, evidence: str, detail: str
    ) -> None:
        if self.closed:
            return
        line = _render_rows(
            [(module, host, port, index, status, evidence, detail)], self.candidates, self.fmt, debug=self.debug
        )[0]
        if self.handle is not None:
            self.handle.write(line + "\n")
            self.handle.flush()
        if self.fmt == "json":
            self.console.plain(line)
            return
        aligned = format_report_line_for_console(line)
        spans: list[tuple[int, int, str]] = []
        if index is not None:
            display = _clean(self.candidates[index].display)
            if status == "valid":
                spans.append((0, len(display), "true_red"))
            if status == "valid" and detail:
                for match in re.finditer(r"\([^()]*\)", detail):
                    value = match.group()[1:-1].partition(":")[2].strip().lower()
                    if value in {"access denied", "denied", "false", "0"}:
                        color = "bright_green"
                    elif value == "true" or re.fullmatch(r"[1-9]\d*", value):
                        color = "true_red"
                    else:
                        color = "orange"
                    offset = len(display) + 1
                    spans.append((offset + match.start(), offset + match.end(), color))
        elif status == "confirmed":
            payload = aligned.split(" [*] ", 1)[-1]
            spans.extend(
                collect_boolean_spans(
                    payload,
                    (BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),),
                )
            )
            unknown = "(version:unknown)"
            at = payload.find(unknown)
            if at >= 0:
                spans.append((at, at + len(unknown), "orange"))
        render_spray_line(self.console, aligned, tag=module.upper(), spans=spans)

    def close(self) -> None:
        with self.lock:
            self.closed = True
            if self.handle is not None:
                self.handle.close()
                self.handle = None


def _group_txt_replay_rows(
    rows: list[tuple[str, str, int, int | None, str, str, str]],
) -> list[tuple[str, str, int, int | None, str, str, str]]:
    """Keep each target's journal rows together without reordering its attempts."""
    order: dict[tuple[str, str, int], int] = {}
    for row in rows:
        order.setdefault((row[0], row[1], row[2]), len(order))
    return sorted(rows, key=lambda row: order[(row[0], row[1], row[2])])


def run_spray_stage(args: Any, logger: Any) -> int:
    try:
        if args.workers < 1 or args.retries < 0:
            raise ValueError("--workers must be positive and --retries non-negative")
        modules = _modules(args.modules)
        if "clickhouse" in modules:
            from .modules.clickhouse import actions as clickhouse_actions

            clickhouse_actions._configure_clickhouse_loggers()
        candidates = load_candidates(args)
        config = _config(args.module_config, modules)
        target_plan = stream_scan_target_specs(
            args.targets,
            policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
        )
        module_args = {module: _module_runtime_args(module, args, config.get(module, {})) for module in modules}
        for ns in module_args.values():
            ns._preparsed_target_plan = target_plan
        if not candidates:
            raise ValueError("credential files contain no candidates")
        if args.resume and not args.checkpoint:
            raise ValueError("--resume requires --checkpoint")
        temporary_checkpoint = None
        checkpoint = args.checkpoint or (str(args.output) + ".checkpoint.sqlite3" if args.output else None)
        if checkpoint is None:
            descriptor, checkpoint = tempfile.mkstemp(prefix="redposture-spray-", suffix=".sqlite3")
            os.close(descriptor)
            os.unlink(checkpoint)
            temporary_checkpoint = checkpoint
        if args.output and os.path.abspath(args.output) == os.path.abspath(checkpoint):
            raise ValueError("--output and --checkpoint must be different files")
        protected_inputs = [args.pairs, args.tokens, args.module_config]
        for source in (args.users, args.passwords):
            if source:
                path = _source_file(str(source))
                if path is not None:
                    protected_inputs.append(str(path))
        if Path(str(args.targets)).is_file():
            protected_inputs.append(args.targets)
        destinations = [checkpoint, args.output]
        if any(
            os.path.realpath(str(destination)) == os.path.realpath(str(source))
            for destination in destinations
            if destination
            for source in protected_inputs
            if source
        ):
            raise ValueError("output/checkpoint must not overwrite an input file")
        journal = AttemptJournal(checkpoint, _input_fingerprint(args, modules, config), args.resume)
        try:
            gate = RateGate(args.origin_rate, args.account_interval)

            def jobs() -> Iterator[tuple[str, Any, str, int, Any]]:
                for module in modules:
                    ns = module_args[module]
                    for host, port, target in _job_targets(module, ns):
                        yield module, ns, host, port, target

            console = Console(debug=args.debug, no_color=args.no_color, structured_output=args.output_format == "json")
            group_targets = args.output_format == "txt" and len(modules) > 1
            sink = SpraySink(
                args.output,
                args.output_format,
                candidates,
                console,
                debug=bool(args.debug),
                group_targets=group_targets,
            )
            try:
                replay_rows = journal.rows()
                if group_targets:
                    replay_rows = _group_txt_replay_rows(replay_rows)
                    for key, grouped in groupby(replay_rows, key=lambda row: (row[0], row[1], row[2])):
                        group_rows = list(grouped)
                        finished = {row[3] for row in group_rows if row[3] is not None}
                        if finished == set(range(len(candidates))):
                            for row in group_rows:
                                sink.emit(*row)
                        else:
                            sink.defer_replay_rows(key, group_rows)
                else:
                    for row in replay_rows:
                        sink.emit(*row)
                journal.on_result = sink.emit
                # The shared scheduler bounds the queue and uses daemon workers,
                # so Ctrl+C cannot be held up by a blocked socket.
                scheduler: BoundedScheduler[tuple[str, Any, str, int, Any], None] = BoundedScheduler(
                    max_workers=args.workers, max_inflight=args.workers * 2
                )

                def work(job: tuple[str, Any, str, int, Any]) -> None:
                    module, ns, host, port, target = job
                    sink.begin_target(module, host, port)
                    try:
                        _run_target(module, ns, host, port, target, candidates, journal, gate, logger)
                    finally:
                        sink.end_target()

                outcomes = scheduler.iter_completed(jobs(), work)
                try:
                    for _job, _result in outcomes:
                        pass
                except KeyboardInterrupt:
                    gate.cancel()
                    raise
                finally:
                    close = getattr(outcomes, "close", None)
                    if callable(close):
                        close()
            finally:
                journal.on_result = None
                sink.close()
        finally:
            journal.close()
            if temporary_checkpoint:
                Path(temporary_checkpoint).unlink(missing_ok=True)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[error] spray: {exc}", file=sys.stderr)
        return 2
    return 0


__all__ = ["Candidate", "RateGate", "classify", "load_candidates", "run_spray_stage"]
