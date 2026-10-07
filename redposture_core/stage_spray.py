"""Bounded, credential-only verification on confirmed audit products."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .audit_models import AuditRecord
from .cli_args import build_parser
from .console import Console
from .module_registry import AUDIT_MODULE_NAMES
from .network_proxy import RuntimeNetworkConfig
from .rendering import format_report_line_for_console
from .scheduler import BoundedScheduler
from .spray_render import render_spray_line
from .stage_runtime import AuditCommandRunner, AuditCredentialRun, AuditHookContext

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
_DISPLAY_NAMES = {
    "clickhouse": "ClickHouse",
    "docker": "Docker Engine",
    "docker-registry": "Docker Registry",
    "elastic": "Elasticsearch/OpenSearch",
    "etcd": "etcd",
    "gitlab": "GitLab",
    "grafana": "Grafana",
    "grpc": "gRPC",
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
        users = _read_lines(args.users)
        # Empty passwords are valid candidates; preserve blank lines here.
        with open(args.passwords, encoding="utf-8-sig") as stream:
            passwords = [line.rstrip("\r\n") for line in stream if not line.startswith("#")]
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
    for name in ("targets", "pairs", "users", "passwords", "tokens", "module_config"):
        value = getattr(args, name, None)
        if value and Path(str(value)).is_file():
            files[name] = hashlib.sha256(Path(str(value)).read_bytes()).hexdigest()
    payload = {
        "targets": args.targets,
        "modules": modules,
        "files": files,
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
            "port INTEGER NOT NULL, candidate INTEGER, status TEXT NOT NULL, evidence TEXT NOT NULL)"
        )
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
        self, key: str, module: str, host: str, port: int, candidate: int | None, status: str, evidence: str
    ) -> None:
        with self.lock:
            if self.closed:
                return
            self.db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, module, host, port, candidate, status, evidence),
            )
            self.db.commit()
            if self.on_result is not None:
                self.on_result(module, host, port, candidate, status, evidence)

    def rows(self) -> list[tuple[str, str, int, int | None, str, str]]:
        with self.lock:
            return self.db.execute(
                "SELECT module, host, port, candidate, status, evidence FROM results ORDER BY rowid"
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
        if prior_detection is None or prior_detection[0] != "confirmed":
            version = detection.extra.get("version") or "unknown"
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
            try:
                result = runner._auth(replace(context, credential=credential, phase="auth"), detection)
                status, evidence = classify(result, credential, runner)
            except Exception as exc:  # an individual verifier must not abort other products
                status, evidence = "inconclusive", f"verifier error: {type(exc).__name__}"
            safe_evidence = _clean(evidence)
            for secret in (candidate.password, candidate.token):
                if secret:
                    safe_evidence = safe_evidence.replace(secret, "<redacted>")
            journal.put(key, module, host, port, index, status, safe_evidence)
            if status == "rate_limited":
                gate.stop(origin, evidence)
    finally:
        if state is not None and spec.lifecycle_state_close is not None:
            spec.lifecycle_state_close(state)


def _render_rows(
    rows: Iterable[tuple[str, str, int, int | None, str, str]], candidates: tuple[Candidate, ...], fmt: str
) -> list[str]:
    lines: list[str] = []
    markers = {
        "valid": "[+]",
        "invalid": "[-]",
        "access_denied": "[-]",
        "rate_limited": "[!]",
        "inconclusive": "[!]",
        "unsupported": "[*]",
    }
    for module, host, port, index, status, evidence in rows:
        if status == "started":
            status, evidence = "inconclusive", "request began before interruption; not retried"
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
            text = f"{markers.get(status, '[!]')} {_clean(candidate.display)} ({status}) (evidence:{_clean(evidence)})"
        lines.append(
            json.dumps(payload, ensure_ascii=False) if fmt == "json" else f"{module.upper()}\t{host}\t{port}\t {text}"
        )
    return lines


class SpraySink:
    """Live terminal/TXT output, replayed from the journal on resume."""

    def __init__(self, output: str | None, fmt: str, candidates: tuple[Candidate, ...], console: Console) -> None:
        self.output = output
        self.fmt = fmt
        self.candidates = candidates
        self.console = console
        self.lock = threading.Lock()
        self.handle: Any = None
        if output:
            _private_file(output)
            self.handle = open(output, "w", encoding="utf-8")

    def emit(self, module: str, host: str, port: int, index: int | None, status: str, evidence: str) -> None:
        if status == "started":
            return
        if index is None and status != "confirmed" and self.fmt == "txt":
            return
        line = _render_rows([(module, host, port, index, status, evidence)], self.candidates, self.fmt)[0]
        with self.lock:
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
                spans.append((0, len(display), "orange"))
                state = f"({status})"
                state_start = len(display) + 1
                spans.append(
                    (
                        state_start,
                        state_start + len(state),
                        {"valid": "red", "invalid": "green", "access_denied": "green"}.get(status, "orange"),
                    )
                )
            render_spray_line(self.console, aligned, tag=module.upper(), spans=spans)

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()


def run_spray_stage(args: Any, logger: Any) -> int:
    try:
        if args.workers < 1 or args.retries < 0:
            raise ValueError("--workers must be positive and --retries non-negative")
        modules = _modules(args.modules)
        candidates = load_candidates(args)
        config = _config(args.module_config, modules)
        module_args = {module: _module_runtime_args(module, args, config.get(module, {})) for module in modules}
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
        protected_inputs = [args.pairs, args.users, args.passwords, args.tokens, args.module_config]
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
            sink = SpraySink(args.output, args.output_format, candidates, console)
            try:
                for row in journal.rows():
                    sink.emit(*row)
                journal.on_result = sink.emit
                # The shared scheduler bounds the queue and uses daemon workers,
                # so Ctrl+C cannot be held up by a blocked socket.
                scheduler: BoundedScheduler[tuple[str, Any, str, int, Any], None] = BoundedScheduler(
                    max_workers=args.workers, max_inflight=args.workers * 2
                )

                def work(job: tuple[str, Any, str, int, Any]) -> None:
                    module, ns, host, port, target = job
                    _run_target(module, ns, host, port, target, candidates, journal, gate, logger)

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
