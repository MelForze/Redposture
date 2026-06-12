from __future__ import annotations

import importlib
from collections.abc import Iterable
from types import SimpleNamespace
from typing import Any

from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
)


def _sync_root_monkeypatches(module: str) -> None:
    root = importlib.import_module(f"redposture_core.stage_{module}")
    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")
    for name in dir(root):
        if not (name.startswith("_audit_") or name.startswith("_call_audit_") or name.startswith("_stream_")):
            continue
        value = getattr(root, name)
        if getattr(actions, name, None) is not value:
            setattr(actions, name, value)


def _legacy_status_tuple(module: str, records: list[dict[str, Any]]) -> tuple[Any, ...]:
    total = len(records)
    status_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status") or "")
        status_counts[status] = status_counts.get(status, 0) + 1

    invalid_anonymous = status_counts.get("invalid_credentials_anonymous", 0)
    open_count = status_counts.get("open_no_auth", 0) + status_counts.get("anonymous_access", 0) + invalid_anonymous
    valid = (
        status_counts.get("valid_credentials", 0)
        + status_counts.get("weak_default_creds", 0)
        + status_counts.get("valid_token", 0)
        + status_counts.get("token_accepted", 0)
        + status_counts.get("token_valid", 0)
        + status_counts.get("auth_valid", 0)
    )
    auth_required = status_counts.get("auth_required", 0)
    failed = status_counts.get("fail", 0)
    unknown = status_counts.get("unknown_auth", 0)
    invalid = status_counts.get("invalid_credentials", 0) + status_counts.get("invalid_credentials_anonymous", 0)
    not_service = sum(1 for record in records if str(record.get("status") or "").startswith("not_"))

    if module in {"redis", "postgres", "clickhouse", "oracle"}:
        return (
            total,
            open_count,
            status_counts.get("weak_default_creds", 0),
            status_counts.get("valid_credentials", 0),
            auth_required,
            failed,
        )
    if module in {"kafka", "elastic", "grafana", "qdrant", "docker", "zookeeper"}:
        return (total, open_count, valid, auth_required, failed + not_service)
    if module in {"gitlab", "kubeapi"}:
        return (total, open_count + valid + auth_required + status_counts.get("detected", 0), failed + not_service)
    if module == "consul":
        return (total, open_count + valid + auth_required + status_counts.get("ok", 0), failed + not_service, False)
    if module == "registry":
        return (total, open_count, valid, auth_required, unknown, failed + not_service)
    if module == "proxmox":
        credential_hits = sum(
            int(record.get("credential_hits") or 0)
            for record in records
            if isinstance(record.get("credential_hits"), int)
        )
        return (
            total,
            valid + open_count + status_counts.get("token_ok", 0),
            status_counts.get("insufficient_privileges", 0),
            invalid + status_counts.get("auth_failed", 0),
            failed + not_service,
            credential_hits,
        )
    if module == "etcd":
        return (total, open_count, auth_required, failed + not_service)
    if module == "mongodb":
        return (
            total,
            open_count - invalid_anonymous,
            valid,
            auth_required,
            status_counts.get("invalid_credentials", 0),
            failed + not_service,
        )
    if module == "grpc":
        return (total, open_count, valid, auth_required, not_service, failed)
    return (total, open_count, valid, auth_required, failed + not_service)


def run_module_targets_for_test(
    module: str,
    *,
    hosts: Iterable[str],
    port: int,
    output_format: str = "txt",
    output_path: str | None = None,
    emit_line=None,
    append_output: bool = False,
    **kwargs: Any,
) -> tuple[Any, ...]:
    _sync_root_monkeypatches(module)
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    args = SimpleNamespace(**kwargs)
    args.output_format = output_format
    args.output = output_path
    args.targets = ",".join(str(host) for host in hosts)
    args.hosts = None
    args.hosts_file = None
    args.port = int(port)
    args.ports = None
    args.workers = int(getattr(args, "workers", 1) or 1)
    args.debug = bool(getattr(args, "debug", False) or getattr(args, "debug_emit", None) is not None)
    args._progress_owner = getattr(args, "_progress_owner", None)
    credential = AuditCredentialRun(
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        token=getattr(args, "token", None) or getattr(args, "api_token", None),
    )
    plan = AuditCommandPlan(
        targets_by_port={int(port): tuple(str(host) for host in hosts)},
        credential_runs=(credential,),
        output_path=output_path,
        output_format=output_format,
        workers=args.workers,
        append=append_output,
    )
    suppress_refused = bool(
        getattr(args, "suppress_connection_refused_status_lines", False)
        or getattr(args, "suppress_fail_status_lines", False)
    )
    suppress_timeout = bool(
        getattr(args, "suppress_timeout_status_lines", False) or getattr(args, "suppress_fail_status_lines", False)
    )
    suppress_fail = bool(suppress_refused or suppress_timeout)

    seen_clickhouse_success: set[str] = set()

    def _emit(line: str) -> None:
        lower_line = line.lower()
        if (suppress_refused or (module in {"clickhouse", "postgres"} and suppress_timeout)) and (
            "connection failed err=connection refused" in lower_line or "connection refused" in lower_line
        ):
            return
        if suppress_timeout and (
            "connection failed err=connection timeout" in lower_line
            or "connection failed err=timeout" in lower_line
            or "connection timeout" in lower_line
        ):
            return
        if module == "zookeeper" and suppress_fail and "unexpected eof" in lower_line:
            return
        if module == "zookeeper" and suppress_fail and "[-] authentication required" in line:
            return
        if module == "clickhouse" and (
            "[-] authentication required" in line or "[-] authentication required (credentials invalid)" in line
        ):
            return
        if module == "clickhouse" and " [+] " in line:
            credential_text = line.split(" [+] ", 1)[1].split(" ", 1)[0]
            if ":" in credential_text:
                if credential_text in seen_clickhouse_success:
                    return
                seen_clickhouse_success.add(credential_text)
        if emit_line is not None:
            emit_line(line)

    def _suppressed_record(record: dict[str, Any]) -> bool:
        if module != "zookeeper" or not suppress_fail:
            return False
        if str(record.get("status") or "") != "fail":
            return False
        error = str(record.get("error") or "").lower()
        if suppress_refused and "connection refused" in error:
            return True
        if suppress_timeout and "timeout" in error:
            return True
        return module == "zookeeper" and suppress_fail and "unexpected eof" in error

    runner = AuditCommandRunner(args=args, spec=getattr(stage, f"build_{module}_spec")(args), emit_line=_emit)
    result = runner.run_plan(plan)
    logger = getattr(args, "logger", None)
    if logger is not None and hasattr(logger, "log"):
        for record in result.records:
            if _suppressed_record(record):
                continue
            logger.log(module, record)
    if output_path and emit_line is not None:
        try:
            for line in open(output_path, encoding="utf-8").read().splitlines():
                _emit(line)
        except OSError:
            pass
    return _legacy_status_tuple(module, result.records)


def patch_runner_for_legacy_target_fake(monkeypatch, module: str, fake) -> None:
    from redposture_core import stage_runtime
    from redposture_core.stage_runtime import AuditCommandResult

    def _run_plan(self, plan):
        has_file_credentials = any(credential.source == "file" for credential in plan.credential_runs)
        skip_anonymous_file_detect = module == "redis" and has_file_credentials
        work_items = [
            item
            for item in plan.iter_work_items()
            if not (skip_anonymous_file_detect and item[3].source == "anonymous")
        ]
        progress = stage_runtime.start_command_progress(
            self.args,
            self.spec.label,
            len(work_items),
            enabled=plan.output_format == "txt" and plan.target_count > 0,
        )
        emitted = 0
        for _idx, host, port, credential, _target in work_items:
            kwargs = dict(vars(self.args)) if hasattr(self.args, "__dict__") else {}
            kwargs.update(
                {
                    "hosts": [host],
                    "port": int(port),
                    "username": credential.username,
                    "password": credential.password,
                    "api_token": credential.token,
                    "output_format": plan.output_format,
                    "output_path": plan.output_path,
                    "emit_line": self.emit_line,
                    "logger": self.logger,
                    "append_output": plan.append or emitted > 0,
                    "show_progress": False,
                    "command_progress": progress,
                    "debug_emit": getattr(self.args, "debug_emit", None),
                }
            )
            if has_file_credentials:
                kwargs["defcreds"] = False
            if module == "clickhouse":
                kwargs.setdefault("protocol", getattr(self.args, "protocol", "native"))
                kwargs.setdefault("suppress_timeout_status_lines", True)
                kwargs.setdefault("suppress_fail_status_lines", True)
            if module in {"redis", "kafka", "elastic", "zookeeper"}:
                kwargs.setdefault(
                    "suppress_connection_refused_status_lines",
                    not bool(getattr(self.args, "debug", False)),
                )
                kwargs.setdefault("suppress_timeout_status_lines", True)
            if module == "postgres":
                kwargs.setdefault("suppress_connection_refused_status_lines", False)
                kwargs.setdefault("suppress_timeout_status_lines", False)
            if module == "consul":
                kwargs.setdefault("check_dump_id", getattr(self.args, "revshell_check_id", None))
                kwargs.setdefault("dump_all_requested", bool(getattr(self.args, "dump_all_requested", False)))
                kwargs.setdefault("show_services", bool(getattr(self.args, "show_services", False)))
                kwargs.setdefault("show_agents", bool(getattr(self.args, "show_agents", False)))
                kwargs.setdefault("show_checks", bool(getattr(self.args, "show_checks", False)))
                kwargs.setdefault("show_nodes", bool(getattr(self.args, "show_nodes", False)))
            if module == "elastic":
                kwargs.setdefault("show_plugins", bool(getattr(self.args, "plugins", False)))
                kwargs.setdefault(
                    "api_token", getattr(self.args, "api_token", None) or getattr(self.args, "apitoken", None)
                )
            if module == "kubeapi":
                kwargs.setdefault("use_https", bool(getattr(self.args, "use_https", True)))
                kwargs.setdefault("namespace_filters", getattr(self.args, "namespace_filters", None) or [])
            if module == "proxmox":
                if _target is not None and getattr(_target, "scheme", None) in {"http", "https"}:
                    kwargs["use_https"] = str(_target.scheme).lower() == "https"
                else:
                    kwargs.setdefault("use_https", bool(getattr(self.args, "https", False)))
            fake(**kwargs)
            emitted += 1
        progress.close()
        return AuditCommandResult(records=[], detected_count=0, emitted_lines=emitted, typed_records=[])

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", _run_plan)
