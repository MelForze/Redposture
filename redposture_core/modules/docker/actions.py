"""Docker Engine API audit stage."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from typing import Any

from ...clients.docker_engine import (
    DockerEngineClient,
    DockerEngineConnectionError,
    DockerEngineError,
    DockerEngineHTTPError,
    find_container_id,
    is_auth_required_error,
    normalize_docker_error,
)
from ...console import Console
from ...rendering import CountColorRule, render_colored_marker_line
from ...stage_runtime import (
    AuditHookContext,
    AuditRecord,
    StageTelemetryBuilder,
    invoke_action_hook_from_args,
)
from ...utils import utc_now_iso

_DOCKER_TAG = "DOCKER"
_DOCKER_DEFAULT_PORTS = [2375, 2376, 4243]
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_DOCKER_DEEP_STATUSES = {"open_no_auth", "valid_credentials"}


def _clip(text: str, width: int = 120) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _transport_order(port: int) -> list[str]:
    if int(port) == 2376:
        return ["tls", "plaintext"]
    return ["plaintext", "tls"]


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_DOCKER_TAG:<8}\t{host}\t{port}\t"


def _base_record(host: str, port: int) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "service": "docker",
        "host": host,
        "port": int(port),
        "is_docker": False,
        "status": "fail",
        "auth_required": None,
        "transport_mode": None,
        "tls_required": None,
        "api_version": None,
        "server_version": None,
        "ostype": None,
        "containers": [],
        "images": [],
        "networks": [],
        "volumes": [],
        "system": {},
        "exec_result": None,
        "capabilities": {},
    }


def _docker_client(
    host: str,
    port: int,
    transport: str,
    timeout: float,
    *,
    insecure: bool,
    tls_ca: str | None,
    tls_cert: str | None,
    tls_key: str | None,
) -> DockerEngineClient:
    return DockerEngineClient(
        host,
        port,
        transport=transport,
        timeout=timeout,
        insecure=insecure,
        ca_file=tls_ca,
        cert_file=tls_cert,
        key_file=tls_key,
    )


def _probe_docker(
    host: str,
    port: int,
    timeout: float,
    *,
    insecure: bool,
    tls_ca: str | None,
    tls_cert: str | None,
    tls_key: str | None,
) -> tuple[DockerEngineClient | None, dict[str, Any] | None, str | None, str | None, bool]:
    last_error: str | None = None
    auth_required = False
    for transport in _transport_order(port):
        client = _docker_client(
            host,
            port,
            transport,
            timeout,
            insecure=insecure,
            tls_ca=tls_ca,
            tls_cert=tls_cert,
            tls_key=tls_key,
        )
        try:
            client.ping()
            try:
                version = client.version()
            except DockerEngineHTTPError as exc:
                if exc.status not in {404, 405}:
                    raise
                info = client.info()
                version = {
                    "Version": info.get("ServerVersion"),
                    "ApiVersion": info.get("ApiVersion"),
                    "Os": info.get("OSType"),
                }
            if version or client.info():
                return client, version, transport, None, auth_required
        except DockerEngineHTTPError as exc:
            if exc.status in {401, 403}:
                auth_required = True
                return client, None, transport, normalize_docker_error(exc), auth_required
            if exc.status in {404, 405}:
                last_error = f"not Docker Engine API endpoint (status:{exc.status})"
            else:
                last_error = normalize_docker_error(exc)
        except DockerEngineConnectionError as exc:
            last_error = normalize_docker_error(exc)
            if is_auth_required_error(exc):
                auth_required = True
                return client, None, transport, last_error, auth_required
        except (DockerEngineError, ValueError, json.JSONDecodeError) as exc:
            last_error = normalize_docker_error(exc)
    return None, None, None, last_error, auth_required


def _container_count(record: dict[str, Any]) -> int:
    containers = record.get("containers")
    return len(containers) if isinstance(containers, list) else 0


def _image_count(record: dict[str, Any]) -> int:
    images = record.get("images")
    return len(images) if isinstance(images, list) else 0


def _network_count(record: dict[str, Any]) -> int:
    networks = record.get("networks")
    return len(networks) if isinstance(networks, list) else 0


def _volume_count(record: dict[str, Any]) -> int:
    volumes = record.get("volumes")
    return len(volumes) if isinstance(volumes, list) else 0


def _caps_suffix(record: dict[str, Any]) -> str:
    capabilities = record.get("capabilities") if isinstance(record.get("capabilities"), dict) else {}
    parts: list[str] = []
    if capabilities.get("can_list_containers") is True:
        parts.append(f"(containers:{_container_count(record)})")
    if capabilities.get("can_list_images") is True:
        parts.append(f"(images:{_image_count(record)})")
    if capabilities.get("can_list_networks") is True:
        parts.append(f"(networks:{_network_count(record)})")
    if capabilities.get("can_list_volumes") is True:
        parts.append(f"(volumes:{_volume_count(record)})")
    return f" {' '.join(parts)}" if parts else ""


def _audit_docker_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    insecure: bool = False,
    tls_ca: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    show_containers: bool = False,
    show_images: bool = False,
    show_networks: bool = False,
    show_volumes: bool = False,
    show_system: bool = False,
    container_selector: str | None = None,
    exec_cmd: str | None = None,
    run_deep_checks: bool = True,
) -> dict[str, Any]:
    record = _base_record(host, port)
    attempts = max(1, int(retries) + 1)
    client: DockerEngineClient | None = None
    version: dict[str, Any] | None = None
    transport: str | None = None
    last_error: str | None = None
    auth_required = False

    for attempt in range(attempts):
        client, version, transport, last_error, auth_required = _probe_docker(
            host,
            port,
            timeout,
            insecure=insecure,
            tls_ca=tls_ca,
            tls_cert=tls_cert,
            tls_key=tls_key,
        )
        if client is not None and (version is not None or auth_required):
            break
        if attempt + 1 < attempts:
            time.sleep(_retry_delay(attempt))

    if auth_required:
        record.update(
            {
                "is_docker": True,
                "status": "auth_required",
                "auth_required": True,
                "transport_mode": transport,
                "tls_required": transport == "tls",
                "error": last_error or "authentication required",
            }
        )
        return record

    if client is None or version is None:
        error = last_error or "connection failed"
        status = "not_docker" if "not Docker" in error or "status:404" in error else "fail"
        record.update({"status": status, "error": error, "auth_required": None})
        return record

    status = "valid_credentials" if tls_cert or tls_key else "open_no_auth"
    record.update(
        {
            "is_docker": True,
            "status": status,
            "auth_required": False,
            "transport_mode": transport,
            "tls_required": transport == "tls",
            "api_version": version.get("ApiVersion") or version.get("APIVersion"),
            "server_version": version.get("Version"),
            "ostype": version.get("Os") or version.get("OSType"),
            "tls_client_cert_used": bool(tls_cert or tls_key),
        }
    )

    if not run_deep_checks:
        return record

    capabilities: dict[str, Any] = {}
    containers_cache: list[dict[str, Any]] | None = None

    def _load_containers() -> list[dict[str, Any]]:
        nonlocal containers_cache
        if containers_cache is None:
            containers_cache = client.containers()
        return containers_cache

    if show_containers:
        try:
            rows = _load_containers()
            record["containers"] = rows
            capabilities["can_list_containers"] = True
        except DockerEngineError as exc:
            record["containers_error"] = normalize_docker_error(exc)
            capabilities["can_list_containers"] = False

    if show_images:
        try:
            record["images"] = client.images()
            capabilities["can_list_images"] = True
        except DockerEngineError as exc:
            record["images_error"] = normalize_docker_error(exc)
            capabilities["can_list_images"] = False

    if show_networks:
        try:
            record["networks"] = client.networks()
            capabilities["can_list_networks"] = True
        except DockerEngineError as exc:
            record["networks_error"] = normalize_docker_error(exc)
            capabilities["can_list_networks"] = False

    if show_volumes:
        try:
            record["volumes"] = client.volumes()
            capabilities["can_list_volumes"] = True
        except DockerEngineError as exc:
            record["volumes_error"] = normalize_docker_error(exc)
            capabilities["can_list_volumes"] = False

    if show_system:
        system: dict[str, Any] = {}
        try:
            system["info"] = client.info()
            capabilities["can_read_system_info"] = True
        except DockerEngineError as exc:
            system["info_error"] = normalize_docker_error(exc)
            capabilities["can_read_system_info"] = False
        try:
            system["df"] = client.system_df()
            capabilities["can_read_disk_usage"] = True
        except DockerEngineError as exc:
            system["df_error"] = normalize_docker_error(exc)
            capabilities["can_read_disk_usage"] = False
        record["system"] = system

    if container_selector and exec_cmd is not None:
        try:
            rows = _load_containers()
            container_id = find_container_id(rows, container_selector)
            if not container_id:
                record["exec_result"] = {"ok": False, "error": f"container not found: {container_selector}"}
                capabilities["can_exec"] = False
            else:
                result = client.exec_command(container_id, exec_cmd)
                result.update(
                    {"ok": True, "container": container_selector, "container_id": container_id, "command": exec_cmd}
                )
                record["exec_result"] = result
                capabilities["can_exec"] = True
        except DockerEngineError as exc:
            record["exec_result"] = {"ok": False, "error": normalize_docker_error(exc), "command": exec_cmd}
            capabilities["can_exec"] = False

    record["capabilities"] = capabilities
    return record


def _audit_docker_host_stage(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    insecure: bool = False,
    tls_ca: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    show_containers: bool = False,
    show_images: bool = False,
    show_networks: bool = False,
    show_volumes: bool = False,
    show_system: bool = False,
    container_selector: str | None = None,
    exec_cmd: str | None = None,
    run_deep_checks: bool = True,
    debug: bool = False,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    attempts = max(1, int(retries) + 1)
    record = _audit_docker_host(
        host,
        port,
        timeout,
        retries,
        insecure=insecure,
        tls_ca=tls_ca,
        tls_cert=tls_cert,
        tls_key=tls_key,
        show_containers=show_containers if run_deep_checks else False,
        show_images=show_images if run_deep_checks else False,
        show_networks=show_networks if run_deep_checks else False,
        show_volumes=show_volumes if run_deep_checks else False,
        show_system=show_system if run_deep_checks else False,
        container_selector=container_selector if run_deep_checks else None,
        exec_cmd=exec_cmd if run_deep_checks else None,
        run_deep_checks=run_deep_checks,
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    status = str(record.get("status") or "fail")
    is_docker = bool(record.get("is_docker"))
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    detect_result = "ok" if is_docker else ("skip" if status == "not_docker" else "error")
    detect_error = str(record.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)
    auth_result = "ok" if is_docker else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)
    if run_deep_checks and status in _DOCKER_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        exec_result = record.get("exec_result") if isinstance(record.get("exec_result"), dict) else {}
        data_error = exec_result.get("error") if exec_result and not exec_result.get("ok") else None
        telemetry.stage(
            _STAGE_DATA, "error" if data_error else "ok", str(data_error) if data_error else None, elapsed_ms
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)
    durations = {str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages}
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={durations.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={durations.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={durations.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={durations.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )
    return telemetry.attach(record, status=status, total_ms=elapsed_ms)


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "service": "docker",
                "host": record.get("host"),
                "port": record.get("port"),
                "detected": bool(record.get("is_docker")),
                "auth_required": record.get("auth_required"),
                "transport_mode": record.get("transport_mode"),
                "api_version": record.get("api_version"),
                "server_version": record.get("server_version"),
            },
            ensure_ascii=False,
        )
    auth = record.get("auth_required")
    auth_text = "True" if auth is True else "False" if auth is False else "unknown"
    transport = str(record.get("transport_mode") or "-")
    version = str(record.get("server_version") or "-")
    return f"{_nxc_prefix(record)} [*] Docker Engine API (auth required:{auth_text}) (transport:{transport}) (version:{version})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)
    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access{_caps_suffix(record)}"
    if status == "valid_credentials":
        return f"{prefix} [+] TLS client certificate accepted{_caps_suffix(record)}"
    if status == "auth_required":
        return f"{prefix} [-] authentication required (transport:{record.get('transport_mode') or '-'})"
    if status == "not_docker":
        return f"{prefix} [-] not Docker Engine API endpoint err={_clip(str(record.get('error') or '-'), 96)}"
    return f"{prefix} [!] connection failed err={_clip(str(record.get('error') or 'connection failed'), 96)}"


def _format_container_lines(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("containers")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "containers",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "containers": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Containers (count:{len(rows)})"]
    for row in rows:
        names = row.get("Names") or []
        name = str(names[0]).lstrip("/") if names else "-"
        lines.append(
            f"{prefix} id={str(row.get('Id') or '-')[:12]} name={name} image={row.get('Image') or '-'} state={row.get('State') or '-'} status={row.get('Status') or '-'}"
        )
    return lines


def _format_image_lines(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("images")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "images",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "images": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Images (count:{len(rows)})"]
    for row in rows:
        tags = row.get("RepoTags") or ["<none>:<none>"]
        lines.append(
            f"{prefix} id={str(row.get('Id') or '-')[:20]} tags={','.join(str(x) for x in tags)} size={row.get('Size') or 0}"
        )
    return lines


def _format_network_lines(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("networks")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "networks",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "networks": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Networks (count:{len(rows)})"]
    for row in rows:
        lines.append(
            f"{prefix} id={str(row.get('Id') or '-')[:12]} name={row.get('Name') or '-'} driver={row.get('Driver') or '-'} scope={row.get('Scope') or '-'}"
        )
    return lines


def _format_volume_lines(record: dict[str, Any], output_format: str) -> list[str]:
    rows = record.get("volumes")
    if not isinstance(rows, list) or not rows:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "volumes",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "volumes": rows,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Volumes (count:{len(rows)})"]
    for row in rows:
        lines.append(
            f"{prefix} name={row.get('Name') or '-'} driver={row.get('Driver') or '-'} mountpoint={_clip(str(row.get('Mountpoint') or '-'), 120)}"
        )
    return lines


def _format_system_lines(record: dict[str, Any], output_format: str) -> list[str]:
    system = record.get("system")
    if not isinstance(system, dict) or not system:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "system",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "system": system,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    info = system.get("info") if isinstance(system.get("info"), dict) else {}
    df = system.get("df") if isinstance(system.get("df"), dict) else {}
    lines = [f"{prefix} [*] System"]
    if info:
        lines.append(
            f"{prefix} containers={info.get('Containers', '-')} running={info.get('ContainersRunning', '-')} images={info.get('Images', '-')} os={info.get('OperatingSystem', '-')}"
        )
    if df:
        lines.append(
            f"{prefix} layers_size={df.get('LayersSize', '-')} images={len(df.get('Images') or [])} containers={len(df.get('Containers') or [])} volumes={len(df.get('Volumes') or [])}"
        )
    return lines


def _split_exec_payload(prefix: str, value: Any) -> list[str]:
    text = str(value or "").rstrip()
    if not text:
        return []
    return [f"{prefix} {_clip(line, 240)}" for line in text.splitlines() or [text]]


def _split_labeled_exec_payload(prefix: str, label: str, value: Any) -> list[str]:
    text = str(value or "").rstrip()
    if not text:
        return []
    return [f"{prefix} {label}={_clip(line, 240)}" for line in text.splitlines() or [text]]


def _format_exec_lines(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    result = record.get("exec_result")
    if not isinstance(result, dict):
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "type": "exec_result",
                    "service": "docker",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "exec_result": result,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Exec Result"]
    if not result.get("ok"):
        lines.append(f"{prefix} [!] exec failed err={_clip(str(result.get('error') or '-'), 160)}")
        return lines
    stdout = str(result.get("stdout") or "").strip()
    stderr = str(result.get("stderr") or "").strip()
    if debug:
        lines.append(
            f"{prefix} container={result.get('container') or '-'} command={_clip(str(result.get('command') or '-'), 120)} exit_code={result.get('exit_code')}"
        )
        lines.extend(_split_labeled_exec_payload(prefix, "stdout", stdout))
        lines.extend(_split_labeled_exec_payload(prefix, "stderr", stderr))
        return lines
    lines.extend(_split_exec_payload(prefix, stdout))
    lines.extend(_split_exec_payload(prefix, stderr))
    if len(lines) == 1:
        lines.append(f"{prefix} <no output>")
    return lines


def _render_colored_docker_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag=_DOCKER_TAG,
        counts=(
            CountColorRule("containers", "red"),
            CountColorRule("images", "red"),
            CountColorRule("networks", "red"),
            CountColorRule("volumes", "red"),
            CountColorRule("count", "orange"),
        ),
    )


__all__ = [
    "_audit_docker_host",
    "_format_detect_record",
    "_format_record",
]


# Typed runner boundary -----------------------------------------------------
def record_from_mapping(payload: dict[str, Any]) -> AuditRecord:
    """Convert legacy protocol payloads at the typed runtime boundary."""

    return AuditRecord.from_mapping(payload, module="docker", service="docker")


def host_hook(ctx: AuditHookContext) -> AuditRecord:
    """Typed host hook consumed by AuditCommandRunner."""

    return invoke_action_hook_from_args(sys.modules[__name__], module="docker", ctx=ctx)
