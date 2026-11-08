"""Read inline workload environment values without exec or reference expansion."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote

from ...discovery_sources import SourceManifest
from ...discovery_values import DiskBackedText
from ...storage_discovery import DiscoveryCollector

# Explicit API schema paths. envFrom/valueFrom are references, never plaintext
# values. Secrets/ConfigMaps are read by their own authorized source readers.
WORKLOADS = (
    ("pods", "/api/v1", ("spec",)),
    ("replicationcontrollers", "/api/v1", ("spec", "template", "spec")),
    ("deployments", "/apis/apps/v1", ("spec", "template", "spec")),
    ("replicasets", "/apis/apps/v1", ("spec", "template", "spec")),
    ("statefulsets", "/apis/apps/v1", ("spec", "template", "spec")),
    ("daemonsets", "/apis/apps/v1", ("spec", "template", "spec")),
    ("jobs", "/apis/batch/v1", ("spec", "template", "spec")),
    ("cronjobs", "/apis/batch/v1", ("spec", "jobTemplate", "spec", "template", "spec")),
)


def scan_workload_env(
    collector: DiscoveryCollector,
    *,
    namespaces: list[str],
    list_items: Callable[[str, Callable[[dict[str, Any]], None]], Any],
    manifest: SourceManifest,
) -> None:
    """List using the existing paged/disk reader and inspect each arriving item."""
    for resource, _api, _spec_path in WORKLOADS:
        manifest.declare("workload_env." + resource)
    for resource, api, spec_path in WORKLOADS:
        for namespace in dict.fromkeys(namespaces or [""]):
            source = "workload_env." + resource
            if not collector.allowed():
                return
            manifest.request(source, scope="selected_namespaces" if namespaces else "all_accessible_namespaces")
            base = api + ("/namespaces/" + quote(namespace, safe="") if namespace else "") + "/" + resource
            received = 0

            def consume(
                item: dict[str, Any],
                *,
                source: str = source,
                namespace: str = namespace,
                spec_path: tuple[str, ...] = spec_path,
                resource: str = resource,
            ) -> None:
                nonlocal received
                received += 1
                manifest.read(source)
                if not collector.allowed():
                    return
                metadata = item.get("metadata")
                if not isinstance(metadata, Mapping) or not isinstance(metadata.get("name"), str):
                    collector.partial(source, "invalid_workload_identity")
                    manifest.finish(source, complete=False)
                    return
                ns = metadata.get("namespace") or namespace
                if not isinstance(ns, str) or not ns or namespace and ns != namespace:
                    collector.partial(source, "invalid_workload_namespace")
                    manifest.finish(source, complete=False)
                    return
                pod_spec: Any = item
                for part in spec_path:
                    pod_spec = pod_spec.get(part) if isinstance(pod_spec, Mapping) else None
                if not isinstance(pod_spec, Mapping):
                    collector.partial(source, "invalid_workload_spec")
                    manifest.finish(source, complete=False)
                    return
                for kind in ("containers", "initContainers", "ephemeralContainers"):
                    containers = pod_spec.get(kind, [])
                    if not isinstance(containers, list):
                        collector.partial(source, "invalid_container_list")
                        manifest.finish(source, complete=False)
                        continue
                    for ci, container in enumerate(containers):
                        if not isinstance(container, Mapping):
                            collector.partial(source, "invalid_container")
                            manifest.finish(source, complete=False)
                            continue
                        envs = container.get("env", [])
                        if not isinstance(envs, list):
                            collector.partial(source, "invalid_env_list")
                            manifest.finish(source, complete=False)
                            continue
                        for ei, env in enumerate(envs):
                            if not collector.allowed():
                                manifest.finish(source, complete=False)
                                return
                            if not isinstance(env, Mapping) or not isinstance(env.get("name"), str) or not env["name"]:
                                collector.partial(source, "invalid_env_entry")
                                manifest.finish(source, complete=False)
                                continue
                            if "valueFrom" in env:
                                # References are not resolved with container exec.
                                # Their sources have separate ACL/coverage rows.
                                if "value" in env:
                                    collector.partial(source, "ambiguous_env_value_and_reference")
                                    manifest.finish(source, complete=False)
                                continue
                            if "value" not in env:
                                continue
                            value = env["value"]
                            if not isinstance(value, (str, DiskBackedText)):
                                collector.partial(source, "invalid_inline_env_value")
                                manifest.finish(source, complete=False)
                                continue
                            name = metadata["name"]
                            path = (
                                f"workloads.{resource}.{ns}.{name}."
                                + ".".join(spec_path)
                                + f".{kind}[{ci}].env[{ei}].value"
                            )
                            before = collector.partial_events
                            collector.add(
                                path,
                                value,
                                charge=False,
                                field_name=env["name"],
                                location={
                                    "source_kind": "workload_inline_env",
                                    "object": name,
                                    "resource": resource,
                                    "namespace": ns,
                                    "uid": metadata.get("uid"),
                                    "resource_version": metadata.get("resourceVersion"),
                                    "container": container.get("name"),
                                    "env": env["name"],
                                },
                            )
                            if collector.partial_events != before:
                                manifest.finish(source, complete=False)

            with collector.source_guard(manifest, source):
                result = list_items(base, consume)
                # Legacy/test readers can return items rather than forwarding them.
                if not received:
                    for item in result.items or ():
                        consume(item)
                if result.access_confirmed:
                    collector.mark_accessible_source()
                manifest.finish(
                    source,
                    complete=result.complete,
                    denied=result.status in {401, 403},
                    unsupported=result.status in {404, 405},
                )
                if not result.complete:
                    reason = (
                        "access_denied"
                        if result.status in {401, 403}
                        else "api_unavailable"
                        if result.status in {404, 405}
                        else result.error or "incomplete_workload_list"
                    )
                    collector.partial(source, reason)
