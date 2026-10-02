"""Audited connection-lifecycle strategy for network-facing modules."""

from __future__ import annotations

from typing import Final, Literal

TransportStrategy = Literal["reusable_lifecycle", "identity_session", "existing_pool"]

# This is intentionally exhaustive: adding a network module requires choosing
# and testing one of the supported ownership strategies instead of silently
# creating a fresh connection for every endpoint request.
MODULE_TRANSPORT_STRATEGY: Final[dict[str, TransportStrategy]] = {
    "clickhouse": "existing_pool",
    "consul": "reusable_lifecycle",
    "docker": "reusable_lifecycle",
    "docker-registry": "reusable_lifecycle",
    "elastic": "existing_pool",
    "etcd": "reusable_lifecycle",
    "exporters": "existing_pool",
    "gitlab": "reusable_lifecycle",
    "grafana": "reusable_lifecycle",
    "grpc": "existing_pool",
    "harbor": "reusable_lifecycle",
    "kafka": "identity_session",
    "kubeapi": "reusable_lifecycle",
    "mongodb": "identity_session",
    "nexus": "reusable_lifecycle",
    "oracle": "identity_session",
    "postgres": "identity_session",
    "proxmox": "reusable_lifecycle",
    "qdrant": "reusable_lifecycle",
    "redis": "existing_pool",
    "zookeeper": "existing_pool",
}

__all__ = ["MODULE_TRANSPORT_STRATEGY", "TransportStrategy"]
