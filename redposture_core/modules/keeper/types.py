"""Keeper module type aliases for the shared ZooKeeper-protocol engine."""

from __future__ import annotations

from ..zookeeper.types import ZooKeeperFingerprintCache


class KeeperFingerprintCache(ZooKeeperFingerprintCache):
    """Keeper-branded bounded fingerprint cache."""


__all__ = ["KeeperFingerprintCache"]
