"""Interfaces for lazy, disk-owned discovery containers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class DiskContainer:
    """Marker: preserve ownership instead of recursively copying a container."""

    @property
    def byte_length(self) -> int:
        raise NotImplementedError

    @property
    def reference_owner(self) -> Any:
        raise NotImplementedError

    @property
    def reference_locator(self) -> Any:
        raise NotImplementedError


class DiskSequence(DiskContainer, list[Any]):
    """List-shaped view whose elements live outside the Python heap."""


class DiskMapping(DiskContainer, Mapping[Any, Any]):
    """Mapping-shaped view whose keys/values live outside the Python heap."""
