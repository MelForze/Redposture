"""Descriptors for runtime attributes forwarded by legacy module facades."""

from __future__ import annotations

from collections.abc import Mapping
from types import ModuleType
from typing import Any


def bind_runtime_properties(facade_type: type[ModuleType], bindings: Mapping[str, tuple[ModuleType, str]]) -> None:
    """Expose forwarded state as descriptors, rather than implicit __getattr__.

    Assigning an alias changes its real owner, not just the facade's namespace.
    A data descriptor makes that contract explicit to tools restoring attributes
    (including pytest 9.2's monkeypatch), and prevents stale facade copies.
    """
    for alias, (owner, attribute) in bindings.items():

        def get(_self: ModuleType, owner: ModuleType = owner, attribute: str = attribute) -> Any:
            return getattr(owner, attribute)

        def set_value(_self: ModuleType, value: Any, owner: ModuleType = owner, attribute: str = attribute) -> None:
            setattr(owner, attribute, value)

        setattr(facade_type, alias, property(get, set_value))
