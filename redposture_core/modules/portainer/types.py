"""In-memory Portainer identity and session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PortainerLifecycleState:
    ui_session_token: str | None = None
    ui_session_api_key: str | None = None
    blocked: bool = False
    sessions: dict[tuple[Any, ...], dict[str, str]] = field(default_factory=dict)
    execution: dict[str, Any] | None = None


__all__ = ["PortainerLifecycleState"]
