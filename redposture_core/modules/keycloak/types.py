"""Keycloak module type declarations."""

from __future__ import annotations

from typing import Literal

DetectionStatus = Literal["confirmed", "probable", "not_service", "transport_failure"]

__all__ = ["DetectionStatus"]
