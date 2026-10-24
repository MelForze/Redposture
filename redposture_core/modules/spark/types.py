"""Spark Standalone audit defaults and typed detection outcomes."""

from typing import Literal

DEFAULT_PORTS = (8080, 6066)
DetectionStatus = Literal["confirmed", "not_service", "transport_failure", "unsupported_protocol"]
