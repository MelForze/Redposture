"""ResourceManager structured fingerprint outcomes."""

from typing import Literal

DetectionStatus = Literal["confirmed", "probable", "not_service", "transport_failure"]

__all__ = ["DetectionStatus"]
