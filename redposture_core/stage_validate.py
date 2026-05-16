"""Compatibility facade for saved-output validation."""

from __future__ import annotations

from .validate.engine import (
    VALIDATION_PRECISION_COLLECT_STRICT,
    VALIDATION_PRECISION_LEGACY,
    ValidationRecordAccumulator,
    run_validation,
    run_validation_records,
    scan_validation_hits,
)

__all__ = [
    "VALIDATION_PRECISION_COLLECT_STRICT",
    "VALIDATION_PRECISION_LEGACY",
    "ValidationRecordAccumulator",
    "run_validation",
    "run_validation_records",
    "scan_validation_hits",
]
