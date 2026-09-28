"""Startup budgets for local real-product QA; independent of scanner timeouts."""

from __future__ import annotations

import os
import sys


def startup_timeout(fixture: str, explicit: int | None = None) -> int:
    raw = explicit if explicit is not None else os.environ.get("REDPOSTURE_QA_STARTUP_TIMEOUT")
    if raw is not None:
        value = int(raw)
        if value < 1:
            raise ValueError("QA startup timeout must be positive")
        return value
    if "gitlab" in fixture:
        return 2400
    if "oracle-licensed" in fixture:
        return 3600
    if "oracle" in fixture or "harbor" in fixture:
        return 1800
    if fixture == "registry":
        return 900
    return 300


if __name__ == "__main__":
    print(startup_timeout(sys.argv[1]))
