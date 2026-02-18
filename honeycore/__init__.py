"""RedPosture core package."""

from __future__ import annotations

from importlib import metadata

try:
    __version__ = metadata.version("redposture")
except metadata.PackageNotFoundError:
    __version__ = "1.0.2+local"

__all__ = ["__version__"]
