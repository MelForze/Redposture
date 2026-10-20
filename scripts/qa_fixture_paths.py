"""Resolve portable fixture bindings without depending on ignored lab symlinks."""

from __future__ import annotations

from pathlib import Path


def compose_file(root: Path, fixture: str) -> Path:
    if fixture == "token-apis":
        return root / "tests/fixtures/token_apis/docker-compose.yml"
    return root / "lab/services" / fixture / "docker-compose.yml"
