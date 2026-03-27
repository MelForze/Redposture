"""Artifact encryption abstraction."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CipherResult:
    payload: bytes
    content_encoding: str | None = None


class ArtifactCipher:
    """Interface for optional artifact encryption-at-rest."""

    def encrypt(self, payload: bytes) -> CipherResult:
        raise NotImplementedError

    def decrypt(self, payload: bytes) -> bytes:
        raise NotImplementedError


class NoOpArtifactCipher(ArtifactCipher):
    """Default no-op artifact cipher."""

    def encrypt(self, payload: bytes) -> CipherResult:
        return CipherResult(payload=payload, content_encoding=None)

    def decrypt(self, payload: bytes) -> bytes:
        return payload
