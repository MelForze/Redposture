"""The real MinIO QA image uses pinned, verified vendor release assets."""

from __future__ import annotations

import hashlib
import io
import subprocess
from pathlib import Path

import pytest

from scripts import prepare_minio_qa_image as image


def test_release_urls_are_pinned_to_official_architecture_specific_assets() -> None:
    assert image.release_urls("arm64") == (
        "https://github.com/minio/minio/releases/download/RELEASE.2025-04-22T22-12-26Z/"
        "minio.linux-arm64.RELEASE.2025-04-22T22-12-26Z",
        "https://github.com/minio/mc/releases/download/RELEASE.2025-04-16T18-13-26Z/"
        "mc.linux-arm64.RELEASE.2025-04-16T18-13-26Z",
    )
    with pytest.raises(ValueError, match="unsupported architecture"):
        image.release_urls("s390x")


def test_verified_download_rejects_corruption_without_leaving_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"official-test-binary"
    checksum = hashlib.sha256(payload).hexdigest()

    def open_url(request: object, timeout: int) -> io.BytesIO:
        del timeout
        url = request.full_url  # type: ignore[attr-defined]
        return io.BytesIO((checksum + "  release-binary\n").encode() if url.endswith(".sha256sum") else payload)

    monkeypatch.setattr(image.urllib.request, "urlopen", open_url)
    destination = tmp_path / "minio"
    image.download_verified("https://github.com/minio/minio/releases/download/tag/binary", destination)
    assert destination.read_bytes() == payload

    destination.unlink()
    monkeypatch.setattr(
        image.urllib.request,
        "urlopen",
        lambda request, timeout: (
            io.BytesIO(b"0" * 64 + b" binary\n") if request.full_url.endswith(".sha256sum") else io.BytesIO(payload)
        ),
    )
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        image.download_verified("https://github.com/minio/minio/releases/download/tag/binary", destination)
    assert not destination.exists()


def test_existing_image_is_reused_without_network_or_build(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        release = image.MINIO_RELEASE if command[6].endswith("/minio") else image.MC_RELEASE
        return subprocess.CompletedProcess(command, 0, f"version {release}\n", "")

    monkeypatch.setattr(image.subprocess, "run", run)
    monkeypatch.setattr(image, "download_verified", lambda *_args: pytest.fail("unexpected download"))
    assert image.prepare_image("arm64") == image.IMAGE_TAG
    assert commands[0] == ["docker", "image", "inspect", image.IMAGE_TAG]
    assert len(commands) == 3
    assert all(command[:3] == ["docker", "run", "--pull"] for command in commands[1:])


def test_existing_image_with_wrong_release_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "wrong release", "")

    monkeypatch.setattr(image.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="unexpected MinIO version"):
        image.prepare_image("arm64")
