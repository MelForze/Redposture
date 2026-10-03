#!/usr/bin/env python3
"""Prepare a local MinIO QA image from verified official release assets."""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

IMAGE_TAG = "redposture-minio-qa:RELEASE.2025-04-22T22-12-26Z"
MINIO_RELEASE = "RELEASE.2025-04-22T22-12-26Z"
MC_RELEASE = "RELEASE.2025-04-16T18-13-26Z"
_ARCHITECTURES = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64"}


def release_urls(architecture: str) -> tuple[str, str]:
    try:
        arch = _ARCHITECTURES[architecture]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {architecture}") from exc
    return (
        f"https://github.com/minio/minio/releases/download/{MINIO_RELEASE}/minio.linux-{arch}.{MINIO_RELEASE}",
        f"https://github.com/minio/mc/releases/download/{MC_RELEASE}/mc.linux-{arch}.{MC_RELEASE}",
    )


def download_verified(url: str, destination: Path) -> None:
    checksum_request = urllib.request.Request(url + ".sha256sum", headers={"User-Agent": "Redposture-QA"})
    with urllib.request.urlopen(checksum_request, timeout=30) as response:
        checksum_text = response.read(256).decode("ascii")
    match = re.match(r"^([0-9a-f]{64})\s+", checksum_text)
    if match is None:
        raise ValueError(f"invalid SHA-256 checksum for {url}")
    expected = match.group(1)
    request = urllib.request.Request(url, headers={"User-Agent": "Redposture-QA"})
    temporary = destination.with_name(destination.name + ".partial")
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError(f"SHA-256 mismatch for {url}")
        temporary.chmod(0o755)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def verify_image() -> None:
    for executable, expected in (("minio", MINIO_RELEASE), ("mc", MC_RELEASE)):
        result = subprocess.run(
            [
                "docker",
                "run",
                "--pull",
                "never",
                "--rm",
                "--entrypoint",
                f"/usr/local/bin/{executable}",
                IMAGE_TAG,
                "--version",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        if expected not in result.stdout:
            name = "MinIO" if executable == "minio" else "mc"
            raise RuntimeError(f"QA image has unexpected {name} version: {result.stdout.strip()}")


def prepare_image(architecture: str) -> str:
    release_urls(architecture)
    present = subprocess.run(
        ["docker", "image", "inspect", IMAGE_TAG], capture_output=True, text=True, check=False, timeout=30
    )
    if present.returncode == 0:
        verify_image()
        print(f"[minio-qa] using existing {IMAGE_TAG}", flush=True)
        return IMAGE_TAG
    with tempfile.TemporaryDirectory(prefix="redposture-minio-qa-") as directory:
        context = Path(directory)
        server_url, client_url = release_urls(architecture)
        for url, filename in ((server_url, "minio"), (client_url, "mc")):
            print(f"[minio-qa] downloading {url}", flush=True)
            download_verified(url, context / filename)
        (context / "Dockerfile").write_text(
            "\n".join(
                (
                    "FROM alpine:3.21.3",
                    "COPY minio /usr/local/bin/minio",
                    "COPY mc /usr/local/bin/mc",
                    "ENV MC_CONFIG_DIR=/tmp/.mc",
                    'ENTRYPOINT ["/usr/local/bin/minio"]',
                    "",
                )
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                "docker",
                "build",
                "--pull=false",
                "--platform",
                f"linux/{_ARCHITECTURES[architecture]}",
                "-t",
                IMAGE_TAG,
                str(context),
            ],
            check=True,
            timeout=900,
        )
    verify_image()
    print(f"[minio-qa] prepared {IMAGE_TAG}", flush=True)
    return IMAGE_TAG


def main() -> int:
    result = subprocess.run(
        ["docker", "info", "--format", "{{.Architecture}}"], capture_output=True, text=True, check=True, timeout=30
    )
    prepare_image(result.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
