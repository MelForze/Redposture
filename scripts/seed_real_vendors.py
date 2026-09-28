"""Seed tiny real Registry images and Harbor projects in isolated loopback labs."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def request(
    url: str, *, method: str = "GET", body: bytes | None = None, headers: dict[str, str] | None = None
) -> tuple[int, bytes, Any]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


def image_payloads() -> tuple[bytes, bytes, bytes]:
    raw_tar = bytes(10240)
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0, filename="") as compressed:
        compressed.write(raw_tar)
    layer = stream.getvalue()
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(raw_tar).hexdigest()]},
        },
        separators=(",", ":"),
    ).encode()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": len(config),
                "digest": "sha256:" + hashlib.sha256(config).hexdigest(),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": len(layer),
                    "digest": "sha256:" + hashlib.sha256(layer).hexdigest(),
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    return config, layer, manifest


def basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def push_image(base: str, repository: str, username: str, password: str) -> None:
    status, _, headers = request(base + "/v2/")
    auth = {"Authorization": basic(username, password)}
    challenge = headers.get("Www-Authenticate", "")
    if status == 401 and challenge.lower().startswith("bearer "):
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params["realm"]
        if urllib.parse.urlsplit(realm).hostname not in {"127.0.0.1", "localhost", "host.docker.internal"}:
            raise RuntimeError("fixture authentication realm is outside the local lab")
        if urllib.parse.urlsplit(realm).hostname == "host.docker.internal":
            parts = urllib.parse.urlsplit(realm)
            realm = urllib.parse.urlunsplit(
                (parts.scheme, urllib.parse.urlsplit(base).netloc, parts.path, parts.query, "")
            )
        query = urllib.parse.urlencode(
            {"service": params.get("service", ""), "scope": f"repository:{repository}:pull,push"}
        )
        status, body, _ = request(realm + ("&" if "?" in realm else "?") + query, headers=auth)
        assert status == 200, f"fixture token request failed: {status}"
        payload = json.loads(body)
        auth = {"Authorization": "Bearer " + (payload.get("token") or payload["access_token"])}
    config, layer, manifest = image_payloads()
    for blob in (config, layer):
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        status, _, _ = request(base + f"/v2/{repository}/blobs/{digest}", method="HEAD", headers=auth)
        if status == 200:
            continue
        status, _, headers = request(base + f"/v2/{repository}/blobs/uploads/", method="POST", body=b"", headers=auth)
        assert status == 202, f"blob initiation failed: {status}"
        location = urllib.parse.urlsplit(urllib.parse.urljoin(base, headers["Location"]))
        target = (
            base
            + location.path
            + "?"
            + urllib.parse.urlencode([*urllib.parse.parse_qsl(location.query), ("digest", digest)])
        )
        status, body, _ = request(
            target, method="PUT", body=blob, headers={**auth, "Content-Type": "application/octet-stream"}
        )
        assert status == 201, f"blob upload failed: {status} {body[:200]!r}"
    status, body, _ = request(
        base + f"/v2/{repository}/manifests/latest",
        method="PUT",
        body=manifest,
        headers={**auth, "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
    )
    assert status == 201, f"manifest upload failed: {status} {body[:200]!r}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vendor", choices=["harbor", "gitlab"])
    parser.add_argument("url")
    parser.add_argument("artifact_dir", type=Path)
    args = parser.parse_args()
    base = args.url.rstrip("/")
    assert urllib.parse.urlsplit(base).hostname in {"127.0.0.1", "localhost"}, "seed is restricted to loopback"
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    if args.vendor == "harbor":
        auth = {"Authorization": basic("admin", "Harbor12345"), "Content-Type": "application/json"}
        status, _, _ = request(base + "/api/v2.0/systeminfo")
        prefix = "/api/v2.0" if status == 200 else "/api"
        for name in ("core", "security"):
            status, body, _ = request(
                base + prefix + "/projects",
                method="POST",
                body=json.dumps(
                    {"project_name": name, "public": 1}
                    if prefix == "/api"
                    else {"project_name": name, "public": True, "metadata": {"public": "true"}}
                ).encode(),
                headers=auth,
            )
            assert status in {201, 409}, f"project seed failed: {status} {body[:200]!r}"
        repositories = ["core/control-plane", "security/scanner-adapter"]
        username, password = "admin", "Harbor12345"
    else:
        repositories = ["gitlab/project-api", "team/ops-sidecar"]
        username, password = "root", "glpat-redposture-lab-root-2026"
    for repository in repositories:
        push_image(base, repository, username, password)
        print(f"[seeded] {args.vendor} {repository}:latest", flush=True)
    (args.artifact_dir / "seed.json").write_text(
        json.dumps({"vendor": args.vendor, "url": base, "repositories": repositories}, indent=2) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
