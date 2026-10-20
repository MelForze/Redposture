"""Flatten Harbor's generated registry certificate bind for Docker Desktop QA.

The registry config directory is already mounted at /etc/registry. Materialize
its public certificate there instead of adding a nested bind into that mount.
Only the owned generated Harbor paths are eligible; other mounts stay intact.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path


def _replace_file(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-qa-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def prepare_compose(compose_path: Path) -> bool:
    """Repair one generated JSON compose; return False on an already-flat bind."""
    compose_path = compose_path.resolve()
    root = compose_path.parent
    payload = json.loads(compose_path.read_text())
    services = payload.get("services") if isinstance(payload, dict) else None
    registry = services.get("registry") if isinstance(services, dict) else None
    if not isinstance(registry, dict):
        raise ValueError("generated Harbor compose has no registry service")
    volumes = registry.get("volumes")
    if not isinstance(volumes, list):
        raise ValueError("generated Harbor compose has no registry volume mappings")
    children = [
        mount for mount in volumes if isinstance(mount, dict) and mount.get("target") == "/etc/registry/root.crt"
    ]
    if not children:
        return False
    parents = [mount for mount in volumes if isinstance(mount, dict) and mount.get("target") == "/etc/registry"]
    if len(children) != 1 or len(parents) != 1:
        raise ValueError("expected one registry config bind and one nested root.crt bind")
    if not str(registry.get("image") or "").startswith("goharbor/registry-photon:"):
        raise ValueError("registry certificate workaround only supports the generated Harbor registry image")

    def owned_source(mount: dict, relative: str) -> Path:
        if mount.get("type") != "bind" or not isinstance(mount.get("source"), str):
            raise ValueError("expected generated Harbor bind source")
        source = Path(mount["source"])
        resolved = (source if source.is_absolute() else root / source).resolve()
        if resolved != root / relative:
            raise ValueError(f"bind source is not the owned generated Harbor {relative}")
        return resolved

    config = owned_source(parents[0], "common/config/registry")
    certificate = owned_source(children[0], "data/secret/registry/root.crt")
    if not config.is_dir() or not certificate.is_file():
        raise ValueError("generated Harbor registry config or root certificate is missing")
    destination = config / "root.crt"
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError("generated registry root.crt destination must be a regular file")
    content = certificate.read_bytes()
    if not content:
        raise ValueError("generated registry root certificate is empty")
    # This is the public verification certificate, not the private signing key.
    # Harbor prepare emits its source as 0600; the registry must be able to read
    # the copied file even when its container runs with a different UID.
    _replace_file(destination, content, 0o644)
    registry["volumes"] = [mount for mount in volumes if mount is not children[0]]
    _replace_file(compose_path, (json.dumps(payload, indent=2) + "\n").encode(), compose_path.stat().st_mode & 0o777)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose", type=Path, help="Owned generated Harbor JSON compose file")
    args = parser.parse_args()
    try:
        changed = prepare_compose(args.compose)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"[error] Harbor QA compose: {exc}\n")
    print(
        "Harbor QA registry certificate: " + ("copied into config; nested bind removed" if changed else "already flat")
    )


if __name__ == "__main__":
    main()
