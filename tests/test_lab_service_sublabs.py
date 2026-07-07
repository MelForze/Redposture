"""Structural tests for the split registry sub-labs.

The registry aggregate lab bundles four independent registry flavors:
Docker Registry v2, Harbor, Nexus, and the GitLab Container Registry mock.
Nexus alone is a ~1.5 GB image with a ~4 min first-boot penalty, so for
focused iteration each flavor lives in its own compose file under
`lab/services/registry-*`.

These tests pin the invariants of that split so a future refactor can't
silently regress the "boot only what you need" contract. Parsing avoids
PyYAML because the CI environment ships a stdlib-only interpreter.
"""

from __future__ import annotations

import re
from pathlib import Path

_SUBLABS = {
    "registry-docker": {"registry-open", "registry-seed", "registry-auth"},
    "registry-harbor": {"harbor-mock"},
    "registry-nexus": {"nexus", "nexus-seed"},
    "registry-gitlab": {"gitlab-registry-mock"},
}

# Sub-labs that use REAL images (not `extends:` into lab/full/docker-compose.yml)
# so the "must extend the shared compose" invariant does NOT apply to them.
# They are opt-in heavy stands: real GitLab CE / Harbor / Proxmox VE.
_REAL_SUBLABS = {
    "gitlab-real": {"gitlab-real"},
    "registry-harbor-real": {
        "harbor-real-db",
        "harbor-real-redis",
        "harbor-real-registry",
        "harbor-real-core",
    },
    "proxmox-real": {"proxmox-real"},
}

# Match top-level `services:` block members: two-space indent + name + ":".
_TOP_SERVICE_RE = re.compile(r"^  ([a-zA-Z0-9_-]+):\s*$", re.MULTILINE)
# Match `extends: file: ...` and `service: ...` pairs inside a service block.
_EXTENDS_FILE_RE = re.compile(r"^\s+file:\s*(.+?)\s*$", re.MULTILINE)
_EXTENDS_SERVICE_RE = re.compile(r"^\s+service:\s*(.+?)\s*$", re.MULTILINE)


def _services_and_extends(path: Path) -> dict[str, tuple[str, str]]:
    """Return `{service_name: (extends_file, extends_service)}`.

    Uses regex parsing tolerant of the compose files' fixed 2-space indent
    convention. The lab files are generated + hand-formatted with that
    convention, so this is stable enough without adding a YAML dep.
    """
    text = path.read_text(encoding="utf-8")
    # Only consider content AFTER `services:` (skip volumes/networks blocks).
    if "\nservices:\n" in text:
        text = text.split("\nservices:\n", 1)[1]
    # Cut off at `volumes:` or `networks:` if present.
    for sentinel in ("\nvolumes:\n", "\nnetworks:\n"):
        if sentinel in text:
            text = text.split(sentinel, 1)[0]

    result: dict[str, tuple[str, str]] = {}
    # Split into per-service chunks using top-level lookahead.
    matches = list(_TOP_SERVICE_RE.finditer(text))
    for idx, match in enumerate(matches):
        name = match.group(1)
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        chunk = text[start:end]
        file_m = _EXTENDS_FILE_RE.search(chunk)
        svc_m = _EXTENDS_SERVICE_RE.search(chunk)
        result[name] = (
            file_m.group(1) if file_m else "",
            svc_m.group(1) if svc_m else "",
        )
    return result


def test_each_registry_sublab_directory_exists_and_has_a_compose_file(lab_services_dir: Path) -> None:
    for sublab in _SUBLABS:
        sublab_dir = lab_services_dir / sublab
        assert sublab_dir.is_dir(), f"missing sub-lab directory: {sublab_dir}"
        compose = sublab_dir / "docker-compose.yml"
        assert compose.is_file(), f"missing compose file for {sublab}: {compose}"


def test_each_registry_sublab_declares_exactly_its_expected_services(lab_services_dir: Path) -> None:
    """Every registry sub-lab must declare ONLY the services relevant to its
    flavor — no cross-pollination — so `docker compose up` on one doesn't
    drag the entire bundle in."""
    for sublab, expected_services in _SUBLABS.items():
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        actual = set(services.keys())
        assert actual == expected_services, (
            f"{sublab} services drifted: expected={sorted(expected_services)} actual={sorted(actual)}"
        )


def test_registry_sublabs_extend_lab_full_docker_compose(lab_services_dir: Path) -> None:
    """Sub-labs must reference `lab/full/docker-compose.yml` via `extends` so
    the definitions stay single-sourced."""
    for sublab in _SUBLABS:
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        for name, (file_ref, ext_service) in services.items():
            assert file_ref, f"{sublab}:{name} has no `extends: file:` line"
            assert "lab/full/docker-compose.yml" in file_ref, f"{sublab}:{name} extends the wrong file: {file_ref!r}"
            assert ext_service == name, f"{sublab}:{name} extends a mismatched service: {ext_service!r}"


def test_registry_aggregate_lab_still_boots_all_four_flavors(lab_services_dir: Path) -> None:
    """The aggregate `lab/services/registry/` compose must remain a superset
    of every split sub-lab — teams that want a bundle boot are unaffected."""
    aggregate_services = set(_services_and_extends(lab_services_dir / "registry" / "docker-compose.yml").keys())
    expected_union = {svc for names in _SUBLABS.values() for svc in names}
    missing = expected_union - aggregate_services
    assert not missing, f"registry aggregate is missing sub-lab services: {sorted(missing)}"


def test_registry_sublab_readme_pointer_in_aggregate_compose(lab_services_dir: Path) -> None:
    """The aggregate compose's header comment must advertise the sub-labs so
    a new contributor discovers the split path without opening every file."""
    text = (lab_services_dir / "registry" / "docker-compose.yml").read_text(encoding="utf-8")
    for sublab in _SUBLABS:
        assert sublab in text, f"aggregate compose does not mention sub-lab: {sublab}"


# ---------------------------------------------------------------------------
# Real (non-mock) opt-in sub-labs
# ---------------------------------------------------------------------------


def test_each_real_sublab_directory_exists_and_has_a_compose_file(lab_services_dir: Path) -> None:
    for sublab in _REAL_SUBLABS:
        sublab_dir = lab_services_dir / sublab
        assert sublab_dir.is_dir(), f"missing real sub-lab directory: {sublab_dir}"
        compose = sublab_dir / "docker-compose.yml"
        assert compose.is_file(), f"missing compose file for {sublab}: {compose}"


def test_each_real_sublab_declares_exactly_its_expected_services(lab_services_dir: Path) -> None:
    for sublab, expected_services in _REAL_SUBLABS.items():
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        actual = set(services.keys())
        assert actual == expected_services, (
            f"{sublab} services drifted: expected={sorted(expected_services)} actual={sorted(actual)}"
        )


def test_real_sublabs_do_not_extend_lab_full(lab_services_dir: Path) -> None:
    """Real sub-labs must NOT `extends:` into the shared lab/full compose —
    they intentionally live standalone so their heavy images (~3 GB GitLab CE,
    ~1.2 GB Harbor bundle, ~2 GB Proxmox VE) are opt-in rather than being
    dragged in by the aggregate lab."""
    for sublab in _REAL_SUBLABS:
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        for name, (file_ref, _ext_svc) in services.items():
            assert not file_ref, f"{sublab}:{name} extends {file_ref!r} — real sub-labs must be self-contained"


def test_real_sublab_docstring_warns_about_resource_cost(lab_services_dir: Path) -> None:
    """Every real sub-lab compose header must warn about resource cost
    (image size / boot time / RAM). Prevents someone silently ballooning
    the CI matrix onto machines that can't run them."""
    for sublab in _REAL_SUBLABS:
        text = (lab_services_dir / sublab / "docker-compose.yml").read_text(encoding="utf-8")
        # Case-insensitive search — the boilerplate uses ⚠ or `warning` / `Resource`.
        assert "⚠" in text or "resource cost" in text.lower() or "resource_cost" in text.lower(), (
            f"{sublab} compose does not carry a resource-cost warning in the header"
        )


def test_gitlab_real_carries_credentials_hint_in_compose_comment(lab_services_dir: Path) -> None:
    """The GitLab CE image emits a randomly-generated root password on first
    boot. The compose comment must point at that discovery path."""
    text = (lab_services_dir / "gitlab-real" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "initial_root_password" in text or "cat /etc/gitlab" in text, (
        "gitlab-real compose must document how to discover the root password"
    )


def test_proxmox_real_documents_kvm_platform_requirement(lab_services_dir: Path) -> None:
    """`dockurr/proxmox` nests KVM inside Docker — it does not work on
    Docker Desktop (macOS / Windows) or on arm64. Compose must warn."""
    text = (lab_services_dir / "proxmox-real" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "KVM" in text or "kvm" in text, "proxmox-real compose must mention KVM requirement"
    assert "macOS" in text or "arm64" in text, "proxmox-real compose must call out the unsupported platforms"


# ---------------------------------------------------------------------------
# Kafka SASL_SSL sub-lab (`kafka-tls/`)
# ---------------------------------------------------------------------------

# Kept in its own map because the registry-focused invariants above
# (aggregate-superset check, README pointer check) don't apply — Kafka has
# its own aggregate compose and its own docs section.
_KAFKA_SUBLABS = {
    "kafka-tls": {"kafka-tls", "kafka-tls-seed"},
}


def test_each_kafka_sublab_directory_exists_and_has_a_compose_file(lab_services_dir: Path) -> None:
    for sublab in _KAFKA_SUBLABS:
        sublab_dir = lab_services_dir / sublab
        assert sublab_dir.is_dir(), f"missing kafka sub-lab directory: {sublab_dir}"
        compose = sublab_dir / "docker-compose.yml"
        assert compose.is_file(), f"missing compose file for {sublab}: {compose}"


def test_each_kafka_sublab_declares_exactly_its_expected_services(lab_services_dir: Path) -> None:
    for sublab, expected_services in _KAFKA_SUBLABS.items():
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        actual = set(services.keys())
        assert actual == expected_services, (
            f"{sublab} services drifted: expected={sorted(expected_services)} actual={sorted(actual)}"
        )


def test_kafka_sublabs_extend_lab_full_docker_compose(lab_services_dir: Path) -> None:
    """The kafka-tls sub-lab must reference `lab/full/docker-compose.yml`
    via `extends` — mirrors the registry-sub-lab invariant so service
    definitions stay single-sourced."""
    for sublab in _KAFKA_SUBLABS:
        services = _services_and_extends(lab_services_dir / sublab / "docker-compose.yml")
        for name, (file_ref, ext_service) in services.items():
            assert file_ref, f"{sublab}:{name} has no `extends: file:` line"
            assert "lab/full/docker-compose.yml" in file_ref, f"{sublab}:{name} extends the wrong file: {file_ref!r}"
            assert ext_service == name, f"{sublab}:{name} extends a mismatched service: {ext_service!r}"


def test_kafka_aggregate_lab_includes_all_kafka_sublab_services(lab_services_dir: Path) -> None:
    """The `lab/services/kafka/` aggregate compose must remain a superset of
    every kafka sub-lab — the TLS broker should be reachable from the
    "boot everything Kafka" entrypoint too."""
    aggregate_services = set(_services_and_extends(lab_services_dir / "kafka" / "docker-compose.yml").keys())
    expected_union = {svc for names in _KAFKA_SUBLABS.values() for svc in names}
    missing = expected_union - aggregate_services
    assert not missing, f"kafka aggregate is missing sub-lab services: {sorted(missing)}"
