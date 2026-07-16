from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_compose_readiness import readiness_issues
from scripts.compose_published_ports import published_ports

ROOT = Path(__file__).resolve().parents[1]
MATRIX_SCRIPT = ROOT / "scripts" / "run_lab_matrix_sequential.sh"
FULL_COMPOSE = ROOT / "lab" / "full" / "docker-compose.yml"
EXPORTERS_COMPOSE = ROOT / "lab" / "services" / "exporters" / "docker-compose.yml"
PROXY_COMPOSE = ROOT / "lab" / "services" / "proxy-isolated" / "docker-compose.yml"


def _compose_service_block(text: str, service_name: str) -> str:
    marker = f"  {service_name}:"
    lines = text.splitlines()
    start = lines.index(marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def test_sequential_matrix_never_force_removes_external_port_occupants() -> None:
    script = MATRIX_SCRIPT.read_text(encoding="utf-8")

    assert "docker rm -f" not in script
    assert "lab port conflict: port=${port} container=${cid:0:12} name=${name:-unknown}" in script
    assert "refusing to remove ${conflicts} external port occupant(s)" in script
    assert 'compose_service "${service}" down -v' in script
    assert 'compose_service "${service}" config --format json' in script
    assert "compose_published_ports.py" in script
    assert "LAB_PORTS=(" not in script
    assert "--remove-orphans" not in script


def test_sequential_matrix_waits_for_nonempty_compose_state_and_nexus_seed() -> None:
    script = MATRIX_SCRIPT.read_text(encoding="utf-8")

    assert 'compose_service "${service}" ps --all' in script
    assert 'compose_service "${service}" ps --all -q' in script
    assert 'if [ "${service}" = "registry" ]; then' in script
    assert "timeout=900" in script
    assert "check_compose_readiness.py" in script
    for completed_name in (
        "redposture-lab-registry-seed",
        "redposture-lab-clickhouse-auth-seed",
        "redposture-lab-clickhouse-open-seed",
        "redposture-lab-redis-seed",
        "redposture-lab-etcd-auth-seed",
        "redposture-lab-etcd-seed",
        "redposture-lab-keeper-tls-certs",
    ):
        assert completed_name in script
    assert "--allow-completed redposture-lab-consul" not in script
    assert "--allow-completed redposture-lab-elastic" not in script
    assert 'grep -q "status=created"' in script
    assert 'compose_service "${service}" up -d --no-build' in script


def test_compose_port_extraction_covers_normalized_ports_and_ranges() -> None:
    payload = {
        "services": {
            "grafana": {"ports": [{"published": "13001"}, {"published": 13004}]},
            "registry": {"ports": [{"published": "15001-15013"}]},
            "grpc": {"ports": [{"published": "50051"}, {"published": "50061"}]},
            "kafka": {"ports": [{"published": "29092"}, {"published": "39092-39095"}]},
        }
    }

    ports = set(published_ports(payload))

    assert {13001, 13004, 15004, 50051, 50061, 29092, 39095} <= ports


@pytest.mark.parametrize(
    "state",
    [
        {"Status": "created", "ExitCode": 0},
        {"Status": "dead", "ExitCode": 0},
        {"Status": "removing", "ExitCode": 0},
        {"Status": "exited", "ExitCode": 0},
        {"Status": "running", "ExitCode": 0, "Health": {"Status": "starting"}},
        {"Status": "running", "ExitCode": 0, "Health": {"Status": "unhealthy"}},
    ],
)
def test_compose_readiness_rejects_non_ready_states(state: dict[str, object]) -> None:
    assert readiness_issues([{"Name": "/redposture-lab-test", "State": state}])


def test_compose_readiness_accepts_only_running_ready_or_explicit_completed() -> None:
    containers = [
        {"Name": "/plain", "State": {"Status": "running", "ExitCode": 0}},
        {
            "Name": "/healthy",
            "State": {"Status": "running", "ExitCode": 0, "Health": {"Status": "healthy"}},
        },
        {"Name": "/seed", "State": {"Status": "exited", "ExitCode": 0}},
    ]

    assert readiness_issues(containers, allowed_completed=frozenset({"seed"})) == []
    assert readiness_issues(containers)


def test_sequential_matrix_uses_valid_gitlab_and_grpc_extended_arguments() -> None:
    script = MATRIX_SCRIPT.read_text(encoding="utf-8")
    consul_line = next(line for line in script.splitlines() if "consul_extended_inventory_filters" in line)
    gitlab_line = next(line for line in script.splitlines() if "gitlab_extended_token_project_clone" in line)
    grpc_line = next(line for line in script.splitlines() if "grpc_extended_metadata_invoke" in line)
    proxmox_line = next(line for line in script.splitlines() if "proxmox_extended_defcreds_empty_password" in line)

    assert "--service redposture-api" in consul_line
    assert "--service svc-redposture-api" not in consul_line
    assert "--https" not in gitlab_line
    assert '--meta "x-redposture-matrix=extended"' in grpc_line
    assert "x-redposture-matrix: extended" not in grpc_line
    assert "--no-https" not in proxmox_line
    assert '-u root@pam -p ""' in proxmox_line


def test_matrix_ssrf_cases_use_reachable_targets_and_real_qdrant_snapshot() -> None:
    script = MATRIX_SCRIPT.read_text(encoding="utf-8")
    grafana_lines = [
        line
        for line in script.splitlines()
        if "grafana_ssrf_edge" in line or "grafana_extended_auth_ssrf_controls" in line
    ]
    consul_line = next(line for line in script.splitlines() if "consul_extended_ssrf_probe" in line)
    qdrant_line = next(line for line in script.splitlines() if "qdrant_extended_ssrf_probe" in line)

    assert grafana_lines
    assert all("grafana-2" in line and "/api/health" in line for line in grafana_lines)
    assert "127.0.0.1:19115" not in "\n".join(grafana_lines)
    assert "--ssrf-target consul --ssrf-port 8500 --ssrf-path /v1/status/leader" in consul_line
    assert "--ssrf-target host.docker.internal --ssrf-port 19115" in qdrant_line
    assert "--listen" in qdrant_line
    assert "REDPOSTURE_QDRANT_SSRF_RESPONSE_FILE" in script
    assert "/collections/demo_vectors/snapshots?wait=true" in script
    assert "/collections/demo_vectors/snapshots/${snapshot_name}" in script


def test_exporters_sublab_includes_every_matrix_exporter_port_owner() -> None:
    if not EXPORTERS_COMPOSE.exists():
        pytest.skip("the Docker lab is a local-only checkout")
    compose_text = EXPORTERS_COMPOSE.read_text(encoding="utf-8")

    assert "  proxmox-exporter:" in compose_text
    assert "service: proxmox-exporter" in compose_text


def test_proxy_sublab_seeds_redis_before_readiness() -> None:
    if not PROXY_COMPOSE.exists():
        pytest.skip("the Docker lab is a local-only checkout")
    proxy_redis = _compose_service_block(PROXY_COMPOSE.read_text(encoding="utf-8"), "proxy-redis")

    assert "redposture:proxy ready" in proxy_redis
    assert "redposture:route isolated" in proxy_redis
    assert "redposture:token proxy-seed-2026" in proxy_redis
    assert "redis-cli -h 127.0.0.1 dbsize" in proxy_redis


def test_full_lab_has_grafana_and_nexus_readiness_barriers() -> None:
    if not FULL_COMPOSE.exists():
        pytest.skip("the full Docker lab is a local-only checkout")
    compose_text = FULL_COMPOSE.read_text(encoding="utf-8")

    for service_name in ("grafana", "grafana-2", "grafana-3", "grafana-4", "grafana-5"):
        block = _compose_service_block(compose_text, service_name)
        assert "/api/health" in block
        assert "database" in block
        assert "ok" in block

    nexus_block = _compose_service_block(compose_text, "nexus")
    assert "/service/rest/v1/status" in nexus_block
    seed_block = _compose_service_block(compose_text, "nexus-seed")
    assert "depends_on:" in seed_block
    assert "nexus:" in seed_block
    assert "condition: service_healthy" in seed_block

    seed_command = seed_block
    assert "rm -f" in seed_command
    assert "seed_nexus.py" in seed_command
    assert "touch" in seed_command
    assert "tail -f /dev/null" in seed_command
    assert "redposture-nexus-seed-ready" in seed_block

    consul_block = _compose_service_block(compose_text, "consul")
    consul_acl_block = _compose_service_block(compose_text, "consul-acl")
    assert "-node=redposture-lab-consul" in consul_block
    assert "-node=redposture-lab-consul-acl" in consul_acl_block


def test_full_lab_clickhouse_open_allows_anonymous_network_access() -> None:
    if not FULL_COMPOSE.exists():
        pytest.skip("the full Docker lab is a local-only checkout")
    clickhouse_open = _compose_service_block(FULL_COMPOSE.read_text(encoding="utf-8"), "clickhouse-open")

    assert 'CLICKHOUSE_SKIP_USER_SETUP: "1"' in clickhouse_open
