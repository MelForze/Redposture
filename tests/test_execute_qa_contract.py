"""Contracts for the isolated real-product execute QA stands."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "tests/fixtures/execute/docker-compose.yml"
RUNNER = ROOT / "scripts/run_execute_qa.py"


def test_execute_compose_has_four_independent_profiles_and_loopback_ports() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    for profile in ("kafka", "portainer", "jenkins", "consul"):
        assert f"profiles: [{profile}]" in text
    for port in ("19089", "19443", "19580", "19500"):
        assert f"127.0.0.1:{port}:" in text
    assert "KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:9092" in text
    assert "-enable-script-checks=true" in text


def test_portainer_stand_never_mounts_a_host_docker_socket() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    assert "/var/run/docker.sock" not in text
    assert "portainer-engine:" in text
    assert "127.0.0.1:19237:2375" in text


def test_execute_runner_covers_all_surfaces_and_always_cleans_up() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    for module in ("kafka", "portainer", "jenkins", "consul"):
        assert f'"{module}"' in text
    assert '"down", "-v", "--remove-orphans"' in text
    assert "finally:" in text
    assert '"executed") is not True' in text
    assert '"exit_code") != 7' in text


def test_execute_fixture_build_context_is_checkout_owned() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    assert "context: ./jenkins" in text
    dockerfile = COMPOSE.parent / "jenkins/Dockerfile"
    assert dockerfile.is_file()
    assert "COPY init.groovy " in dockerfile.read_text(encoding="utf-8")
    assert (dockerfile.parent / "init.groovy").is_file()
    runner = RUNNER.read_text(encoding="utf-8")
    assert 'ROOT / "tests" / "fixtures" / "execute" / "docker-compose.yml"' in runner


def test_execute_qa_docs_keep_kafka_broker_and_ui_separate() -> None:
    text = (ROOT / "tests/fixtures/execute/README.md").read_text(encoding="utf-8")
    assert "real single-node Kafka broker" in text
    assert "configured broker" in text
    assert "Docker-in-Docker" in text
