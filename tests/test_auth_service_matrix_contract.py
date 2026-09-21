from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_real_auth_matrix_pins_services_and_exercises_three_auth_states() -> None:
    compose = (ROOT / "tests/fixtures/auth_service_matrix/docker-compose.yml").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/run_auth_service_matrix.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify_auth_service_matrix.py").read_text(encoding="utf-8")

    for image in (
        "postgres:16.4-alpine",
        "mongo:7.0.14",
        "elasticsearch:8.15.0",
        "rabbitmq:3.13.7-management-alpine",
        "apache/kafka:3.7.2",
    ):
        assert image in compose
    for module in ("postgres", "mongodb", "elastic", "rabbitmq", "kafka"):
        assert f'AuthCase("{module}"' in verifier
    assert "_wait_for_anonymous_result(case)" in verifier
    assert "valid = _scan" in verifier
    assert "invalid = _scan" in verifier
    assert "down --volumes --remove-orphans" in runner
