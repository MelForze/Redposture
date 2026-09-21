from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_minio_kubeapi_lab_pins_real_vendor_versions_and_tls_paths() -> None:
    compose = (ROOT / "tests/fixtures/minio_kubeapi_lab/docker-compose.yml").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/run_minio_kubeapi_lab.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify_minio_kubeapi_lab.py").read_text(encoding="utf-8")

    assert "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z" in compose
    assert "rancher/k3s:v1.27.5-k3s1" in compose
    assert "${MINIO_CERTS_DIR}:/root/.minio/certs:ro" in compose
    assert "openssl req -x509" in runner
    assert '"http://127.0.0.1:19000"' in verifier
    assert '"http://127.0.0.1:16443"' in verifier
    assert '"--defcreds"' in verifier
