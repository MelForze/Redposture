"""Regression checks for the short weak-password sweeps used by --defcreds."""

from __future__ import annotations

import pytest

from redposture_core.clients import kafka as kafka_client
from redposture_core.modules.airflow import actions as airflow
from redposture_core.modules.clickhouse import actions as clickhouse
from redposture_core.modules.elastic import actions as elastic
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.gitlab import stage as gitlab
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.grpc import actions as grpc
from redposture_core.modules.kubeapi import stage as kubeapi
from redposture_core.modules.minio import actions as minio
from redposture_core.modules.mongodb import actions as mongodb
from redposture_core.modules.oracle import actions as oracle
from redposture_core.modules.postgres import actions as postgres
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.modules.rabbitmq import actions as rabbitmq
from redposture_core.modules.redis import actions as redis
from redposture_core.modules.registry import stage as registry
from redposture_core.zookeeper_defaults import KEEPER_DIGEST_DEFAULT_CREDENTIALS, ZOOKEEPER_DIGEST_DEFAULT_CREDENTIALS


@pytest.mark.parametrize(
    ("module", "pairs", "candidate"),
    [
        ("airflow", airflow._DEFAULT_CREDENTIALS, ("admin", "12345678")),
        (
            "clickhouse",
            [(u, p) for u, p, _ in clickhouse._build_credential_candidates(None, None, True)],
            ("default", "12345678"),
        ),
        ("elastic", elastic._ELASTIC_DEFAULT_CREDENTIALS, ("elastic", "12345678")),
        ("opensearch", elastic._ELASTIC_DEFAULT_CREDENTIALS, ("admin", "12345678")),
        ("etcd", etcd._ETCD_DEFAULT_CREDS, ("root", "12345678")),
        ("gitlab", gitlab._GITLAB_BASIC_PAIRS, ("root", "12345678")),
        (
            "grafana",
            [(u, p) for u, p, _ in grafana._build_credential_candidates(None, None, True)],
            ("admin", "12345678"),
        ),
        ("grpc", grpc._DEFAULT_BASIC_CREDENTIALS, ("admin", "12345678")),
        ("kafka", kafka_client._KAFKA_DEFAULT_CREDENTIALS, ("admin", "12345678")),
        ("keeper", KEEPER_DIGEST_DEFAULT_CREDENTIALS, ("default", "12345678")),
        ("kubeapi", kubeapi._KUBE_BASIC_PAIRS, ("admin", "12345678")),
        ("minio", minio._MINIO_DEFAULT_CREDENTIALS, ("minioadmin", "12345678")),
        ("mongodb", mongodb._MONGODB_DEFAULT_CREDS, ("admin", "12345678")),
        ("oracle", oracle._ORACLE_DEFAULT_CREDS, ("system", "12345678")),
        ("postgres", postgres._POSTGRES_DEFAULT_CREDENTIALS, ("postgres", "12345678")),
        ("proxmox", proxmox._PROXMOX_DEFAULT_CREDENTIALS, ("root@pam", "12345678")),
        ("rabbitmq", rabbitmq.DEFAULT_CREDENTIALS, ("admin", "12345678")),
        ("redis", redis._REDIS_DEFAULT_CREDENTIALS, ("default", "12345678")),
        ("zookeeper", ZOOKEEPER_DIGEST_DEFAULT_CREDENTIALS, ("admin", "12345678")),
        ("harbor", (*registry._PRODUCT_BASIC_PAIRS["harbor"], *registry._WEAK_BASIC_PAIRS), ("admin", "12345678")),
        ("nexus", (*registry._PRODUCT_BASIC_PAIRS["nexus"], *registry._WEAK_BASIC_PAIRS), ("admin", "12345678")),
        (
            "docker-registry",
            (*registry._PRODUCT_BASIC_PAIRS["docker-registry"], *registry._WEAK_BASIC_PAIRS),
            ("admin", "12345678"),
        ),
    ],
)
def test_weak_eight_digit_candidate_reaches_applicable_auth_catalog(
    module: str, pairs: tuple[tuple[str, str], ...] | list[tuple[str, str]], candidate: tuple[str, str]
) -> None:
    assert candidate in pairs, module
    assert list(pairs).count(candidate) == 1
