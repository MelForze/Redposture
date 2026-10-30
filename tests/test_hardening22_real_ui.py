"""Opt-in real panels with isolated backends and a loopback TLS/prefix proxy.

The proxy is a test transport, not a real nginx deployment. Product inventory
and login requests reach the genuine products; no host Docker socket is used.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from scripts.bootstrap_ui_lab import onboard_redisinsight
from scripts.qa_owned_lab import OwnedLab
from scripts.qa_tls_prefix_proxy import proxy

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="explicit serial real-panel QA")
ROOT = Path(__file__).resolve().parents[1]


def api(
    base: str,
    path: str,
    value: Any = None,
    *,
    method: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5,
) -> Any:
    body = json.dumps(value).encode() if value is not None else None
    request = urllib.request.Request(
        base + path, body, headers={"Content-Type": "application/json", **(headers or {})}, method=method
    )
    with urllib.request.urlopen(request, timeout=timeout, context=ssl._create_unverified_context()) as response:
        raw = response.read()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def ready(base: str, path: str, *, seconds: float = 120, allow_auth: bool = True, evidence: Path | None = None) -> None:
    statuses: list[int | str] = []
    deadline = time.monotonic() + seconds
    while True:
        try:
            api(base, path)
            statuses.append(200)
            if evidence:
                evidence.write_text(json.dumps(statuses))
            return
        except urllib.error.HTTPError as exc:
            statuses.append(exc.code)
            if allow_auth and exc.code in (401, 403):
                return
        except (OSError, ValueError) as exc:
            statuses.append(str(exc))
        if evidence:
            evidence.write_text(json.dumps(statuses))
        assert time.monotonic() < deadline, base + path + " readiness timeout"
        time.sleep(0.5)


def audit(lab: OwnedLab, module: str, target: str, *flags: str, label: str = "audit") -> dict[str, Any]:
    raw = lab.run(
        sys.executable,
        str(ROOT / "redposture.py"),
        module,
        "-t",
        target,
        "--timeout",
        "8",
        "--retries",
        "0",
        "--workers",
        "2",
        "--no-color",
        "--format",
        "json",
        *flags,
        timeout=180,
    )
    (lab.out / (label + ".json")).write_text(raw)
    assert "\x1b" not in raw
    rows = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    assert len(rows) == 1, raw[-2000:]
    return rows[0]


def exported(lab: OwnedLab, record: dict[str, Any], seed: str) -> None:
    assert record["surface"] == "ui", record
    result = record["ui"]["inventory"]["export"]
    assert result["partial"] is False, record
    path = Path(result["path"])
    raw = (path if path.is_absolute() else lab.out / path).read_text()
    assert seed in raw and "\x1b" not in raw
    rows = raw.splitlines()
    assert len(rows) == result["count"] == len(set(rows))
    assert record.get("backend_credentials_ok") is not True


@pytest.mark.parametrize("product", ["minio", "mongo", "redis", "pgadmin"])
def test_real_panel_seeded_dump_tls_and_prefix(tmp_path: Path, mtls_material: dict[str, Path], product: str) -> None:
    with OwnedLab(tmp_path / product) as lab:
        auth: tuple[str, ...] = ()
        flags: tuple[str, ...] = ()
        if product == "minio":
            lab.start(
                "minio",
                "redposture-minio-qa:RELEASE.2025-04-22T22-12-26Z",
                command=("server", "/data", "--console-address", ":9001"),
                env={
                    "MINIO_ROOT_USER": "minioadmin",
                    "MINIO_ROOT_PASSWORD": "minioadmin",
                    "MC_HOST_local": "http://minioadmin:minioadmin@127.0.0.1:9000",
                },
                ports=(9000, 9001),
            )
            lab.ready("minio", "mc", "ready", "local")
            lab.execute(
                "minio",
                "/bin/sh",
                "-c",
                "mc mb local/qa-data && printf seeded-minio-content | mc pipe local/qa-data/known.txt",
            )
            upstream = f"http://127.0.0.1:{lab.port('minio', 9001)}"
            module, seed, flags = "minio", "seeded-minio-content", ("--dump",)
            auth = ("-u", "minioadmin", "-p", "minioadmin")
        elif product == "mongo":
            lab.start("mongo", "mongo:7.0.14", ports=(27017,), memory="512m")
            lab.ready("mongo", "mongosh", "--quiet", "--eval", "db.adminCommand({ping:1})")
            lab.execute(
                "mongo",
                "mongosh",
                "--quiet",
                "--eval",
                'db.getSiblingDB("qa").values.insertMany([{_id:ObjectId("507f1f77bcf86cd799439011"),value:"seeded-mongo-content"},{_id:UUID("00112233-4455-6677-8899-aabbccddeeff"),value:"seeded-binary-id-content"}])',
            )
            lab.start(
                "ui",
                "mongo-express:1.0.2-20",
                env={
                    "ME_CONFIG_MONGODB_URL": "mongodb://mongo:27017/",
                    "ME_CONFIG_BASICAUTH_ENABLED": "true",
                    "ME_CONFIG_BASICAUTH_USERNAME": "reader",
                    "ME_CONFIG_BASICAUTH_PASSWORD": "reader-pass-22",
                },
                ports=(8081,),
                memory="256m",
            )
            upstream = f"http://127.0.0.1:{lab.port('ui', 8081)}"
            module, seed, flags = "mongodb", "seeded-mongo-content", ("--database", "qa", "--dump")
            auth = ("-u", "reader", "-p", "reader-pass-22")
            ready(upstream, "/")
            hidden = audit(lab, "mongodb", upstream, *auth, label="generic-basic-hidden")
            assert hidden.get("ui_product") is None and hidden.get("provided_credentials_ok") is not True, hidden
            # Generic Basic hides all product signals: pairs must not be sent.
            # Separately verify the genuine public panel with its real backend.
            lab.collect_mounts()
            lab.docker("rm", "-f", lab.owner + "-ui")
            lab.start(
                "ui",
                "mongo-express:1.0.2-20",
                env={
                    "ME_CONFIG_MONGODB_URL": "mongodb://mongo:27017/",
                    "ME_CONFIG_BASICAUTH_ENABLED": "false",
                    "ME_CONFIG_BASICAUTH": "false",
                },
                ports=(8081,),
                memory="256m",
            )
            upstream = f"http://127.0.0.1:{lab.port('ui', 8081)}"
            auth = ()
        elif product == "redis":
            lab.start("redis", "redis:7.4.11-alpine", command=("redis-server", "--requirepass", "reader-pass-22"))
            lab.ready("redis", "redis-cli", "-a", "reader-pass-22", "PING")
            lab.execute("redis", "redis-cli", "-a", "reader-pass-22", "SET", "qa:key", "seeded-redis-content")
            lab.start(
                "ui",
                "redis/redisinsight:2.68",
                env={"RI_ACCEPT_TERMS_AND_CONDITIONS": "true", "RI_ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef"},
                ports=(5540,),
                memory="512m",
            )
            upstream = f"http://127.0.0.1:{lab.port('ui', 5540)}"
            ready(upstream, "/api/info")
            onboard_redisinsight(upstream)
            module, seed, flags = "redis", "seeded-redis-content", ("--show-keys", "--dump")
        else:
            lab.start(
                "postgres",
                "postgres:16.15-alpine",
                env={"POSTGRES_USER": "reader", "POSTGRES_PASSWORD": "reader-pass-22", "POSTGRES_DB": "qa"},
            )
            lab.ready("postgres", "pg_isready", "-U", "reader", "-d", "qa")
            lab.execute(
                "postgres",
                "psql",
                "-U",
                "reader",
                "-d",
                "qa",
                "-c",
                "CREATE TABLE known(value text); INSERT INTO known VALUES('seeded-pgadmin-content')",
            )
            servers = lab.out / "servers.json"
            servers.write_text(
                json.dumps(
                    {
                        "Servers": {
                            "1": {
                                "Name": "qa",
                                "Group": "Servers",
                                "Host": "postgres",
                                "Port": 5432,
                                "MaintenanceDB": "qa",
                                "Username": "reader",
                                "SSLMode": "prefer",
                            }
                        }
                    }
                )
            )
            lab.start(
                "ui",
                "dpage/pgadmin4:9.9",
                env={
                    "PGADMIN_DEFAULT_EMAIL": "qa@example.com",
                    "PGADMIN_DEFAULT_PASSWORD": "admin-password-22",
                    "PGADMIN_REPLACE_SERVERS_ON_STARTUP": "True",
                },
                mounts=(str(servers) + ":/pgadmin4/servers.json:ro",),
                ports=(80,),
                memory="512m",
            )
            upstream = f"http://127.0.0.1:{lab.port('ui', 80)}"
            module, seed, flags = (
                "postgres",
                "seeded-pgadmin-content",
                (
                    "--pgadmin-server-password",
                    "reader-pass-22",
                    "--database",
                    "qa",
                    "--table",
                    "public.known",
                    "--dump",
                ),
            )
            auth = ("-u", "qa@example.com", "-p", "admin-password-22")
        ready(upstream, "/api/info" if product == "redis" else "/")
        if product == "mongo":
            # Keep independent wire evidence when HTML/BSON document parsing differs.
            import re

            collection_html = api(upstream, "/db/qa/values")
            (lab.out / "collection.html").write_text(str(collection_html))
            for number, document_path in enumerate(
                re.findall(r"loadDocument\(['\"]([^'\"]+)['\"]\)", str(collection_html))
            ):
                try:
                    raw_document = api(upstream, document_path)
                    (lab.out / f"document-{number}.txt").write_text(str(raw_document))
                except urllib.error.HTTPError as exc:
                    (lab.out / f"document-{number}.txt").write_text(
                        str(exc) + "\n" + exc.read().decode(errors="replace")
                    )
        # Direct HTTP, then TLS with a base path, on the same real product.
        direct = audit(lab, module, upstream, *auth, *flags, label="direct")
        exported(lab, direct, seed)
        assert (
            direct["ui"]["inventory"]["export"]["count"] == {"minio": 2, "mongo": 4, "redis": 2, "pgadmin": 4}[product]
        )
        if product == "mongo":
            exported(lab, direct, "seeded-binary-id-content")
        with proxy(upstream, mtls_material) as base:
            proxied = audit(lab, module, base, *auth, *flags, label="tls-prefix")
            exported(lab, proxied, seed)
            if product == "mongo":
                exported(lab, proxied, "seeded-binary-id-content")
        (lab.out / "scenario.json").write_text(
            json.dumps(
                {
                    "real_product": product,
                    "direct_seed_exact": True,
                    "tls_prefix_seed_exact": True,
                    "backend_identity_not_inherited": True,
                }
            )
        )


@pytest.mark.parametrize("product", ["kibana", "dashboards"])
def test_real_dashboard_devtools_seed(tmp_path: Path, mtls_material: dict[str, Path], product: str) -> None:
    with OwnedLab(tmp_path / product) as lab:
        opensearch = product == "dashboards"
        image = (
            "opensearchproject/opensearch:2.14.0"
            if opensearch
            else "docker.elastic.co/elasticsearch/elasticsearch:8.13.4"
        )
        env = {
            "discovery.type": "single-node",
            "cluster.routing.allocation.disk.threshold_enabled": "false",
            **(
                {
                    "DISABLE_SECURITY_PLUGIN": "true",
                    "OPENSEARCH_JAVA_OPTS": "-XX:ActiveProcessorCount=1 -Xms256m -Xmx256m",
                }
                if opensearch
                else {"xpack.security.enabled": "false", "ES_JAVA_OPTS": "-XX:ActiveProcessorCount=1 -Xms256m -Xmx256m"}
            ),
        }
        lab.start("backend", image, env=env, ports=(9200,), memory="768m")
        backend = f"http://127.0.0.1:{lab.port('backend', 9200)}"
        ready(backend, "/", seconds=120)
        # Root/version being ready does not guarantee index creation is ready.
        ready(backend, "/_cluster/health?wait_for_status=yellow&timeout=30s", seconds=120)
        api(backend, "/qa/_doc/one?refresh=true", {"password": "qa-dashboard-secret-22"}, method="PUT", timeout=30)
        image = (
            "opensearchproject/opensearch-dashboards:2.14.0" if opensearch else "docker.elastic.co/kibana/kibana:8.13.4"
        )
        env = (
            {"OPENSEARCH_HOSTS": '["http://backend:9200"]', "DISABLE_SECURITY_DASHBOARDS_PLUGIN": "true"}
            if opensearch
            else {"ELASTICSEARCH_HOSTS": "http://backend:9200", "SERVER_HOST": "0.0.0.0", "TELEMETRY_ENABLED": "false"}
        )
        lab.start("ui", image, env={**env, "NODE_OPTIONS": "--max-old-space-size=384"}, ports=(5601,), memory="768m")
        upstream = f"http://127.0.0.1:{lab.port('ui', 5601)}"
        ready(upstream, "/api/status", seconds=240, allow_auth=False, evidence=lab.out / "api-status-readiness.json")
        # UI --cluster includes the read-only Dev Tools route; full documents via discover.
        with proxy(upstream, mtls_material) as base:
            value = audit(lab, "elastic", base, "--cluster", "--discover", label=product)
            assert value.get("surface") == "ui", value
            assert value.get("ui_product") == ("opensearch_dashboards" if opensearch else "kibana"), value
            assert value.get("ui", {}).get("inventory"), value
            assert "qa-dashboard-secret-22" in json.dumps(value), value
            discovery = value["ui"]["inventory"]["discover"]
            if opensearch:
                pipeline = discovery["discover_coverage"]["surfaces"]["ingest_pipelines"]
                assert pipeline["status"] == "unsupported" and pipeline["error_detail"]["status"] == 404
                assert discovery["partial"] is True  # A missing UI endpoint is not full coverage.
            (lab.out / "scenario.json").write_text(
                json.dumps({"real_product": product, "tls_prefix_ui_confirmed": True, "record": value}, default=str)
            )


def test_real_portainer_sees_only_disposable_engine(tmp_path: Path) -> None:
    with OwnedLab(tmp_path / "portainer") as lab:
        tar = lab.out / "alpine.tar"
        lab.docker("image", "save", "-o", str(tar), "alpine:3.20")
        lab.start(
            "engine",
            "docker:27.5.1-dind",
            command=("dockerd", "--host=tcp://0.0.0.0:2375", "--tls=false"),
            env={"DOCKER_TLS_CERTDIR": ""},
            mounts=(str(tar) + ":/seed.tar:ro",),
            memory="512m",
            privileged=True,
        )
        lab.ready("engine", "docker", "-H", "tcp://127.0.0.1:2375", "info", seconds=90)
        lab.execute("engine", "docker", "-H", "tcp://127.0.0.1:2375", "load", "-i", "/seed.tar")
        lab.execute(
            "engine",
            "docker",
            "-H",
            "tcp://127.0.0.1:2375",
            "create",
            "--pull=never",
            "--name",
            "qa-seeded-container",
            "alpine:3.20",
            "true",
        )
        lab.start("ui", "portainer/portainer-ce:2.39.7", command=("--no-setup-token",), ports=(9443,), memory="256m")
        base = f"https://127.0.0.1:{lab.port('ui', 9443)}"
        ready(base, "/api/system/status")
        api(base, "/api/users/admin/init", {"Username": "admin", "Password": "portainer-password-22"})
        auth = api(base, "/api/auth", {"Username": "admin", "Password": "portainer-password-22"})
        boundary = "rphard22-boundary"
        fields = {"Name": "qa-own-engine", "EndpointCreationType": "1", "URL": "tcp://engine:2375", "TLS": "false"}
        body = (
            "".join(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in fields.items()
            )
            + f"--{boundary}--\r\n"
        ).encode()
        request = urllib.request.Request(
            base + "/api/endpoints",
            body,
            headers={
                "Content-Type": "multipart/form-data; boundary=" + boundary,
                "Authorization": "Bearer " + auth["jwt"],
            },
        )
        with urllib.request.urlopen(request, timeout=15, context=ssl._create_unverified_context()) as reply:
            assert reply.status == 200
        record = audit(
            lab,
            "portainer",
            base,
            "-u",
            "admin",
            "-p",
            "portainer-password-22",
            "--show-endpoints",
            "--show-containers",
            "--show-images",
            "--show-networks",
            "--show-volumes",
            "--show-system",
        )
        inventory = record["ui"]["inventory"]
        assert record.get("provided_credentials_ok") is True, record
        assert inventory["containers"]["count"] == 1 and "qa-seeded-container" in json.dumps(inventory["containers"])
        assert all(
            not inventory[key].get("partial")
            for key in ("environments", "containers", "images", "networks", "volumes", "system")
        )
