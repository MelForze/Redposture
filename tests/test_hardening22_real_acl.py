"""Opt-in real ACL tests; one limited Docker product at a time.

REDPOSTURE_REAL_QA=1 python -m pytest tests/test_hardening22_real_acl.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.qa_owned_lab import OwnedLab

pytestmark = pytest.mark.skipif(
    os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="explicit sequential real-product QA"
)
ROOT = Path(__file__).resolve().parents[1]


def cli(lab: OwnedLab, module: str, port: int, *flags: str) -> dict[str, Any]:
    raw = lab.run(
        sys.executable,
        str(ROOT / "redposture.py"),
        module,
        "-t",
        f"127.0.0.1:{port}",
        "--timeout",
        "3",
        "--retries",
        "0",
        "--workers",
        "2",
        "--no-color",
        "--format",
        "json",
        *flags,
        timeout=120,
    )
    assert "\x1b" not in raw
    values = (
        json.loads(raw)
        if raw.lstrip().startswith("[")
        else [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    )
    if isinstance(values, dict):
        values = [values]
    records = [x for x in values if x.get("type") != "summary"]
    assert len(records) == 1, records
    return records[0]


@pytest.mark.parametrize("image", ["redis:7.4.11-alpine", "redis:8.0-alpine"])
def test_real_redis_restricted_keys_are_denied_without_rejecting_identity(tmp_path: Path, image: str) -> None:
    with OwnedLab(tmp_path / "redis") as lab:
        lab.start("redis", image, ports=(6379,))
        lab.ready("redis", "redis-cli", "PING")
        lab.execute("redis", "redis-cli", "SET", "allowed:one", "acl-seed")
        lab.execute("redis", "redis-cli", "SET", "denied:one", "must-not-read")
        lab.execute(
            "redis",
            "redis-cli",
            "ACL",
            "SETUSER",
            "reader",
            "on",
            ">reader-pass-22",
            "~allowed:*",
            "+auth",
            "+ping",
            "+hello",
            "+info",
            "+scan",
            "+type",
            "+get",
            "+dbsize",
        )
        port = lab.port("redis", 6379)
        good = cli(lab, "redis", port, "-u", "reader", "-p", "reader-pass-22", "--show-keys", "--dump")
        bad = cli(lab, "redis", port, "-u", "reader", "-p", "wrong-pass-22")
        assert good["provided_credentials_ok"] is True, good
        assert bad["provided_credentials_ok"] is False, bad
        rows = {x["key"]: x for x in good["key_value_entries"]}
        assert rows["allowed:one"]["value"] == "acl-seed"
        assert rows["denied:one"]["value"] is None and "NOPERM" in rows["denied:one"]["error"]
        assert "must-not-read" not in json.dumps(good)


@pytest.mark.parametrize("image", ["postgres:16.4-alpine", "postgres:16.15-alpine"])
def test_real_postgres_table_acl_is_not_a_password_verdict(tmp_path: Path, image: str) -> None:
    with OwnedLab(tmp_path / "postgres") as lab:
        lab.start("pg", image, env={"POSTGRES_PASSWORD": "root-pass-22", "POSTGRES_DB": "qa22"}, ports=(5432,))
        lab.ready("pg", "pg_isready", "-U", "postgres", "-d", "qa22")
        sql = "CREATE USER reader PASSWORD 'reader-pass-22'; CREATE TABLE allowed(id int, value text); INSERT INTO allowed VALUES(1,'pg-acl-seed'); CREATE TABLE denied(value text); INSERT INTO denied VALUES('must-not-read'); GRANT CONNECT ON DATABASE qa22 TO reader; GRANT USAGE ON SCHEMA public TO reader; GRANT SELECT ON allowed TO reader;"
        lab.execute("pg", "psql", "-U", "postgres", "-d", "qa22", "-v", "ON_ERROR_STOP=1", "-c", sql)
        port = lab.port("pg", 5432)
        common = ("-u", "reader", "-p", "reader-pass-22", "--database", "qa22")
        good = cli(lab, "postgres", port, *common, "--table", "public.allowed", "--dump")
        denied = cli(lab, "postgres", port, *common, "--table", "public.denied", "--dump")
        bad = cli(lab, "postgres", port, "-u", "reader", "-p", "wrong-pass-22", "--database", "qa22")
        assert good["status"] == denied["status"] == "valid_credentials", (good, denied)
        assert bad["status"] == "auth_required", bad
        assert "pg-acl-seed" in json.dumps(good["table_dumps"])
        assert "must-not-read" not in json.dumps(denied)
        assert denied.get("error") != "authentication failed", denied
        assert "denied" in json.dumps(denied).lower() and "permission" in json.dumps(denied).lower()


@pytest.mark.parametrize("image", ["mongo:7.0.14", "mongo:7.0.43"])
def test_real_mongodb_database_acl_keeps_valid_scram_identity(tmp_path: Path, image: str) -> None:
    with OwnedLab(tmp_path / "mongo") as lab:
        lab.start(
            "mongo",
            image,
            env={"MONGO_INITDB_ROOT_USERNAME": "root", "MONGO_INITDB_ROOT_PASSWORD": "root-pass-22"},
            ports=(27017,),
            memory="512m",
        )
        shell = (
            "mongosh",
            "--quiet",
            "-u",
            "root",
            "-p",
            "root-pass-22",
            "--authenticationDatabase",
            "admin",
            "--eval",
        )
        lab.ready("mongo", *shell, "db.adminCommand({ping:1})")
        lab.execute(
            "mongo",
            *shell,
            'db.getSiblingDB("allowed").values.insertOne({_id:1,value:"mongo-acl-seed"}); db.getSiblingDB("denied").values.insertOne({_id:1,value:"must-not-read"}); db.getSiblingDB("admin").createUser({user:"reader",pwd:"reader-pass-22",roles:[{role:"read",db:"allowed"}]})',
        )
        port = lab.port("mongo", 27017)
        common = ("-u", "reader", "-p", "reader-pass-22", "--auth-db", "admin")
        good = cli(lab, "mongodb", port, *common, "--database", "allowed", "--collection", "values", "--dump")
        denied = cli(lab, "mongodb", port, *common, "--database", "denied", "--collection", "values", "--dump")
        bad = cli(lab, "mongodb", port, "-u", "reader", "-p", "wrong-pass-22")
        assert good.get("provided_credentials_ok") is True and denied.get("provided_credentials_ok") is True, (
            good,
            denied,
        )
        assert bad.get("provided_credentials_ok") is False, bad
        assert "mongo-acl-seed" in json.dumps(good)
        assert "must-not-read" not in json.dumps(denied)
        assert denied.get("error") == "authorization denied", denied
        assert any(x in json.dumps(denied).lower() for x in ("unauthorized", "not authorized", "denied"))


def test_real_minio_bucket_reader_verifies_credentials_without_admin_rights(tmp_path: Path) -> None:
    with OwnedLab(tmp_path / "minio") as lab:
        lab.start(
            "minio",
            "redposture-minio-qa:RELEASE.2025-04-22T22-12-26Z",
            command=("server", "/data"),
            env={
                "MINIO_ROOT_USER": "minioadmin",
                "MINIO_ROOT_PASSWORD": "minioadmin",
                "MC_HOST_local": "http://minioadmin:minioadmin@127.0.0.1:9000",
            },
            ports=(9000,),
        )
        lab.ready("minio", "mc", "ready", "local")
        lab.execute(
            "minio", "/bin/sh", "-c", "mc mb local/qa-data && printf minio-acl-seed | mc pipe local/qa-data/known.txt"
        )
        lab.execute("minio", "mc", "admin", "user", "add", "local", "reader", "reader-pass-22")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::qa-data"],
                },
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::qa-data/*"]},
            ],
        }
        lab.execute("minio", "/bin/sh", "-c", "cat > /tmp/read-policy.json", input=json.dumps(policy))
        lab.execute("minio", "mc", "admin", "policy", "create", "local", "qa-read", "/tmp/read-policy.json")
        lab.execute("minio", "mc", "admin", "policy", "attach", "local", "qa-read", "--user", "reader")
        port = lab.port("minio", 9000)
        good = cli(
            lab,
            "minio",
            port,
            "-u",
            "reader",
            "-p",
            "reader-pass-22",
            "--bucket",
            "qa-data",
            "--object",
            "known.txt",
            "--dump",
        )
        bad = cli(lab, "minio", port, "-u", "reader", "-p", "wrong-pass-22", "--bucket", "qa-data")
        assert good.get("provided_credentials_ok") is True, good
        assert good.get("admin_capability") in {"not_confirmed", "unknown"}, good
        assert "minio-acl-seed" in json.dumps(good), good
        assert bad.get("provided_credentials_ok") is False, bad


@pytest.mark.parametrize("phase", ["startup", "seed", "dump"])
def test_real_failure_cleanup_preserves_original_resources(tmp_path: Path, phase: str) -> None:
    lab = OwnedLab(tmp_path / phase)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            with lab:
                lab.start("redis", "redis:7.4.11-alpine", ports=(6379,))
                if phase != "startup":
                    lab.ready("redis", "redis-cli", "PING")
                    lab.execute("redis", "redis-cli", "SET", "qa:owned", "preserved-until-teardown")
                if phase == "dump":
                    value = cli(lab, "redis", lab.port("redis", 6379), "--show-keys", "--dump")
                    assert "preserved-until-teardown" in json.dumps(value)
                raise RuntimeError("injected " + phase + " failure")
    finally:
        assert not lab.docker("ps", "-aq", "--filter", "label=" + lab.label).strip()
