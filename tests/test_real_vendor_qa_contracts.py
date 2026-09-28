from __future__ import annotations

import copy
import gzip
import hashlib
import json

import pytest

from scripts.seed_real_vendors import image_payloads
from scripts.verify_valkey_lab import validate_valkey_record


def test_seeded_image_is_portable_and_content_addressed() -> None:
    config, layer, manifest_raw = image_payloads()
    assert image_payloads() == (config, layer, manifest_raw)
    manifest = json.loads(manifest_raw)
    assert manifest["schemaVersion"] == 2
    assert manifest["config"]["digest"] == "sha256:" + hashlib.sha256(config).hexdigest()
    assert manifest["layers"][0]["digest"] == "sha256:" + hashlib.sha256(layer).hexdigest()
    assert manifest["layers"][0]["size"] == len(layer)
    assert json.loads(config)["rootfs"]["diff_ids"] == ["sha256:" + hashlib.sha256(gzip.decompress(layer)).hexdigest()]


@pytest.mark.parametrize(
    "mutation", ["compatibility_version", "wrong_implementation", "wrong_product", "redis_cve", "failed_credentials"]
)
def test_valkey_qa_rejects_redis_identity_or_false_auth_success(mutation) -> None:
    record = {
        "is_redis": True,
        "implementation": "valkey",
        "valkey_version": "8.0.10",
        "server_version": "8.0.10",
        "redis_version": None,
        "provided_credentials_ok": True,
        "cve_enumeration": {"status": "no_matches", "products": [{"product_key": "valkey"}], "findings": []},
    }
    validate_valkey_record(copy.deepcopy(record), version_known=True, credentials=True)
    if mutation == "compatibility_version":
        record["redis_version"] = "7.2.4"
    elif mutation == "wrong_implementation":
        record["implementation"] = "redis"
    elif mutation == "wrong_product":
        record["cve_enumeration"]["products"][0]["product_key"] = "redis"
    elif mutation == "redis_cve":
        record["cve_enumeration"]["findings"] = [{"product": "redis"}]
    else:
        record["provided_credentials_ok"] = False
    with pytest.raises(AssertionError):
        validate_valkey_record(record, version_known=True, credentials=True)
