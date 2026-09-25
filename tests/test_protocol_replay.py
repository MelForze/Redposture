"""Replay stable binary wire samples through the production protocol parsers."""

from __future__ import annotations

import json
from pathlib import Path

from redposture_core.clients import kafka, oracle, zookeeper

FIXTURE = Path(__file__).parent / "fixtures" / "protocol_replay" / "wire_samples.json"


def test_protocol_replay_fixture_is_versioned_and_has_provenance() -> None:
    corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert corpus["schema_version"] == 1
    assert {sample["protocol"] for sample in corpus["samples"]} == {"kafka", "zookeeper", "oracle_tns"}
    for sample in corpus["samples"]:
        assert sample["capture_context"]
        assert bytes.fromhex(sample["payload_hex"])


def test_replay_real_binary_protocol_samples() -> None:
    corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))
    samples = {sample["protocol"]: sample for sample in corpus["samples"]}

    kafka_sample = samples["kafka"]
    kafka_result = kafka._parse_apiversions_response(
        bytes.fromhex(kafka_sample["payload_hex"]),
        kafka_sample["expected"]["correlation_id"],
    )
    assert kafka_result.ok is True
    assert kafka_result.error is None
    assert kafka_result.versions[kafka.KAFKA_FETCH] == (
        kafka_sample["expected"]["fetch_min"],
        kafka_sample["expected"]["fetch_max"],
    )

    zookeeper._parse_connect_response(bytes.fromhex(samples["zookeeper"]["payload_hex"]))

    oracle_sample = samples["oracle_tns"]
    oracle_result = oracle.parse_tns_packet(bytes.fromhex(oracle_sample["payload_hex"]))
    assert oracle_result["type"] == oracle_sample["expected"]["packet_type"]
    assert oracle_sample["expected"]["contains"] in oracle_result["text"]


def test_truncated_replay_samples_fail_closed() -> None:
    corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))
    samples = {sample["protocol"]: bytes.fromhex(sample["payload_hex"]) for sample in corpus["samples"]}

    kafka_result = kafka._parse_apiversions_response(samples["kafka"][:-1], 9)
    assert kafka_result.ok is False

    try:
        zookeeper._parse_connect_response(samples["zookeeper"][:-8])
    except ValueError:
        pass
    else:
        raise AssertionError("truncated ZooKeeper replay was accepted")

    try:
        oracle.parse_tns_packet(samples["oracle_tns"][:-1])
    except oracle.OracleTnsError:
        pass
    else:
        raise AssertionError("truncated Oracle replay was accepted")
