"""Opt-in two-broker Kafka, retention, leader failover, compaction and UI parity."""

from __future__ import annotations

import collections
import json
import os
import re
import socket
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from scripts.qa_owned_lab import OwnedLab

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="explicit sequential real Kafka QA")
ROOT = Path(__file__).resolve().parents[1]


def available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_real_multi_broker_retention_failover_and_compaction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with OwnedLab(tmp_path / "kafka") as lab:
        ports = [available_port(), available_port()]
        common = {
            "CLUSTER_ID": "LxzRBSyNT-neGe7wyn5kSw",
            "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@one:9093",
            "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT",
            "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
            "KAFKA_INTER_BROKER_LISTENER_NAME": "INTERNAL",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
            "KAFKA_AUTO_CREATE_TOPICS_ENABLE": "false",
            "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
            "KAFKA_HEAP_OPTS": "-XX:ActiveProcessorCount=1 -Xms128M -Xmx256M",
            "KAFKA_LOG_CLEANER_BACKOFF_MS": "250",
            "KAFKA_LOG_CLEANER_DEDUPE_BUFFER_SIZE": "16777216",
        }
        for index, name in enumerate(("one", "two")):
            listeners = "INTERNAL://0.0.0.0:9092,EXTERNAL://0.0.0.0:9094" + (
                ",CONTROLLER://0.0.0.0:9093" if index == 0 else ""
            )
            env = {
                **common,
                "KAFKA_NODE_ID": str(index + 1),
                "KAFKA_PROCESS_ROLES": "broker,controller" if index == 0 else "broker",
                "KAFKA_LISTENERS": listeners,
                "KAFKA_ADVERTISED_LISTENERS": f"INTERNAL://{name}:9092,EXTERNAL://127.0.0.1:{ports[index]}",
            }
            lab.start(name, "confluentinc/cp-kafka:7.6.1", env=env, published={9094: ports[index]}, memory="640m")

        def tool(*args: str, **kw: Any) -> str:
            return lab.execute("one", "env", "KAFKA_HEAP_OPTS=-XX:ActiveProcessorCount=1 -Xms16M -Xmx64M", *args, **kw)

        lab.ready(
            "one",
            "env",
            "KAFKA_HEAP_OPTS=-XX:ActiveProcessorCount=1 -Xmx64M",
            "kafka-topics",
            "--bootstrap-server",
            "one:9092",
            "--list",
            seconds=120,
        )
        lab.ready(
            "two",
            "env",
            "KAFKA_HEAP_OPTS=-XX:ActiveProcessorCount=1 -Xmx64M",
            "kafka-topics",
            "--bootstrap-server",
            "two:9092",
            "--list",
            seconds=120,
        )
        tool(
            "kafka-topics",
            "--bootstrap-server",
            "one:9092",
            "--create",
            "--topic",
            "events",
            "--replica-assignment",
            "1:2,2:1,1:2",
        )
        expected_values = [json.dumps({"id": i, "seed": f"distributed-{i}"}, separators=(",", ":")) for i in range(150)]
        tool(
            "kafka-console-producer",
            "--bootstrap-server",
            "one:9092",
            "--topic",
            "events",
            "--property",
            "parse.key=true",
            "--property",
            "key.separator=:!:",
            "--producer-property",
            "acks=all",
            "--producer-property",
            "batch.size=0",
            input="\n".join(f"key-{i}:!:{value}" for i, value in enumerate(expected_values)) + "\n",
            timeout=60,
        )
        oracle = tool(
            "kafka-console-consumer",
            "--bootstrap-server",
            "one:9092",
            "--topic",
            "events",
            "--from-beginning",
            "--max-messages",
            "150",
            "--timeout-ms",
            "15000",
            "--property",
            "print.partition=true",
            "--property",
            "print.offset=true",
            timeout=45,
        )
        expected: dict[tuple[int, int], str] = {}
        for line in oracle.splitlines():
            match = re.fullmatch(r"Partition:(\d+)\tOffset:(\d+)\t(.*)", line)
            assert match, line
            expected[int(match[1]), int(match[2])] = match[3]
        assert len(expected) == 150 and {p for p, _ in expected} == {0, 1, 2}
        assert collections.Counter(expected.values()) == collections.Counter(expected_values)

        def audit(label: str, topic: str = "events", *, target: str | None = None) -> dict[str, Any]:
            raw = lab.run(
                sys.executable,
                str(ROOT / "redposture.py"),
                "kafka",
                "-t",
                target or f"127.0.0.1:{ports[0]}",
                "--timeout",
                "10",
                "--retries",
                "0",
                "--workers",
                "2",
                "--no-color",
                "--format",
                "json",
                "--topic",
                topic,
                "--dump",
                timeout=120,
            )
            (lab.out / (label + ".json")).write_text(raw)
            record = json.loads(next(line for line in raw.splitlines() if line.startswith("{")))
            if target:
                return record
            assert record.get("dump_error") is None and record.get("dump_errors") == {}, record
            assert record.get("dump_coverage", {}).get("complete") is True, record
            return record

        def positions(record: dict[str, Any], topic: str = "events") -> dict[tuple[int, int], str]:
            result: dict[tuple[int, int], str] = {}
            for row in record["dump_results"][topic]:
                match = re.fullmatch(r"p(\d+)@(\d+) (.*)", row)
                assert match, row
                key = int(match[1]), int(match[2])
                assert key not in result
                result[key] = match[3]
            return result

        assert positions(audit("initial")) == expected
        tool(
            "/bin/sh",
            "-c",
            "cat > /tmp/delete.json",
            input=json.dumps({"partitions": [{"topic": "events", "partition": 0, "offset": 5}], "version": 1}),
        )
        tool("kafka-delete-records", "--bootstrap-server", "one:9092", "--offset-json-file", "/tmp/delete.json")
        expected = {k: v for k, v in expected.items() if k[0] != 0 or k[1] >= 5}
        assert positions(audit("after-retention")) == expected
        # Stop a real leader between Fetch pages on an already authenticated socket.
        from redposture_core.clients import kafka

        session = kafka.KafkaSession.open(
            "127.0.0.1", ports[1], 2, username=None, password=None, use_tls=False, tls_config=None
        )
        try:
            ok, error = session.bootstrap(known_kafka=True)
            assert ok, error
            fetch_calls = 0
            original_send = kafka._send_kafka_request

            def send(sock: socket.socket, **kw: Any) -> bytes:
                nonlocal fetch_calls
                if kw["api_key"] == kafka.KAFKA_FETCH:
                    fetch_calls += 1
                    if fetch_calls == 2:
                        lab.docker("stop", "-t", "3", lab.owner + "-two", timeout=20)
                return original_send(sock, **kw)

            with monkeypatch.context() as patch:
                patch.setattr(kafka, "KAFKA_FETCH_MAX_BYTES", 160)
                patch.setattr(kafka, "_send_kafka_request", send)
                prefix, _corr, error = kafka._read_partition_messages_on_leader(
                    session.sock, session.correlation_id, "events", 1, None
                )
            assert error and fetch_calls == 2 and prefix, (error, fetch_calls, prefix)
            for row in prefix:
                match = re.fullmatch(r"p(\d+)@(\d+) (.*)", row)
                assert match and expected[int(match[1]), int(match[2])] == match[3]
            (lab.out / "mid-fetch-failure.json").write_text(
                json.dumps({"valid_prefix": prefix, "error": error, "fetch_calls": fetch_calls})
            )
        finally:
            session.close()
        # Readiness is a condition, not a fixed sleep: every partition must elect broker one.
        deadline = time.monotonic() + 45
        while True:
            describe = tool("kafka-topics", "--bootstrap-server", "one:9092", "--describe", "--topic", "events")
            leaders = re.findall(r"Partition:\s*\d+\s+Leader:\s*(-?\d+)", describe)
            if leaders == ["1", "1", "1"]:
                break
            assert time.monotonic() < deadline, describe
            time.sleep(0.5)
        assert positions(audit("after-leader-failover")) == expected
        for name, image in (
            ("kafbat", "ghcr.io/kafbat/kafka-ui:v1.5.0"),
            ("provectus", "provectuslabs/kafka-ui:v0.7.2"),
        ):
            lab.start(
                name,
                image,
                env={
                    "KAFKA_CLUSTERS_0_NAME": "qa",
                    "KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS": "one:9092",
                    "JAVA_TOOL_OPTIONS": "-XX:ActiveProcessorCount=1 -Xms64m -Xmx256m",
                },
                ports=(8080,),
                memory="512m",
            )
            try:
                base = f"http://127.0.0.1:{lab.port(name, 8080)}"
                deadline = time.monotonic() + 120
                while True:
                    try:
                        with urllib.request.urlopen(base + "/api/clusters", timeout=2) as reply:
                            clusters = json.load(reply)
                        if clusters and clusters[0].get("topicCount", 0) >= 1:
                            break
                    except (OSError, ValueError):
                        pass
                    assert time.monotonic() < deadline, name + " readiness"
                    time.sleep(0.5)
                record = audit(name, target=base)
                result = record["ui_export"]
                assert result["partial"] is False, record
                path = Path(result["path"])
                values = [
                    json.loads(line)["value"]
                    for line in (path if path.is_absolute() else lab.out / path).read_text().splitlines()
                ]
                actual = {(r["partition"], r["offset"]): r["value"] for r in values}
                assert len(values) == len(actual) and actual == expected
            finally:
                lab.collect_mounts()
                lab.docker("rm", "-f", "-v", lab.owner + "-" + name)
        # Single surviving broker now owns a compacted topic. Real cleaning must be observed.
        tool(
            "kafka-topics",
            "--bootstrap-server",
            "one:9092",
            "--create",
            "--topic",
            "compacted",
            "--partitions",
            "1",
            "--replication-factor",
            "1",
            "--config",
            "cleanup.policy=compact",
            "--config",
            "segment.ms=1000",
            "--config",
            "segment.bytes=1024",
            "--config",
            "min.cleanable.dirty.ratio=0.01",
            "--config",
            "max.compaction.lag.ms=1000",
        )
        for generation in range(3):
            tool(
                "kafka-console-producer",
                "--bootstrap-server",
                "one:9092",
                "--topic",
                "compacted",
                "--property",
                "parse.key=true",
                "--property",
                "key.separator=:",
                "--producer-property",
                "acks=all",
                input="\n".join(f"k{i % 5}:generation-{generation}-{i}" for i in range(40)) + "\n",
                timeout=30,
            )
        deadline = time.monotonic() + 45
        while True:
            compact = positions(audit("compacted", "compacted"), "compacted")
            if len(compact) < 120 and any((0, i) not in compact for i in range(max(o for _, o in compact))):
                break
            assert time.monotonic() < deadline, (
                "real compaction was not observed (stand readiness, not a product verdict)"
            )
            time.sleep(1)
        for i in range(35, 40):
            assert f"generation-2-{i}" in compact.values()
        (lab.out / "exact-oracle.json").write_text(
            json.dumps(
                {
                    "partitions": 3,
                    "seed_records": 150,
                    "after_retention": len(expected),
                    "failover_exact": True,
                    "compacted_positions": sorted(o for _, o in compact),
                },
                indent=2,
            )
        )
