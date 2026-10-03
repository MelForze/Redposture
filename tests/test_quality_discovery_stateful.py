"""State-machine checks for target-wide discovery budgets and deduplication."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow.discover import _collection
from redposture_core.modules.clickhouse.discover.inventory import collect_inventory, quote_identifier
from redposture_core.modules.elastic.discover import DiscoverOptions, DiscoveryBudget
from redposture_core.modules.minio.discover import Budget
from redposture_core.modules.proxmox import actions as proxmox_actions


class ElasticBudgetMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.now = 0.0
        self.model_documents = 0
        self.model_bytes = 0
        self.model_stopped = False
        self.budget = DiscoveryBudget(
            DiscoverOptions(max_documents=5, max_source_bytes=50, max_seconds=10, max_findings=3),
            monotonic=lambda: self.now,
        )

    @rule(length=st.integers(0, 70))
    def document(self, length: int) -> None:
        expected = (
            not self.model_stopped
            and self.now < 10
            and self.model_documents + 1 <= 5
            and self.model_bytes + length <= 50
        )
        actual = self.budget.consume_document(length)
        assert actual is expected
        if expected:
            self.model_documents += 1
            self.model_bytes += length
        else:
            self.model_stopped = True

    @rule(length=st.integers(0, 70))
    def richer_source(self, length: int) -> None:
        expected = not self.model_stopped and self.now < 10 and self.model_bytes + length <= 50
        actual = self.budget.consume_source_bytes(length)
        assert actual is expected
        if expected:
            self.model_bytes += length
        else:
            self.model_stopped = True

    @rule(seconds=st.integers(0, 11))
    def advance_clock(self, seconds: int) -> None:
        self.now += seconds
        if self.now >= 10:
            self.model_stopped = True
            assert self.budget.check() is False

    @invariant()
    def never_exceed_budgets(self) -> None:
        assert self.budget.documents == self.model_documents <= 5
        assert self.budget.source_bytes == self.model_bytes <= 50


TestElasticBudgetMachine = ElasticBudgetMachine.TestCase


class MinioClaimMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.budget = Budget(max_total_bytes=50)
        self.claimed = 0

    @rule(length=st.integers(0, 70))
    def claim_and_release(self, length: int) -> None:
        granted = self.budget.claim(length)
        assert granted == min(length, 50 - self.claimed)
        self.claimed += granted
        if granted:
            self.budget.release(granted)
            self.claimed -= granted

    @invariant()
    def reservation_never_exceeds_limit(self) -> None:
        assert 0 <= self.budget._claimed_bytes <= 50
        assert self.budget._claimed_bytes == self.claimed


TestMinioClaimMachine = MinioClaimMachine.TestCase


class AirflowPaginationMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []
        self.cap = 0

    @rule(index=st.integers(0, 120))
    def append_dag(self, index: int) -> None:
        name = f"dag_{index}"
        if name not in self.names:
            self.names.append(name)

    @rule(cap=st.integers(0, 130))
    def change_limit(self, cap: int) -> None:
        self.cap = cap

    @invariant()
    def collection_matches_the_current_independent_prefix_model(self) -> None:
        names = self.names

        class Client:
            def get(self, path: str) -> AirflowResponse:
                query = parse_qs(urlsplit(path).query)
                offset = int(query["offset"][0])
                limit = int(query["limit"][0])
                payload = {
                    "dags": [{"dag_id": name} for name in names[offset : offset + limit]],
                    "total_entries": len(names),
                }
                return AirflowResponse(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())

        result = _collection(Client(), "/api/v1/dags", "dags", self.cap, None)
        assert [item["dag_id"] for item in result.items] == names[: self.cap]


TestAirflowPaginationMachine = AirflowPaginationMachine.TestCase


class ClickHouseInventoryMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.entries: dict[tuple[str, str], int] = {}
        self.fallback = False

    @rule(database=st.integers(0, 4), table=st.integers(0, 8), rows=st.integers(0, 500))
    def upsert_table(self, database: int, table: int, rows: int) -> None:
        self.entries[(f"db{database}", f"table{table}")] = rows

    @rule()
    def switch_permissions(self) -> None:
        self.fallback = not self.fallback

    @invariant()
    def inventory_matches_catalog_or_read_only_fallback(self) -> None:
        entries = self.entries
        fallback = self.fallback

        def query(sql: str):
            if sql.startswith("SELECT database,name"):
                if fallback:
                    return None, "permission denied"
                return [
                    [database, table, "MergeTree", "", "", "", rows, rows]
                    for (database, table), rows in entries.items()
                ], None
            if sql.startswith(
                ("SELECT database,table,name", "SELECT database,table,column", "SELECT database,table,partition_id")
            ):
                return [], None
            if sql == "SHOW DATABASES":
                return [[name] for name in sorted({database for database, _table in entries})], None
            if sql.startswith("SHOW TABLES FROM "):
                quoted = sql.removeprefix("SHOW TABLES FROM ")
                database = next(name for name, _table in entries if quote_identifier(name) == quoted)
                return [[table] for source, table in entries if source == database], None
            if sql.startswith("DESCRIBE TABLE "):
                return [["payload", "String"]], None
            raise AssertionError(sql)

        tables, errors = collect_inventory(query)
        assert {(table.database, table.name) for table in tables} == set(entries)
        assert errors == (["system.tables: permission denied"] if fallback else [])
        if not fallback:
            assert {(table.database, table.name): table.total_rows for table in tables} == entries


TestClickHouseInventoryMachine = ClickHouseInventoryMachine.TestCase


class ProxmoxFindingMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.findings: list[dict[str, str]] = []
        self.seen: set[tuple[str, str, str, str]] = set()
        self.expected: set[tuple[str, str]] = set()

    @rule(node=st.integers(0, 5), token=st.integers(10000000, 99999999))
    def read_endpoint(self, node: int, token: int) -> None:
        endpoint = f"/nodes/pve{node}/config"
        secret = f"Secret{token}"
        proxmox_actions._scan_endpoint_payload(
            endpoint, json.dumps({"password": secret}).encode(), self.findings, self.seen
        )
        self.expected.add((endpoint, secret))

    @rule(node=st.integers(0, 5))
    def read_malformed_endpoint(self, node: int) -> None:
        proxmox_actions._scan_endpoint_payload(f"/nodes/pve{node}/config", b"{broken", self.findings, self.seen)

    @invariant()
    def credentials_match_unique_evidence_from_the_read_sequence(self) -> None:
        assert {(item["endpoint"], item["sample"]) for item in self.findings} == self.expected
        assert len(self.findings) == len(self.expected)


TestProxmoxFindingMachine = ProxmoxFindingMachine.TestCase


def test_elastic_budget_accepts_exact_document_and_byte_boundaries() -> None:
    budget = DiscoveryBudget(
        DiscoverOptions(max_documents=1, max_source_bytes=5, max_seconds=30),
        monotonic=lambda: 0.0,
    )
    assert budget.consume_document(5)
    assert budget.documents == 1 and budget.source_bytes == 5
    assert budget.consume_document(1) is False
    assert "max_documents" in budget.reasons
