from __future__ import annotations

from redposture_core.discovery_frontier import DiscoveryFrontier


def test_frontier_keeps_fifo_order_and_deduplicates_on_disk() -> None:
    with DiscoveryFrontier() as frontier:
        for index in range(10_000):
            assert frontier.enqueue(f"entry-{index}")
        assert not frontier.enqueue("entry-42")
        assert frontier.pop() == "entry-0"
        assert not frontier.enqueue("entry-0")
        assert frontier.claim("leaf-1")
        assert not frontier.claim("leaf-1")
        assert frontier.pop() == "entry-1"
        for index in range(2, 10_000):
            assert frontier.pop() == f"entry-{index}"
        assert frontier.pop() is None


def test_frontier_removes_temporary_database_on_exit() -> None:
    with DiscoveryFrontier() as frontier:
        location = frontier.location
        assert frontier.enqueue("secret/path")
        assert location.exists()
    assert not location.exists()


def test_frontier_membership_does_not_claim_or_enqueue_missing_values() -> None:
    with DiscoveryFrontier() as frontier:
        assert not frontier.contains("missing")
        assert frontier.claim("missing")
        assert frontier.contains("missing")
        assert frontier.pop() is None
