"""The Docker-owned default bridge may be recreated across Engine restarts."""

from scripts.qa_owned_lab import compare_network_snapshots


def network(name: str, network_id: str, driver: str = "bridge") -> dict[str, str]:
    return {"Name": name, "ID": network_id, "Driver": driver, "Labels": ""}


def test_recreated_builtin_bridge_does_not_fail_resource_preservation() -> None:
    before = [network("bridge", "old"), network("lab", "lab-id")]
    after = [network("bridge", "new"), network("lab", "lab-id")]
    result = compare_network_snapshots(before, after)
    assert result["preserved"] is True
    assert result["missing"] == {}
    assert result["recreated_builtin"] == {"bridge": {"before": "old", "after": "new"}}


def test_recreated_user_network_still_fails_resource_preservation() -> None:
    before = [network("bridge", "same"), network("lab", "old")]
    after = [network("bridge", "same"), network("lab", "new")]
    result = compare_network_snapshots(before, after)
    assert result["preserved"] is False
    assert result["missing"] == {"old": "lab"}


def test_missing_builtin_bridge_still_fails_resource_preservation() -> None:
    result = compare_network_snapshots([network("bridge", "old")], [])
    assert result["preserved"] is False
    assert result["missing"] == {"old": "bridge"}
