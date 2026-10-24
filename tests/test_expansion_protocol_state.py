"""Generated wire-format and state transition checks against independent models."""

from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from redposture_core import servers, stage_spray
from redposture_core.exporters import discovery_logic as discovery
from redposture_core.targeting import chunked_hosts, parse_scan_target_specs, stream_scan_target_specs


def _mysql_response(user: bytes = b"qa", *, database: bytes | None = None, plugin: bytes | None = None) -> bytes:
    capabilities = 0x200 | 0x8000 | (0x8 if database is not None else 0) | (0x80000 if plugin is not None else 0)
    payload = capabilities.to_bytes(4, "little") + bytes(28) + user + b"\x00\x14" + bytes(range(1, 21))
    if database is not None:
        payload += database + b"\x00"
    if plugin is not None:
        payload += plugin + b"\x00"
    return payload


@pytest.mark.parametrize("database", [None, b"warehouse"])
def test_mysql_callback_requires_complete_auth_packet(database: bytes | None) -> None:
    payload = _mysql_response(database=database, plugin=b"mysql_native_password")
    result = servers.parse_mysql_handshake_response(payload)
    assert result is not None
    assert result["username"] == "qa"
    assert result["auth_response"] == bytes(range(1, 21)).hex()
    assert result["auth_plugin"] == "mysql_native_password"
    if database:
        assert result["database"] == "warehouse"
    for end in range(len(payload)):
        assert servers.parse_mysql_handshake_response(payload[:end]) is None, end


@pytest.mark.parametrize("user", [b"", b"x" * 256, b"\xff", b"qa\n", b"qa\t"])
def test_mysql_callback_rejects_nonidentities(user: bytes) -> None:
    assert servers.parse_mysql_handshake_response(_mysql_response(user)) is None


@pytest.mark.parametrize("plugin", [b"", b"caching_sha2_password", b"\xff", b"mysql_native_password\n"])
def test_mysql_callback_does_not_mislabel_other_auth_plugins(plugin: bytes) -> None:
    assert servers.parse_mysql_handshake_response(_mysql_response(plugin=plugin)) is None


@pytest.mark.parametrize("mask", [0x200, 0x8000])
def test_mysql_callback_requires_both_protocol41_and_secure_connection(mask: int) -> None:
    payload = bytearray(_mysql_response())
    payload[:4] = mask.to_bytes(4, "little")
    assert servers.parse_mysql_handshake_response(bytes(payload)) is None


@given(community=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-", min_size=1, max_size=96))
def test_snmp_callback_roundtrip_and_every_truncated_prefix(community: str) -> None:
    encoded = community.encode("ascii")
    body = b"\x02\x01\x01\x04" + bytes([len(encoded)]) + encoded + b"\xa0\x00"
    packet = b"\x30" + bytes([len(body)]) + body
    assert servers._snmp_community_from_packet(packet) == community
    for end in range(len(packet)):
        assert servers._snmp_community_from_packet(packet[:end]) is None
    assert servers._snmp_community_from_packet(packet + b"\x00") is None


@pytest.mark.parametrize(
    "packet",
    [
        b"\x30\x80" + b"x" * 12,
        b"\x30\x83\x00\x00\x08" + b"x" * 8,
        b"\x30\x08\x02\x01\x03\x04\x01x\xa0\x00",
        b"\x30\x08\x02\x01\x01\x04\x01\n\xa0\x00",
        b"\x30\x08\x02\x01\x01\x04\x01x\x90\x00",
    ],
)
def test_snmp_callback_rejects_nonmatching_ber_or_nonprintable_community(packet: bytes) -> None:
    assert servers._snmp_community_from_packet(packet) is None


@given(parts=st.lists(st.binary(min_size=0, max_size=32), min_size=1, max_size=5))
def test_resp_callback_roundtrips_binary_arguments_with_explicit_lengths(parts: list[bytes]) -> None:
    packet = f"*{len(parts)}\r\n".encode() + b"".join(f"${len(part)}\r\n".encode() + part + b"\r\n" for part in parts)
    assert servers.read_redis_cmd(io.BytesIO(packet)) == [part.decode("utf-8", "replace") for part in parts]
    for end in {len(packet) - 1, len(packet) - 2}:
        assert servers.read_redis_cmd(io.BytesIO(packet[:end])) == []


@given(
    addresses=st.lists(st.integers(1, 25), min_size=0, max_size=25),
    port=st.integers(1024, 65000),
    excluded=st.integers(1, 25),
)
def test_streaming_target_plan_matches_eager_identity_and_exclusions(
    addresses: list[int], port: int, excluded: int
) -> None:
    values = [f"127.0.0.{value}:{port}" for value in addresses]
    raw = ",".join(values)
    exclude = f"127.0.0.{excluded}"
    eager = parse_scan_target_specs(raw, exclude_targets=exclude)
    lazy = stream_scan_target_specs(raw, exclude_targets=exclude)
    actual = list(lazy.iter_specs())
    expected_hosts = list(dict.fromkeys(f"127.0.0.{value}" for value in addresses if value != excluded))
    assert [item.host for item in eager] == expected_hosts
    assert actual == eager
    assert lazy.count_for_ports((port,)) == len(eager)
    assert [item.host for item in lazy.iter_specs_for_port(port, (port,))] == expected_hosts


@given(items=st.lists(st.integers(), max_size=100), size=st.integers(1, 15))
def test_chunked_hosts_never_drops_tail_or_changes_order(items: list[int], size: int) -> None:
    chunks = list(chunked_hosts(iter(items), size))
    assert [item for chunk in chunks for item in chunk] == [str(item) for item in items]
    assert all(1 <= len(chunk) <= size for chunk in chunks)
    assert all(len(chunk) == size for chunk in chunks[:-1])


class _RateReservations(RuleBasedStateMachine):
    """Model origin/account reservations and irreversible cancellation independently."""

    def __init__(self) -> None:
        super().__init__()
        self.now = 100.0
        self.origins: dict[str, float] = {}
        self.accounts: dict[tuple[str, str], float] = {}
        self.stops: dict[str, str] = {}
        self.cancelled = False
        self.gate = stage_spray.RateGate(2, 5)

    @rule(seconds=st.integers(0, 10))
    def advance(self, seconds: int) -> None:
        self.now += seconds

    @rule(origin=st.sampled_from(["http://a:80", "http://b:80"]), account=st.sampled_from(["alice", "bob"]))
    def reserve(self, origin: str, account: str) -> None:
        with patch.object(stage_spray, "time", SimpleNamespace(monotonic=lambda: self.now)):
            actual = self.gate.reserve(origin, account)
        if self.cancelled:
            assert actual == (False, "interrupted")
        elif origin in self.stops:
            assert actual == (False, self.stops[origin])
        else:
            start = max(self.now, self.origins.get(origin, self.now), self.accounts.get((origin, account), self.now))
            assert actual == (True, start - self.now)
            self.origins[origin] = start + 0.5
            self.accounts[(origin, account)] = start + 5

    @rule(origin=st.sampled_from(["http://a:80", "http://b:80"]))
    def stop(self, origin: str) -> None:
        self.stops[origin] = "captcha"
        self.gate.stop(origin, "captcha")

    @rule()
    def cancel(self) -> None:
        self.cancelled = True
        self.gate.cancel()

    @invariant()
    def model_matches_reserved_deadlines(self) -> None:
        assert self.gate.next_origin == self.origins
        assert self.gate.next_account == self.accounts
        assert self.gate.stopped == self.stops


TestRateReservations = _RateReservations.TestCase


@pytest.mark.parametrize(
    ("candidates", "products", "fingerprint", "reason", "name"),
    [
        ([], {}, ("", ""), "no_markers", None),
        ([{"name": "a", "score": 25}], {}, ("", ""), "ambiguous_no_ranked_candidates", None),
        (
            [{"name": "a", "score": 25}],
            {"a": {"name": "a", "fingerprint_vars": "build"}},
            ("build", ""),
            "fingerprint_unique",
            "a",
        ),
        (
            [{"name": "a", "score": 25}, {"name": "b", "score": 25}],
            {"a": {"name": "a", "fingerprint_vars": "build"}, "b": {"name": "b", "fingerprint_vars": "build"}},
            ("build", ""),
            "ambiguous_fingerprint_tie",
            None,
        ),
    ],
)
def test_exporter_ambiguity_requires_distinguishing_evidence(
    candidates: list[dict], products: dict, fingerprint: tuple[str, str], reason: str, name: str | None
) -> None:
    result, _source, actual_reason = discovery.resolve_best_exporter_candidate(
        host="127.0.0.1",
        port=9100,
        candidates=candidates,
        exporters_by_name=products,
        timeout=1,
        retries=0,
        fetch_fingerprint_bodies_fn=lambda *_: fingerprint,
    )
    assert actual_reason == reason
    assert (result["name"] if result else None) == name


def test_exporter_single_weak_marker_without_fingerprint_remains_unconfirmed() -> None:
    candidate = discovery.score_metrics_candidate({"name": "a", "weak_markers": ["generic_count"]}, "generic_count 1")
    assert candidate is not None and candidate["strong_count"] == 0 and candidate["score"] == 25
    result, _source, _reason = discovery.resolve_best_exporter_candidate(
        host="127.0.0.1",
        port=9100,
        candidates=[candidate],
        exporters_by_name={"a": {"name": "a"}},
        timeout=1,
        retries=0,
        fetch_fingerprint_bodies_fn=lambda *_: ("", ""),
        weak_confidence_score=50,
    )
    assert result is None, "A single weak marker below confidence threshold needs fingerprint confirmation"


def test_exporter_fingerprint_ignores_http_error_bodies_and_handles_ipv6() -> None:
    requests: list[str] = []

    def get(url: str, *_: object, **__: object) -> dict:
        requests.append(url)
        return {"status": 403 if len(requests) == 1 else 200, "body": "marker"}

    assert discovery.fetch_fingerprint_bodies("::1", 9100, 1, 0, http_get_details_fn=get, max_bytes=128) == (
        "",
        "marker",
    )
    assert requests == ["http://[::1]:9100/debug/vars", "http://[::1]:9100/debug/pprof/cmdline?debug=1"]


def test_exporter_port_fallback_requires_one_distinct_product() -> None:
    assert discovery.resolve_prometheus_port_fallback([]) is None
    assert discovery.resolve_prometheus_port_fallback([{"name": "a"}, {"name": "b"}]) is None
    result = discovery.resolve_prometheus_port_fallback([{}, {"name": " a "}, {"name": "a"}])
    assert result is not None and result["name"] == "a" and result["marker_hit"] is None
