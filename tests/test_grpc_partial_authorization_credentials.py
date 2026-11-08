"""A requested RPC denial must not erase independently protected authentication."""

from __future__ import annotations

import pytest

from redposture_core.modules.grpc import actions


def result(status):
    return {"grpc_status": status, "call": {"is_grpc": status is not None}}


@pytest.mark.parametrize("required", ["reflection", "health"])
def test_other_protected_rpc_success_verifies_identity_but_not_requested_permission(monkeypatch, required):
    monkeypatch.setattr(actions, "_health_check_call", lambda *a, **k: result(0 if required == "reflection" else 7))
    monkeypatch.setattr(
        actions, "_reflection_capability_call", lambda *a, **k: result(7 if required == "reflection" else 0)
    )
    candidate = {"type": "basic", "username": "limited", "password": "limited", "source": "provided"}
    ok, matched, evidence = actions._try_credentials(
        "qa.invalid",
        1,
        timeout=1,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[candidate],
        required_capability=required,
    )
    assert ok is True and matched == candidate
    assert evidence["attempts"] == [{"candidate": candidate, "ok": True, "verdict": "valid"}]
    assert evidence[required + "_ok"] is False
    assert evidence[required + "_candidate"] is None


def test_keep_searching_for_requested_capability_after_partial_success(monkeypatch):
    seen = []
    first = {"type": "basic", "username": "limited", "password": "limited", "source": "provided"}
    second = {"type": "basic", "username": "full", "password": "full", "source": "provided"}
    monkeypatch.setattr(actions, "_health_check_call", lambda *a, **k: result(0))

    def reflection(*args, **kwargs):
        seen.append(kwargs["authorization"])
        return result(7 if len(seen) == 1 else 0)

    monkeypatch.setattr(actions, "_reflection_capability_call", reflection)
    ok, matched, evidence = actions._try_credentials(
        "qa.invalid",
        1,
        timeout=1,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[first, second],
        required_capability="reflection",
    )
    assert ok and matched == second and len(seen) == 2
    assert evidence["health_candidate"] == first and evidence["reflection_candidate"] == second
    assert [row["verdict"] for row in evidence["attempts"]] == ["valid", "valid"]


@pytest.mark.parametrize(
    "health_access,health_status,reflection_status",
    [("anonymous", 0, 7), ("auth_required", None, 7), ("auth_required", 7, 7)],
)
def test_public_or_unavailable_success_is_not_authentication(
    monkeypatch, health_access, health_status, reflection_status
):
    monkeypatch.setattr(actions, "_health_check_call", lambda *a, **k: result(health_status))
    monkeypatch.setattr(actions, "_reflection_capability_call", lambda *a, **k: result(reflection_status))
    candidate = {"type": "token", "token": "unverified", "source": "provided"}
    ok, matched, evidence = actions._try_credentials(
        "qa.invalid",
        1,
        timeout=1,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[candidate],
        required_capability="reflection",
        health_access=health_access,
    )
    assert not ok and matched is None and evidence["attempts"][0]["verdict"] == "unverified"


def test_full_sweep_preserves_partial_success_and_explicit_rejections(monkeypatch):
    candidate = {"type": "token", "token": "limited", "source": "defcreds"}
    bad = {"type": "token", "token": "bad", "source": "defcreds"}
    monkeypatch.setattr(
        actions, "_health_check_call", lambda *a, **k: result(0 if k["authorization"] == "Bearer limited" else 16)
    )
    monkeypatch.setattr(
        actions,
        "_reflection_capability_call",
        lambda *a, **k: result(7 if k["authorization"] == "Bearer limited" else 16),
    )
    ok, matched, evidence = actions._try_credentials(
        "qa.invalid",
        1,
        timeout=1,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[candidate, bad],
        required_capability="reflection",
        continue_after_success=True,
    )
    assert ok and matched == candidate
    assert [row["verdict"] for row in evidence["attempts"]] == ["valid", "rejected"]
