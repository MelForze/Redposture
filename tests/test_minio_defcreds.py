from __future__ import annotations

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio import actions
from redposture_core.modules.minio.stage import build_minio_plan


def test_real_default_includes_minioadmin_and_is_separated_from_heuristics():
    assert ("minioadmin", "minioadmin") in actions._MINIO_REAL_DEFAULT_CREDENTIALS
    assert ("minioadmin", "minioadmin") not in actions._MINIO_HEURISTIC_DEFAULT_CREDENTIALS
    # каталог = реальные + эвристика, без дублей
    combined = actions._MINIO_DEFAULT_CREDENTIALS
    assert combined[: len(actions._MINIO_REAL_DEFAULT_CREDENTIALS)] == actions._MINIO_REAL_DEFAULT_CREDENTIALS
    assert len(set(combined)) == len(combined)


def test_candidate_builder_prioritises_provided_and_dedups():
    cands = actions._build_credential_candidates("AK", "SK", True)
    assert cands[0] == ("AK", "SK", "provided")
    assert ("minioadmin", "minioadmin", "default") in cands
    keys = [(u, p) for u, p, _ in cands]
    assert len(keys) == len(set(keys))  # dedup


def test_candidate_builder_no_defcreds_returns_only_provided():
    assert actions._build_credential_candidates("AK", "SK", False) == [("AK", "SK", "provided")]
    assert actions._build_credential_candidates(None, None, False) == []


def test_plan_includes_defcreds_runs_when_flag_set():
    plan = build_minio_plan(parse_args(["minio", "-t", "127.0.0.1", "--defcreds"]))
    labels = {(r.username, r.password, r.source) for r in plan.credential_runs}
    assert ("minioadmin", "minioadmin", "default") in labels
