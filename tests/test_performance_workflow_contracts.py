"""Workflow profiles compare exact outputs, never counts alone."""

from __future__ import annotations

import pytest

from scripts.profile_workflow_performance import BAD_PAIR, ENDPOINTS, GRAFANA_HEALTH, PAIR, fixture_body, verify_records


def sample(workflow):
    if workflow == "spray":
        return [
            {"host": "qa", "module": "grafana", "status": "confirmed"},
            *[
                {
                    "host": "qa",
                    "module": "grafana",
                    "credential_type": "pair",
                    "username": u,
                    "password": p,
                    "status": "valid" if (u, p) == PAIR else "invalid",
                }
                for u, p in (BAD_PAIR, PAIR)
            ],
        ]
    if workflow == "collect":
        return [{"host": "qa", "endpoint": path, "ok": True, "body": fixture_body(path)} for path in ENDPOINTS]
    return [{"source_type": "trigger", "host": "qa", "success": True, "confirmed": True, "probe_success": True}]


def test_public_grafana_health_fixture_meets_the_real_detector_schema():
    import json

    from redposture_core.modules.grafana import actions

    assert actions._is_grafana_health_api_response(200, json.dumps(GRAFANA_HEALTH))
    assert not actions._is_grafana_health_api_response(
        200, json.dumps({k: v for k, v in GRAFANA_HEALTH.items() if k != "commit"})
    )


def test_actual_trigger_serializer_is_recognized_without_fabricating_a_type_field():
    from redposture_core.stage_trigger import _json_record_from_trigger_event

    row = _json_record_from_trigger_event(
        {"phase": "callback_result", "host": "qa", "confirmed": True, "probe_success": True, "status": 200}
    )
    assert row is not None and row["source_type"] == "trigger" and "type" not in row
    assert verify_records([row], "trigger", "grafana", {"qa"})["quality"] == "PASS"


@pytest.mark.parametrize("workflow", ["spray", "collect", "trigger"])
def test_complete_seeded_workflow_is_verified(workflow):
    result = verify_records(sample(workflow), workflow, "grafana", {"qa"})
    assert result["quality"] == "PASS" and result["duplicates"] == 0


@pytest.mark.parametrize("workflow", ["spray", "collect", "trigger"])
@pytest.mark.parametrize("fault", ["missing", "duplicate", "extra", "malformed"])
def test_same_count_or_bad_identity_cannot_hide_a_regression(workflow, fault):
    rows = sample(workflow)
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows.append(dict(rows[-1]))
    elif fault == "extra":
        rows[-1] = dict(rows[-1], host="foreign")
    else:
        rows[-1] = dict(rows[-1], host={"malformed": "identity"})
    assert verify_records(rows, workflow, "grafana", {"qa"})["quality"] == "FAIL"


def test_unverified_pair_is_not_invalid_and_a_wrong_pair_is_never_accepted():
    for verdict in ("inconclusive", "valid", "unsupported", "rate_limited"):
        rows = sample("spray")
        rows[1]["status"] = verdict
        assert verify_records(rows, "spray", "grafana", {"qa"})["quality"] == "FAIL"


def test_changed_password_or_hidden_extra_token_is_not_full_spray_parity():
    rows = sample("spray")
    rows[-1]["password"] = "different"
    assert verify_records(rows, "spray", "grafana", {"qa"})["quality"] == "FAIL"
    rows = sample("spray")
    rows.append({"host": "qa", "module": "grafana", "credential_type": "token", "token": "extra", "status": "valid"})
    assert verify_records(rows, "spray", "grafana", {"qa"})["quality"] == "FAIL"


def test_count_correct_but_truncated_body_fails():
    rows = sample("collect")
    rows[-1]["body"] = rows[-1]["body"][:-1]
    assert verify_records(rows, "collect", "grafana", {"qa"})["quality"] == "FAIL"


def test_http_success_without_confirmed_probe_is_not_a_trigger_success():
    rows = sample("trigger")
    rows[-1]["probe_success"] = None
    assert verify_records(rows, "trigger", "grafana", {"qa"})["quality"] == "FAIL"


def test_workflow_snapshot_retains_and_hashes_fixture_data(tmp_path, monkeypatch):
    from scripts import profile_workflow_performance as profile

    root = tmp_path / "source"
    for name in profile.WORKFLOW_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    monkeypatch.setattr(profile, "ROOT", root)
    output = tmp_path / "output"
    before = profile.workflow_hash(output)
    catalog = "tests/fixtures/detection_pages/application-markup.json"
    assert (output / ("instrument-" + before) / catalog).read_bytes() == (root / catalog).read_bytes()
    (root / catalog).write_text("changed payload")
    assert profile.workflow_hash(output) != before


def test_workflow_snapshot_does_not_silently_rewrite_a_corrupted_manifest(tmp_path):
    from scripts import profile_workflow_performance as profile

    fingerprint = profile.workflow_hash(tmp_path)
    manifest = tmp_path / ("instrument-" + fingerprint) / "MANIFEST.json"
    manifest.write_text('{"files":{},"profile_sha256":"corrupted"}')
    with pytest.raises(ValueError, match="manifest changed"):
        profile.workflow_hash(tmp_path)


@pytest.mark.parametrize("workflow", ["collect", "trigger", "spray"])
def test_first_finding_ignores_negative_partial_and_wrong_value(tmp_path, workflow):
    import json
    import time

    from scripts.profile_workflow_performance import FirstFinding

    observer = FirstFinding(workflow, "grafana", {"qa"})
    path = tmp_path / "records.jsonl"
    path.write_text(json.dumps({"host": "foreign", "status": "valid"}) + "\n")
    observer.observe(path, 0.1)
    assert observer.seconds is None
    positive = sample(workflow)[-1]
    raw = json.dumps(positive).encode() + b"\n"
    with path.open("ab") as stream:
        stream.write(raw[: len(raw) // 2])
    observer.observe(path, 0.2)
    assert observer.seconds is None
    with path.open("ab") as stream:
        stream.write(raw[len(raw) // 2 :])
    observer.observe(path, time.monotonic() - 0.3)
    assert observer.seconds == pytest.approx(0.3, abs=0.01) and observer.error is None
    recorded = observer.seconds
    observer.observe(path, 0.9)
    assert observer.seconds == recorded


def test_first_finding_never_accepts_a_truncated_collect_body(tmp_path):
    import json

    from scripts.profile_workflow_performance import FirstFinding

    row = sample("collect")[0]
    row["body"] = row["body"][:-1]
    path = tmp_path / "records.jsonl"
    path.write_text(json.dumps(row) + "\n")
    observer = FirstFinding("collect", "grafana", {"qa"})
    observer.observe(path, 0.1)
    assert observer.seconds is None


def test_first_finding_reports_corrupt_or_unbounded_fixture_records(tmp_path):
    from scripts.profile_workflow_performance import FirstFinding

    for raw in (b"not json\n", b"x" * 65537):
        path = tmp_path / "records.jsonl"
        path.write_bytes(raw)
        observer = FirstFinding("collect", "grafana", {"qa"})
        observer.observe(path, 0.1)
        assert observer.error and observer.seconds is None
