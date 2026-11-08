"""A batch must not hide missing results, failed gates or unsafe cleanup."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from scripts import compare_module_performance as batch
from scripts.performance_contracts import matching_case


def readonly_kafka_rows():
    samples = rows()
    for row in samples:
        row["result"].update(
            module="kafka",
            mode="actions",
            auth_surface="rest-proxy",
            auth_case="invalid",
            targets=40,
            credential_scenario_applicable=False,
            fixture_access_case=None,
            credential_verdict_model="not_applicable_readonly_api",
            credential_quality="NOT_APPLICABLE",
            credential_expectation_per_positive=None,
            credential_expected_sha256=None,
            credential_identity_digests={},
            credential_count_histogram={"0": 40},
            credential_observations=dict.fromkeys(
                [
                    "attempts_observed",
                    "accepted_claims",
                    "invalid",
                    "unverified",
                    "skipped",
                    "duplicate_attempts",
                    "malformed_attempts",
                ],
                0,
            ),
            read_wire_errors={},
            read_wire_summary={
                "recorded_calls": 120,
                "pending_calls": 0,
                "pending_targets": 0,
                "overflow": 0,
                "malformed": 0,
                "storage_errors": 0,
                "temporary_storage_removed": 1,
            },
            read_wire_evidence={"roots": 40, "sha256": "a" * 64},
        )
    return samples


def test_readonly_kafka_comparison_accepts_explicit_zero_credentials_with_complete_wire():
    assert batch.summarize_samples(readonly_kafka_rows(), 3)["gate"] == "PASS"


@pytest.mark.parametrize(
    "fault",
    [
        "form-auth",
        "native",
        "other-module",
        "credentials",
        "accepted",
        "boolean",
        "overflow",
        "pending",
        "disk",
        "cleanup",
        "missing-wire",
        "bad-hash",
        "missing-root",
    ],
)
def test_readonly_kafka_comparison_does_not_hide_unsupported_auth_or_incomplete_evidence(fault):
    samples = readonly_kafka_rows()
    for row in samples:
        sample = row["result"]
        if fault in {"form-auth", "native"}:
            sample["auth_surface"] = "kafbat-ui" if fault == "form-auth" else "default"
        elif fault == "other-module":
            sample["module"] = "grafana"
        elif fault == "credentials":
            sample["mode"] = "credentials"
        elif fault in {"accepted", "boolean"}:
            sample["credential_observations"]["accepted_claims"] = 1 if fault == "accepted" else False
        elif fault in {"overflow", "pending", "disk", "cleanup"}:
            key = {
                "overflow": "overflow",
                "pending": "pending_calls",
                "disk": "storage_errors",
                "cleanup": "temporary_storage_removed",
            }[fault]
            sample["read_wire_summary"][key] = 0 if fault == "cleanup" else 1
        elif fault == "missing-wire":
            sample["read_wire_evidence"] = None
        else:
            sample["read_wire_evidence"]["sha256" if fault == "bad-hash" else "roots"] = (
                "short" if fault == "bad-hash" else 39
            )
    assert batch.summarize_samples(samples, 3)["gate"] == "FAIL"


def rows():
    result = []
    for repeat, side in batch.sample_order(3):
        sample = dict.fromkeys(matching_case({}, {}))
        sample.update(
            wall_seconds=1 if side == "before" else 0.5,
            source_sha256=side,
            quality="PASS",
            cleanup="PASS",
            result_sha256="same exact set",
            missing=[],
            extra=[],
            duplicates=0,
            invalid_credentials_accepted=0,
            requests={"connections": 40},
            cpu_seconds=0.1,
        )
        result.append({"repeat": repeat, "side": side, "exit": 0, "result": sample})
    return result


def test_schedule_has_one_warmup_then_alternates_and_never_overlaps():
    assert batch.sample_order(3) == [
        (0, "before"),
        (0, "after"),
        (1, "after"),
        (1, "before"),
        (2, "before"),
        (2, "after"),
        (3, "after"),
        (3, "before"),
    ]


def test_native_peer_policy_cannot_silently_be_compared_to_a_thread_per_socket_server():
    before = dict.fromkeys(matching_case({}, {}))
    before.update(http_peer="native_threaded", mode="detect")
    after = {**before, "http_peer": "native_process"}
    assert matching_case(before, after) == ["http_peer"]


def test_ram_and_disk_wire_observers_cannot_form_one_timing_pair():
    before = dict.fromkeys(matching_case({}, {}))
    before.update(read_wire_storage_policy="bounded_memory")
    after = {**before, "read_wire_storage_policy": "sqlite_pending_disk256MiB_cache512KiB_perroot8MiB"}
    assert matching_case(before, after) == ["read_wire_storage_policy"]


def test_kafka_ui_surface_is_forwarded_to_the_actual_profiler(tmp_path, monkeypatch):
    source = tmp_path / "source" / "redposture_core"
    source.mkdir(parents=True)
    (source / "module_registry.py").write_text("# provenance fixture\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "--before",
            str(source.parent),
            "--after",
            str(source.parent),
            "--output",
            str(tmp_path / "out"),
            "--modules",
            "kafka",
            "--mode",
            "credentials",
            "--auth-case",
            "valid",
            "--auth-surface",
            "kafbat-ui",
            "--container-image",
            "unused",
        ],
    )
    calls = []

    def run(command, destination):
        calls.append(command)
        return {"exit": 1, "result": None, "unsafe_to_continue": True}

    monkeypatch.setattr(batch, "run_sample", run)
    assert batch.main() == 1 and len(calls) == 1
    assert calls[0][calls[0].index("--auth-surface") + 1] == "kafbat-ui"


def test_native_peer_policy_is_forwarded_into_the_sample_command(tmp_path, monkeypatch):
    source = tmp_path / "source" / "redposture_core"
    source.mkdir(parents=True)
    (source / "module_registry.py").write_text("# provenance fixture\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "--before",
            str(source.parent),
            "--after",
            str(source.parent),
            "--output",
            str(tmp_path / "out"),
            "--modules",
            "mongodb",
            "--native-peer",
            "process",
            "--container-image",
            "unused",
        ],
    )
    calls = []

    def run(command, destination):
        calls.append(command)
        return {"exit": 1, "result": None, "unsafe_to_continue": True}

    monkeypatch.setattr(batch, "run_sample", run)
    assert batch.main() == 1 and len(calls) == 1
    assert calls[0][calls[0].index("--native-peer") + 1] == "process"


def test_public_action_comparison_forwards_identical_controls_to_each_sample(tmp_path, monkeypatch):
    source = tmp_path / "source" / "redposture_core"
    source.mkdir(parents=True)
    (source / "module_registry.py").write_text("# provenance fixture\n")
    out = tmp_path / "comparison"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "--before",
            str(source.parent),
            "--after",
            str(source.parent),
            "--output",
            str(out),
            "--modules",
            "gitlab",
            "--container-image",
            "unused",
            "--mode",
            "actions",
            "--auth-case",
            "limited",
            "--http-peer",
            "process",
            "--target-style",
            "http",
            "--format",
            "json",
            "--save",
            "--debug",
            "--auto-concurrency",
            "--action=--project",
            "--action=platform/reporting",
        ],
    )
    calls = []

    def run(command, destination):
        calls.append(command)
        return {"exit": 1, "result": None, "unsafe_to_continue": True}

    monkeypatch.setattr(batch, "run_sample", run)
    assert batch.main() == 1
    assert len(calls) == 1
    command = calls[0]
    for flag, value in (
        ("--mode", "actions"),
        ("--auth-case", "limited"),
        ("--http-peer", "process"),
        ("--format", "json"),
        ("--target-style", "http"),
    ):
        assert command[command.index(flag) + 1] == value
    assert all(
        flag in command
        for flag in ("--save", "--debug", "--auto-concurrency", "--action=--project", "--action=platform/reporting")
    )


@pytest.mark.parametrize("count", [0, 1, 2, 21])
def test_underpowered_or_unbounded_repeat_plan_is_rejected(count):
    with pytest.raises(ValueError):
        batch.sample_order(count)


def test_valid_repeats_exclude_warmups_and_record_independent_quality():
    samples = rows()
    samples[0]["result"]["wall_seconds"] = 1000
    summary = batch.summarize_samples(samples, 3)
    assert summary["gate"] == "PASS" and summary["same_results"]
    assert summary["before_median_seconds"] == 1
    assert summary["medians"]["cpu_seconds"] == {"before": 0.1, "after": 0.1}
    assert summary["medians"]["first_finding_seconds"] == {"before": None, "after": None}


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "no-result",
        "exit",
        "changed-source",
        "changed-environment",
        "different-results",
        "missing-warmup",
        "failed-warmup",
    ],
)
def test_failed_or_incomparable_samples_cannot_become_green(fault):
    samples = rows()
    if fault == "missing":
        samples.pop()
    elif fault == "no-result":
        samples[-1]["result"] = None
    elif fault == "exit":
        samples[-1]["exit"] = 1
    elif fault == "changed-source":
        samples[-1]["result"]["source_sha256"] = "another source"
    elif fault == "changed-environment":
        samples[-1]["result"]["environment_sha256"] = "other drivers"
    elif fault == "different-results":
        samples[-1]["result"]["result_sha256"] = "missing target"
    elif fault == "missing-warmup":
        samples.pop(0)
    else:
        samples[1]["result"]["quality"] = "FAIL"
    assert batch.summarize_samples(samples, 3)["gate"] == "FAIL"


def test_a_real_baseline_defect_remains_visible_when_candidate_is_fixed():
    samples = rows()
    for row in samples:
        if row["side"] == "before":
            row["exit"] = 1
            row["result"].update(quality="FAIL", cleanup="FAIL")
    summary = batch.summarize_samples(samples, 3)
    assert summary["gate"] == "PASS"
    assert summary["quality"] == {"before": "FAIL", "after": "PASS"}


def test_non_applicability_requires_both_sources_and_successful_processes():
    samples = rows()
    for row in samples:
        row["result"].update(quality="NOT_APPLICABLE", reason="no defcreds flag")
    assert batch.summarize_samples(samples, 3)["gate"] == "NOT_APPLICABLE"
    samples[-1]["exit"] = 1
    assert batch.summarize_samples(samples, 3)["gate"] == "FAIL"


def test_outer_timeout_is_not_a_pass_or_permission_to_start_another_container(tmp_path, monkeypatch):
    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired(["profile"], 720)

    monkeypatch.setattr(batch.subprocess, "run", run)
    sample = batch.run_sample(["profile"], tmp_path / "case.json")
    assert sample["exit"] == 124 and sample["result"] is None
    assert sample["unsafe_to_continue"]
    assert (tmp_path / "case.log").exists()


def test_pending_cleanup_stops_matrix_and_keeps_unrun_groups_visible(tmp_path, monkeypatch):
    source = tmp_path / "source/redposture_core"
    source.mkdir(parents=True)
    (source / "module_registry.py").write_text("# source snapshot")
    out = tmp_path / "results"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "--before",
            str(source.parent),
            "--after",
            str(source.parent),
            "--output",
            str(out),
            "--modules",
            "grafana",
            "jenkins",
            "--container-image",
            "unused-local-image",
        ],
    )
    calls = []

    def run(*args):
        calls.append(args)
        return {"exit": 1, "result": None, "unsafe_to_continue": True}

    monkeypatch.setattr(batch, "run_sample", run)
    assert batch.main() == 1
    report = json.loads((out / "results.json").read_text())
    assert len(calls) == 1
    assert report["status"] == "STOPPED_CLEANUP"
    assert [row["status"] for row in report["groups"]] == ["FAIL", "PENDING"]
