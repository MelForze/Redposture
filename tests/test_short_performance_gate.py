"""Short gate keeps exact quality, resource regressions and scope visible."""

from argparse import Namespace
from pathlib import Path

import pytest

from scripts.check_performance_regressions import command, recipes, resource_gate, summarize_native
from scripts.compare_module_performance import sample_order
from scripts.performance_selection import selection
from tests.test_performance_selection import inventory


def resource_rows():
    return [
        {
            "side": side,
            "repeat": n,
            "result": {"first_finding_seconds": 0.1, "peak_rss_bytes": 40_000_000, "fd_peak": 20},
        }
        for n in (1, 2, 3)
        for side in ("before", "after")
    ]


@pytest.mark.parametrize("metric", ["first_finding_seconds", "peak_rss_bytes", "fd_peak"])
def test_resource_gate_rejects_repeated_regressions_and_missing_evidence(metric):
    rows = resource_rows()
    assert resource_gate(rows)["gate"] == "PASS"
    rows[-1]["result"].pop(metric)
    assert resource_gate(rows)["gate"] == "FAIL"
    rows = resource_rows()
    for row in rows:
        if row["side"] == "after":
            row["result"][metric] *= 100
    assert resource_gate(rows)["gate"] == "FAIL"


def test_direct_module_has_detect_auth_data_and_full_discover_quality_selection():
    plan = selection(inventory(), ["redposture_core/modules/grafana/actions.py"])
    cases, boundaries = recipes(plan)
    assert {c["mode"] for c in cases} == {"detect", "credentials", "actions"}
    assert not boundaries and plan["discover_routes"] == ["grafana"]


def test_native_transport_boundary_is_visible_not_relabelled_product_na():
    cases, boundaries = recipes(selection(inventory(), ["redposture_core/modules/postgres/actions.py"]))
    assert {c["mode"] for c in cases if "mode" in c} == {"detect", "credentials"}
    assert [c["id"] for c in cases if c.get("native_data")] == ["postgres-data-adapter"]
    assert boundaries[0]["status"] == "NOT_PROFILED"


def native_rows():
    return [
        {
            "repeat": repeat,
            "side": side,
            "exit": 0,
            "result": {
                "module": "postgres",
                "mode": "data-adapter",
                "rows": 128,
                "scope": "excludes network",
                "profile_sha256": "instrument",
                "environment": {"python": "3.12"},
                "container_image_id": "image",
                "container_limits": {"cpus": 2},
                "result_sha256": "known",
                "expected_sha256": "known",
                "input_sha256": "known",
                "source_sha256": side,
                "quality": "PASS",
                "cleanup": "PASS",
                "wall_seconds": 0.1,
            },
        }
        for repeat, side in sample_order(3)
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("cleanup", "FAIL"),
        ("quality", "FAIL"),
        ("result_sha256", "wrong"),
        ("profile_sha256", "changed"),
        ("source_sha256", "changed"),
        ("wall_seconds", float("nan")),
        ("wall_seconds", -1),
    ],
)
def test_native_comparison_rejects_bad_evidence(field, value):
    rows = native_rows()
    assert summarize_native(rows, 3)["gate"] == "PASS"
    rows[-1]["result"][field] = value
    assert summarize_native(rows, 3)["gate"] == "FAIL"


def test_native_comparison_requires_all_samples_and_rejects_wall_regression():
    rows = native_rows()
    assert summarize_native(rows[:-1], 3)["gate"] == "FAIL"
    for row in rows:
        if row["side"] == "after":
            row["result"]["wall_seconds"] = 5
    assert summarize_native(rows, 3)["gate"] == "FAIL"


def test_native_command_and_redis_steady_workload():
    args = Namespace(container_image="fixture:local", targets=64)
    cases, _ = recipes(selection(inventory(), ["redposture_core/modules/redis/actions.py"]))
    case = next(c for c in cases if c["id"] == "redis-auth")
    argv = command(case, Path("/tmp/before"), Path("/tmp/result"), args)
    assert argv[argv.index("--targets") + 1] == "512"
    argv = command(next(c for c in cases if c.get("native_data")), Path("/tmp/before"), Path("/tmp/result"), args)
    assert argv[1].endswith("profile_native_data_performance.py")
    assert argv[argv.index("--rows") + 1] == "128"


def test_workflow_selection_and_arguments_are_literal():
    cases, _ = recipes(selection(inventory(), ["redposture_core/async_detection.py"]))
    assert {c["workflow"] for c in cases if "workflow" in c} == {"collect", "trigger", "spray"}
    argv = command(
        {"module": "grafana", "mode": "actions", "actions": ["--show-datasources"]},
        Path("/tmp/source with spaces"),
        Path("/tmp/output.json"),
        Namespace(container_image="fixture:local", targets=64),
    )
    assert argv[argv.index("--source") + 1] == "/tmp/source with spaces"
    assert "--action=--show-datasources" in argv
    assert argv[argv.index("--native-peer") + 1] == "process"


def test_missing_or_failed_quality_artifact_never_becomes_pass(tmp_path):
    import json

    from scripts.check_performance_regressions import check_artifact

    assert not check_artifact("discover-quality", tmp_path, ["redis"])
    path = tmp_path / "discover-quality.json"
    for record in (
        {"status": "PASS"},
        {"status": "PASS", "routes": ["other"], "failures": 0, "results": [{}]},
        {"status": "FAIL", "routes": ["redis"], "failures": 0, "results": [{}]},
    ):
        path.write_text(json.dumps(record))
        assert not check_artifact("discover-quality", tmp_path, ["redis"])
    record = {
        "status": "PASS",
        "routes": ["redis"],
        "failures": 0,
        "cases": 1,
        "corpus_sha256": "labels",
        "results": [
            {
                "route": "redis",
                "case": "positive",
                "status": "complete",
                "expected_status": "complete",
                "metrics": dict.fromkeys(
                    ("fn", "fp", "duplicates", "value_missing", "value_extra", "confidence_mismatch"), 0
                ),
            }
        ],
    }
    path.write_text(json.dumps(record))
    assert check_artifact("discover-quality", tmp_path, ["redis"])
    record["results"][0]["metrics"]["value_missing"] = 1
    path.write_text(json.dumps(record))
    assert not check_artifact("discover-quality", tmp_path, ["redis"])


def test_retained_controls_are_exact_and_tampering_is_rejected(tmp_path):
    from scripts.check_performance_regressions import ROOT, retain_controls

    files = retain_controls(ROOT, tmp_path)
    assert "scripts/profile_native_data_performance.py" in files
    assert retain_controls(ROOT, tmp_path) == files
    (tmp_path / "controls/scripts/profile_native_data_performance.py").write_text("tampered")
    with pytest.raises(ValueError, match="retained control changed"):
        retain_controls(ROOT, tmp_path)
