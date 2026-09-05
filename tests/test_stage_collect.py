from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from redposture_core import stage_collect as collect
from redposture_core.exporters.output import format_collect_record
from redposture_core.logger import AttemptLogger
from redposture_core.stage_collect import run_collect_stage


def _base_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "workers": 4,
        "retries": 1,
        "targets": "10.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "profiles_file": None,
        "output": None,
        "output_format": "txt",
        "save_responses_dir": None,
        "deep": False,
        "pprof_seconds": 5,
        "trace_seconds": 2,
        "resume": False,
        "checkpoint_file": None,
        "max_inflight": None,
        "adaptive_collect": True,
        "collect_exporters_filter": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_collect_helper_functions_cover_checkpoint_and_filters(tmp_path: Path) -> None:
    args = _base_args(
        output=str(tmp_path / "collect.txt"),
        save_responses_dir=str(tmp_path / "raw"),
        checkpoint_file=str(tmp_path / "explicit.ckpt"),
    )
    assert collect._resolve_collect_checkpoint_path(args) == str(tmp_path / "explicit.ckpt")

    args_no_explicit = _base_args(output=str(tmp_path / "collect.txt"), save_responses_dir=str(tmp_path / "raw"))
    assert collect._resolve_collect_checkpoint_path(args_no_explicit).endswith("collect.txt.checkpoint.jsonl")

    args_only_save = _base_args(output=None, save_responses_dir=str(tmp_path / "raw"))
    assert collect._resolve_collect_checkpoint_path(args_only_save).endswith("collect.checkpoint.jsonl")

    assert collect._materialize_collect_endpoint("/x/{pprof_seconds}/{trace_seconds}", 11, 4) == "/x/11/4"

    endpoints = collect._build_collect_endpoints(
        ["/debug/vars", "/debug/vars", "/debug/pprof/profile?seconds={pprof_seconds}"],
        deep=True,
        pprof_seconds=9,
        trace_seconds=3,
    )
    assert "/debug/vars" in endpoints
    assert "/debug/pprof/profile?seconds=9" in endpoints
    assert len(endpoints) == len(set(endpoints))

    aliases = collect._collect_exporter_alias_map(
        [{"name": "redis_exporter"}, {"name": "pgbackrest_exporter"}, {"name": "custom"}]
    )
    assert aliases["redis"] == "redis_exporter"
    assert aliases["pgbackrest"] == "pgbackrest_exporter"
    assert aliases["custom"] == "custom"

    selected = collect._parse_collect_exporter_filter(
        "redis,pgbackrest_exporter",
        [{"name": "redis_exporter"}, {"name": "pgbackrest_exporter"}],
    )
    assert selected == {"redis_exporter", "pgbackrest_exporter"}

    with pytest.raises(ValueError):
        collect._parse_collect_exporter_filter("unknown", [{"name": "redis_exporter"}])

    filtered_discovery, filtered_collect = collect._filter_collect_exporter_profiles(
        discovery_exporters=[{"name": "redis_exporter"}, {"name": "postgres_exporter"}],
        collect_exporters=[{"name": "redis_exporter"}, {"name": "postgres_exporter"}],
        selected_exporter_names={"redis_exporter"},
    )
    assert filtered_discovery == [{"name": "redis_exporter"}]
    assert filtered_collect == [{"name": "redis_exporter"}]


def test_collect_stage_excludes_out_targets_before_scanning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        collect,
        "scan_exporter_presence",
        lambda *_a, **_k: pytest.fail("excluded target reached scanner"),
    )

    rc = run_collect_stage(
        _base_args(targets="10.0.0.1", out_targets=["10.0.0.0/24"]),
        AttemptLogger(),
    )

    assert rc == 2
    assert "all targets were excluded by --out-target" in capsys.readouterr().err


def test_run_collect_stage_large_cidr_chunks_output_and_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output_path = tmp_path / "collect.txt"
    scan_calls: list[list[str]] = []
    collect_calls: list[tuple[list[str], str]] = []

    monkeypatch.setattr(collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(
        collect,
        "load_profiles",
        lambda _path: {
            "discovery_exporters": [{"name": "node_exporter", "port": 9100, "markers": ()}],
            "collect_exporters": [{"name": "node_exporter", "port": 9100}],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )

    def fake_scan_exporter_presence(
        hosts,
        timeout,
        output_path,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=10,
        retries=3,
        discovery_exporters=None,
        custom_ports=None,
        emit_summary=True,
        show_progress=False,
        progress_leave=True,
        progress_owner=None,
        stats_sink=None,
    ):
        _ = (
            timeout,
            output_path,
            output_format,
            logger,
            emit_line,
            workers,
            retries,
            discovery_exporters,
            custom_ports,
            emit_summary,
            show_progress,
            progress_leave,
            progress_owner,
            stats_sink,
        )
        host_list = list(hosts)
        scan_calls.append(host_list)
        found_by_host = {
            host: [{"exporter": "node_exporter", "port": 9100, "url": f"http://{host}:9100/metrics"}]
            for host in host_list
        }
        return len(host_list), len(host_list), found_by_host

    def fake_collect_exporter_debug_data(
        logger,
        hosts,
        timeout,
        output_path,
        output_format="json",
        emit_line=None,
        workers=10,
        retries=3,
        collect_exporters=None,
        collect_debug_endpoints=None,
        found_by_host=None,
        save_responses_dir=None,
        record_callback=None,
        output_mode="w",
        index_mode="w",
        emit_summary=True,
        adaptive_collect=True,
        max_inflight_requests=None,
        resume_completed_jobs=None,
        checkpoint_path=None,
        checkpoint_mode="a",
        stats_sink=None,
        progress_owner=None,
    ):
        _ = (
            logger,
            timeout,
            workers,
            retries,
            collect_exporters,
            collect_debug_endpoints,
            found_by_host,
            save_responses_dir,
            index_mode,
            emit_summary,
            adaptive_collect,
            max_inflight_requests,
            resume_completed_jobs,
            checkpoint_path,
            checkpoint_mode,
            stats_sink,
            progress_owner,
        )
        host_list = list(hosts)
        collect_calls.append((host_list, output_mode))
        lines = []
        for host in host_list:
            record = {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": host,
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/debug/vars",
                "url": f"http://{host}:9100/debug/vars",
                "ok": True,
                "status": 200,
                "elapsed_ms": 1,
                "content_type": "text/plain",
                "error": None,
                "truncated": False,
                "body": "ok",
            }
            if record_callback is not None:
                record_callback(record)
            lines.append(format_collect_record(record, output_format))
        if output_path:
            with open(output_path, output_mode, encoding="utf-8") as fh:
                for line in lines:
                    fh.write(line + "\n")
        if emit_line is not None:
            for line in lines:
                emit_line(line)
        return len(host_list), len(host_list)

    monkeypatch.setattr(collect, "scan_exporter_presence", fake_scan_exporter_presence)
    monkeypatch.setattr(collect, "collect_exporter_debug_data", fake_collect_exporter_debug_data)

    rc = run_collect_stage(
        _base_args(targets="10.0.0.0/30", output=str(output_path), workers=1),
        logger=AttemptLogger(),
    )

    assert rc == 0
    assert scan_calls == [["10.0.0.1", "10.0.0.2"]]
    assert collect_calls == [(["10.0.0.1", "10.0.0.2"], "w")]
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert "Node Exporter" in lines[0]
    assert "Node Exporter" in lines[1]
    assert lines[2].startswith("VALIDATE")
    assert lines[-1].startswith("COLLECT")
    assert "requests=2" in lines[-1]
    assert "success=2" in lines[-1]


def test_run_collect_stage_large_cidr_resume_keeps_checkpoint_jobs_lazy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checkpoint_path = tmp_path / "large.ckpt.jsonl"
    checkpoint_path.write_text(
        json.dumps(
            {
                "host": "10.0.0.1",
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/debug/vars",
                "ok": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    captured_completed: list[set[tuple[str, str, int, str]]] = []
    monkeypatch.setattr(collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(
        collect,
        "load_profiles",
        lambda _path: {
            "discovery_exporters": [{"name": "node_exporter", "port": 9100, "markers": ()}],
            "collect_exporters": [{"name": "node_exporter", "port": 9100}],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        hosts = list(kwargs["hosts"])
        return len(hosts), len(hosts), {host: [{"exporter": "node_exporter", "port": 9100}] for host in hosts}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        completed = set(kwargs.get("resume_completed_jobs") or set())
        captured_completed.append(completed)
        stats = kwargs.get("stats_sink")
        assert isinstance(stats, dict)
        stats.update({"errors": 0, "skipped_jobs": 1})
        return 1, 1

    monkeypatch.setattr(collect, "scan_exporter_presence", fake_scan)
    monkeypatch.setattr(collect, "collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(
        _base_args(
            targets="10.0.0.0/30",
            output=str(tmp_path / "collect.txt"),
            resume=True,
            checkpoint_file=str(checkpoint_path),
        ),
        AttemptLogger(),
    )

    assert rc == 0
    assert captured_completed == [{("10.0.0.1", "node_exporter", 9100, "/debug/vars")}]
    assert "resumed=1" in capsys.readouterr().out


def test_collect_load_completed_jobs_parses_valid_rows_and_warns_on_open_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ckpt = tmp_path / "collect.ckpt.jsonl"
    ckpt.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "host": "10.0.0.1",
                        "exporter": "redis_exporter",
                        "port": 9121,
                        "endpoint": "/metrics",
                        "ok": True,
                    }
                ),
                '{"host":"10.0.0.2","exporter":"node_exporter","port":"bad","endpoint":"/debug/vars"}',
                "not-json",
                json.dumps({"host": "", "exporter": "x", "port": 1, "endpoint": "/e"}),
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    jobs = collect._load_collect_completed_jobs(str(ckpt))
    assert ("10.0.0.1", "redis_exporter", 9121, "/metrics") in jobs
    assert len(jobs) == 1

    missing = collect._load_collect_completed_jobs(str(tmp_path / "missing.jsonl"))
    assert missing == set()

    console = collect.Console(debug=False)
    warn_jobs = collect._load_collect_completed_jobs(str(tmp_path), console=console)
    assert warn_jobs == set()
    out = capsys.readouterr().out
    assert "failed to load collect checkpoint" in out


def test_collect_resume_retries_failed_and_latest_failed_jobs(tmp_path: Path) -> None:
    ckpt = tmp_path / "collect.ckpt.jsonl"
    base = {"host": "h", "exporter": "node_exporter", "port": 9100, "endpoint": "/metrics"}
    ckpt.write_text(
        "\n".join(
            [
                json.dumps(base | {"ok": True, "status": 200}),
                json.dumps(base | {"ok": False, "status": None, "error": "timeout"}),
                json.dumps(base | {"endpoint": "/debug/vars", "ok": False, "status": 503}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert collect._load_collect_completed_jobs(str(ckpt)) == set()


def test_collect_resume_preserves_outputs_and_restores_validation_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect.jsonl"
    output_path.write_text('{"old":true}\n', encoding="utf-8")
    save_dir = tmp_path / "raw"
    save_dir.mkdir()
    index_path = save_dir / "index.jsonl"
    index_path.write_text('{"old_index":true}\n', encoding="utf-8")
    checkpoint_path = tmp_path / "collect.ckpt.jsonl"
    prior_record = {
        "host": "10.0.0.1",
        "exporter": "node_exporter",
        "port": 9100,
        "endpoint": "/metrics",
        "url": "http://10.0.0.1:9100/metrics",
        "ok": True,
        "status": 200,
        "body": "Authorization: Bearer A1b2C3d4E5f6G7h8I9j0K1l2",
    }
    checkpoint_path.write_text(
        json.dumps(
            {
                "host": "10.0.0.1",
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/metrics",
                "ok": True,
                "status": 200,
                "record": prior_record,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda _path: {
            "discovery_exporters": [{"name": "node_exporter", "port": 9100, "markers": ["node_"]}],
            "collect_exporters": [{"name": "node_exporter", "port": 9100}],
            "collect_debug_endpoints": ["/metrics"],
        },
    )
    monkeypatch.setattr(
        "redposture_core.stage_collect.scan_exporter_presence",
        lambda *_args, **_kwargs: (1, 0, {"10.0.0.1": []}),
    )

    rc = run_collect_stage(
        _base_args(
            output=str(output_path),
            output_format="json",
            save_responses_dir=str(save_dir),
            resume=True,
            checkpoint_file=str(checkpoint_path),
        ),
        AttemptLogger(),
    )

    assert rc == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert json.loads(output_lines[0]) == {"old": True}
    summary = json.loads(output_lines[-1])
    assert summary["type"] == "summary"
    assert summary["requests"] == summary["success"] == summary["resumed"] == 1
    assert json.loads(index_path.read_text(encoding="utf-8").splitlines()[0]) == {"old_index": True}
    vulnerable_urls = (tmp_path / "vulnerable_urls.txt").read_text(encoding="utf-8")
    assert "http://10.0.0.1:9100/metrics" in vulnerable_urls


def test_collect_stage_runs_scan_before_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 4, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        captured["found_by_host"] = kwargs.get("found_by_host")
        return 2, 2

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 0
    assert calls == ["scan", "collect"]
    assert captured["found_by_host"] == {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}


def test_collect_stage_skips_collect_when_scan_finds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 4, 0, {"10.0.0.1": []}

    def fake_collect(*_args: object, **_kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        return 0, 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 0
    assert calls == ["scan"]


def test_collect_stage_hides_scan_and_meta_without_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line("SCAN     10.0.0.1                         9100   [+] Node Exporter")
            emit_line("SCAN     summary                          -      [*] hosts=1 checks=1 found=1")
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line(
                "COLLECT  10.0.0.1                         9100   [+] Node Exporter url=http://10.0.0.1:9100/debug/vars"
            )
            emit_line("COLLECT  summary                          -      [*] hosts=1 requests=1 success=1")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(debug=False), AttemptLogger())
    assert rc == 0

    out = capsys.readouterr().out
    assert "SCAN" not in out
    assert "DISCOVER" in out
    assert "collect started" not in out
    assert "collect complete" in out
    assert "Node Exporter url=http://10.0.0.1:9100/debug/vars" in out


def test_collect_stage_creates_empty_index_when_save_dir_set_and_no_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_dir = tmp_path / "collect_raw"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 4, 0, {"10.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)

    rc = run_collect_stage(_base_args(save_responses_dir=str(save_dir)), AttemptLogger())
    assert rc == 0
    assert (save_dir / "index.jsonl").exists()


def test_collect_stage_appends_validate_output_to_txt_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_path = tmp_path / "collect.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            "COLLECT\t10.0.0.1\t9100\t[+] Node Exporter url=http://10.0.0.1:9100/debug/vars\n",
            encoding="utf-8",
        )
        return 1, 1

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            _ = (input_format, max_lines, precision_profile)

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, source, records_total)
            console.plain("VALIDATE\t10.0.0.1\t9100\t [*] Dump Validate Node Exporter")
            console.plain("VALIDATE\t10.0.0.1\t9100\t reason=password=value endpoint=/debug/vars")
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    contents = output_path.read_text(encoding="utf-8")
    assert "COLLECT\t10.0.0.1\t9100\t[+] Node Exporter url=http://10.0.0.1:9100/debug/vars" in contents
    assert "VALIDATE\t10.0.0.1\t9100\t [*] Dump Validate Node Exporter" in contents
    assert "VALIDATE\t10.0.0.1\t9100\t reason=password=value endpoint=/debug/vars" in contents


def test_collect_stage_creates_output_file_for_validate_when_scan_finds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_no_hits.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 0, {"10.0.0.1": []}

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            _ = (input_format, max_lines, precision_profile)

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, source, records_total)
            console.plain("VALIDATE\t-\t-\t [*] no credential hits")
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0
    assert output_path.exists()
    assert "VALIDATE\t-\t-\t [*] no credential hits" in output_path.read_text(encoding="utf-8")


def test_collect_stage_keeps_validate_summary_in_output_file_while_hiding_console(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "collect_summary.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 0, {"10.0.0.1": []}

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            _ = (input_format, max_lines, precision_profile)

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, source, records_total)
            console.plain("VALIDATE\t-\t-\t [!] validate complete: lines=10 credential_hits=2")
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    out = capsys.readouterr().out
    assert "validate complete: lines=10 credential_hits=2" not in out
    assert output_path.exists()
    assert "validate complete: lines=10 credential_hits=2" in output_path.read_text(encoding="utf-8")


def test_collect_stage_writes_json_summary_when_scan_finds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_no_hits.json"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 0, {"10.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)

    rc = run_collect_stage(_base_args(output=str(output_path), output_format="json"), AttemptLogger())
    assert rc == 0
    assert output_path.exists()

    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    summary = json.loads(lines[0])
    assert summary["type"] == "summary"
    assert summary["hosts"] == 1
    assert summary["requests"] == 0
    assert summary["success"] == 0
    assert summary["output_path"] == str(output_path)


def test_collect_stage_writes_json_summary_after_normal_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect.jsonl"
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda _path: {
            "discovery_exporters": [],
            "collect_exporters": [{"name": "node_exporter", "port": 9100}],
            "collect_debug_endpoints": ["/metrics"],
        },
    )
    monkeypatch.setattr(
        "redposture_core.stage_collect.scan_exporter_presence",
        lambda *_args, **_kwargs: (1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}),
    )

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        Path(str(kwargs["output_path"])).write_text('{"type":"record"}\n', encoding="utf-8")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    rc = run_collect_stage(_base_args(output=str(output_path), output_format="json"), AttemptLogger())

    assert rc == 0
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["type"] == "record"
    assert rows[-1]["type"] == "summary"
    assert rows[-1]["requests"] == rows[-1]["success"] == 1


def test_collect_stage_is_inconclusive_when_no_exporter_and_any_discovery_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda _path: {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/metrics"],
        },
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        stats = kwargs.get("stats_sink")
        assert isinstance(stats, dict)
        stats.update({"checks": 2, "found": 0, "errors": 1})
        return 2, 0, {"10.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    rc = run_collect_stage(_base_args(), AttemptLogger())

    assert rc == 1
    assert "no exporter confirmed; 1/2 discovery requests failed" in capsys.readouterr().err


def test_collect_stage_is_inconclusive_when_every_data_request_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda _path: {
            "discovery_exporters": [],
            "collect_exporters": [{"name": "node_exporter", "port": 9100}],
            "collect_debug_endpoints": ["/metrics", "/debug/vars"],
        },
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        stats = kwargs.get("stats_sink")
        assert isinstance(stats, dict)
        stats.update({"checks": 1, "found": 1, "errors": 0})
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        stats = kwargs.get("stats_sink")
        assert isinstance(stats, dict)
        stats.update({"requests": 2, "success": 0, "errors": 2})
        return 2, 0

    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    rc = run_collect_stage(_base_args(), AttemptLogger())

    assert rc == 1
    assert "collect inconclusive: every data request failed" in capsys.readouterr().err


def test_collect_stage_runs_validation_always(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        captured["save_responses_dir"] = kwargs.get("save_responses_dir")
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9100,
                    "exporter": "node_exporter",
                    "endpoint": "/debug/vars",
                    "body": "password=secret",
                }
            )
        return 1, 1

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            calls.append("validator_init")
            self._records: list[dict[str, object]] = []
            captured["input_format"] = input_format
            captured["max_lines"] = max_lines
            captured["precision_profile"] = precision_profile

        def feed(self, record: dict[str, object]) -> None:
            calls.append("validator_feed")
            self._records.append(record)

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            calls.append("validate")
            captured["records_len"] = len(self._records)
            captured["show"] = show
            captured["fail_on_creds"] = fail_on_creds
            captured["debug"] = debug
            captured["console_set"] = console is not None
            captured["source"] = source
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(
        _base_args(
            save_responses_dir="collect_raw",
        ),
        AttemptLogger(),
    )
    assert rc == 0
    assert calls == ["validator_init", "scan", "collect", "validator_feed", "validate"]
    assert captured["save_responses_dir"] == "collect_raw"
    assert captured["records_len"] == 1
    assert captured["input_format"] == "auto"
    assert captured["precision_profile"] == "collect_strict"
    assert captured["show"] is True
    assert captured["max_lines"] == 0
    assert captured["fail_on_creds"] is False
    assert captured["debug"] is False
    assert captured["console_set"] is True
    assert captured["source"] == "stream"


def test_collect_stage_filters_exporters_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [
                {"name": "redis_exporter", "port": 9121},
                {"name": "postgres_exporter", "port": 9187},
            ],
            "collect_exporters": [
                {"name": "redis_exporter", "port": 9121},
                {"name": "postgres_exporter", "port": 9187},
            ],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        discovery = list(kwargs.get("discovery_exporters") or [])
        captured["discovery_names"] = [str(item.get("name")) for item in discovery]
        return 1, 1, {"10.0.0.1": [{"exporter": "redis_exporter", "port": 9121}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        collect = list(kwargs.get("collect_exporters") or [])
        captured["collect_names"] = [str(item.get("name")) for item in collect]
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(collect_exporters_filter="redis"), AttemptLogger())
    assert rc == 0
    assert captured["discovery_names"] == ["redis_exporter"]
    assert captured["collect_names"] == ["redis_exporter"]


def test_collect_stage_rejects_unknown_exporter_filter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [{"name": "redis_exporter", "port": 9121}],
            "collect_exporters": [{"name": "redis_exporter", "port": 9121}],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)

    rc = run_collect_stage(_base_args(collect_exporters_filter="redis,unknown"), AttemptLogger())
    assert rc == 2
    captured = capsys.readouterr()
    assert "unsupported collect exporters: unknown" in (captured.out + captured.err)


def test_collect_stage_filters_exporters_by_new_short_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [
                {"name": "redis_exporter", "port": 9121},
                {"name": "pgbackrest_exporter", "port": 9854},
                {"name": "victoriametrics_exporter", "port": 8428},
            ],
            "collect_exporters": [
                {"name": "redis_exporter", "port": 9121},
                {"name": "pgbackrest_exporter", "port": 9854},
                {"name": "victoriametrics_exporter", "port": 8428},
            ],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        discovery = list(kwargs.get("discovery_exporters") or [])
        captured["discovery_names"] = [str(item.get("name")) for item in discovery]
        return 1, 1, {"10.0.0.1": [{"exporter": "pgbackrest_exporter", "port": 9854}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        collect = list(kwargs.get("collect_exporters") or [])
        captured["collect_names"] = [str(item.get("name")) for item in collect]
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(collect_exporters_filter="pgbackrest,victoriametrics"), AttemptLogger())
    assert rc == 0
    assert captured["discovery_names"] == ["pgbackrest_exporter", "victoriametrics_exporter"]
    assert captured["collect_names"] == ["pgbackrest_exporter", "victoriametrics_exporter"]


def test_collect_stage_builds_deep_endpoints_with_custom_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars", "/debug/pprof/profile?seconds={pprof_seconds}"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        captured["collect_debug_endpoints"] = kwargs.get("collect_debug_endpoints")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(
        _base_args(
            deep=True,
            pprof_seconds=11,
            trace_seconds=4,
        ),
        AttemptLogger(),
    )

    assert rc == 0
    endpoints = tuple(captured["collect_debug_endpoints"])
    assert "/debug/vars" in endpoints
    assert "/debug/pprof/profile?seconds=11" in endpoints
    assert "/debug/pprof/trace?seconds=4" in endpoints


@pytest.mark.parametrize("debug_mode", [False, True])
def test_collect_stage_hides_validate_summary_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    debug_mode: bool,
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 0, {"10.0.0.1": []}

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            _ = input_format
            _ = max_lines
            _ = precision_profile

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, source, records_total)
            console.plain("VALIDATE\t-\t-\t [!] validate complete: lines=10 credential_hits=2")
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(_base_args(debug=debug_mode), AttemptLogger())
    assert rc == 0

    out = capsys.readouterr().out
    assert "validate complete: lines=" not in out


def test_collect_stage_resume_passes_checkpoint_options(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint_path = tmp_path / "collect.ckpt.jsonl"
    checkpoint_path.write_text(
        json.dumps(
            {
                "host": "10.0.0.1",
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/debug/vars",
                "ok": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        captured.update(kwargs)
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(
        _base_args(
            output=str(tmp_path / "collect.txt"),
            save_responses_dir=str(tmp_path / "collect_raw"),
            resume=True,
            checkpoint_file=str(checkpoint_path),
        ),
        AttemptLogger(),
    )

    assert rc == 0
    assert captured["output_mode"] == "a"
    assert captured["index_mode"] == "a"
    assert captured["checkpoint_mode"] == "a"
    assert captured["checkpoint_path"] == str(checkpoint_path)
    completed = captured["resume_completed_jobs"]
    assert ("10.0.0.1", "node_exporter", 9100, "/debug/vars") in completed


def test_collect_stage_passes_adaptive_and_max_inflight_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        captured["adaptive_collect"] = kwargs.get("adaptive_collect")
        captured["max_inflight_requests"] = kwargs.get("max_inflight_requests")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(
        _base_args(
            adaptive_collect=False,
            max_inflight=256,
        ),
        AttemptLogger(),
    )

    assert rc == 0
    assert captured["adaptive_collect"] is False
    assert captured["max_inflight_requests"] == 256


def test_collect_stage_appends_connection_string_validate_hits_to_txt_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_validate.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/pprof/cmdline?debug=1"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "elasticsearch_exporter", "port": 9114}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            "COLLECT\t10.0.0.1\t9114\t[+] Elasticsearch Exporter url=http://10.0.0.1:9114/debug/pprof/cmdline?debug=1\n",
            encoding="utf-8",
        )
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:password@elastic.mydomain.local\n",
                }
            )
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    contents = output_path.read_text(encoding="utf-8")
    assert "Endpoint: /debug/pprof/cmdline?debug=1" in contents
    assert "Reason:" in contents
    assert "conn creds" in contents
    assert "Signals:" not in contents
    assert "Leak:" in contents
    assert "[HIT]" not in contents
    assert "[/HIT]" not in contents
    assert "es.uri=https://elastic:password@" in contents


def test_collect_stage_suppresses_placeholder_connection_string_validate_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_validate_placeholder.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/pprof/cmdline?debug=1"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "elasticsearch_exporter", "port": 9114}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            "COLLECT\t10.0.0.1\t9114\t[+] Elasticsearch Exporter url=http://10.0.0.1:9114/debug/pprof/cmdline?debug=1\n",
            encoding="utf-8",
        )
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://$ES_USERNAME:$ES_PASSWORD@elastic.mydomain.local\n",
                }
            )
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    contents = output_path.read_text(encoding="utf-8")
    assert "COLLECT\t10.0.0.1\t9114\t[+] Elasticsearch Exporter" in contents
    assert "Dump Validate Elasticsearch Exporter" not in contents
    assert "conn creds" not in contents


def test_collect_stage_summary_counts_only_shown_hits_after_score_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_validate_mixed.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/pprof/cmdline?debug=1"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "elasticsearch_exporter", "port": 9114}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            "COLLECT\t10.0.0.1\t9114\t[+] Elasticsearch Exporter url=http://10.0.0.1:9114/debug/pprof/cmdline?debug=1\n",
            encoding="utf-8",
        )
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://$ES_USERNAME:$ES_PASSWORD@elastic.mydomain.local\n",
                }
            )
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:password@elastic.mydomain.local\n",
                }
            )
        return 2, 2

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    contents = output_path.read_text(encoding="utf-8")
    assert "validate complete: lines=2 credential_hits=1 unique_hits=1" in contents


def test_collect_stage_writes_vulnerable_targets_files_next_to_output_and_dedupes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_validate_targets.txt"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/pprof/cmdline?debug=1"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "elasticsearch_exporter", "port": 9114}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            "COLLECT\t10.0.0.1\t9114\t[+] Elasticsearch Exporter url=http://10.0.0.1:9114/debug/pprof/cmdline?debug=1\n",
            encoding="utf-8",
        )
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            # Gated out in collect_strict: placeholder credentials.
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://$ES_USERNAME:$ES_PASSWORD@elastic.mydomain.local\n",
                }
            )
            # Shown hit (duplicate added twice to verify dedupe).
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:ElasticRead2026!@elastic.mydomain.local?api_key=ZXMtbGFiLWFwaS1rZXktMjAyNg==\n",
                }
            )
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:ElasticRead2026!@elastic.mydomain.local?api_key=ZXMtbGFiLWFwaS1rZXktMjAyNg==\n",
                }
            )
            # Second shown target.
            record_callback(
                {
                    "host": "collector.local",
                    "port": 9308,
                    "exporter": "kafka_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": (
                        "--kafka.server kafka-1.internal:9093 "
                        "--sasl.username metrics_collector "
                        "--sasl.password Sup3rS3cret2026\n"
                    ),
                }
            )
            # API-key-only hit: should not be added to vulnerable_ips.txt.
            record_callback(
                {
                    "host": "apikey-only.local",
                    "port": 9100,
                    "exporter": "node_exporter",
                    "endpoint": "/debug/vars",
                    "body": "Authorization: Bearer A1b2C3d4E5f6G7h8I9j0K1l2\n",
                }
            )
        return 4, 4

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(output=str(output_path)), AttemptLogger())
    assert rc == 0

    ips_file = tmp_path / "vulnerable_ips.txt"
    urls_file = tmp_path / "vulnerable_urls.txt"
    users_file = tmp_path / "vulnerable_users.txt"
    pass_file = tmp_path / "vulnerable_pass.txt"
    user_pass_file = tmp_path / "vulnerable_user_pass.txt"
    api_keys_file = tmp_path / "vulnerable_apikeys.txt"
    findings_file = tmp_path / "vulnerable_findings.md"
    assert ips_file.exists()
    assert urls_file.exists()
    assert users_file.exists()
    assert pass_file.exists()
    assert user_pass_file.exists()
    assert not (tmp_path / "vulnerable_passwords.txt").exists()
    assert api_keys_file.exists()
    assert findings_file.exists()

    ips = [line.strip() for line in ips_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    urls = [line.strip() for line in urls_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    users = [line.strip() for line in users_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    passwords = [line.strip() for line in pass_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    user_pass = [line.strip() for line in user_pass_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    api_keys = [line.strip() for line in api_keys_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert ips == ["10.0.0.1", "collector.local"]
    assert urls == [
        "http://10.0.0.1:9114/debug/pprof/cmdline?debug=1",
        "http://apikey-only.local:9100/debug/vars",
        "http://collector.local:9308/debug/pprof/cmdline?debug=1",
    ]
    assert users == ["elastic", "metrics_collector"]
    assert passwords == ["ElasticRead2026!", "Sup3rS3cret2026"]
    assert user_pass == ["elastic:ElasticRead2026!", "metrics_collector:Sup3rS3cret2026"]
    assert list(zip(ips, users, passwords, strict=False)) == [
        ("10.0.0.1", "elastic", "ElasticRead2026!"),
        ("collector.local", "metrics_collector", "Sup3rS3cret2026"),
    ]
    assert api_keys == [
        "10.0.0.1:9114:ZXMtbGFiLWFwaS1rZXktMjAyNg==",
        "apikey-only.local:9100:A1b2C3d4E5f6G7h8I9j0K1l2",
    ]
    findings = findings_file.read_text(encoding="utf-8")
    assert "# RedPosture Vulnerable Findings" in findings
    assert "ElasticRead2026!" in findings
    assert "apikey-only.local:9100:A1b2C3d4E5f6G7h8I9j0K1l2" in findings


def test_collect_stage_does_not_write_vulnerable_targets_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9100,
                    "exporter": "node_exporter",
                    "endpoint": "/debug/vars",
                    "body": "jdbc:postgresql://db.local/app?user=postgres&password=postgres\n",
                }
            )
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 0
    assert not (tmp_path / "vulnerable_ips.txt").exists()
    assert not (tmp_path / "vulnerable_urls.txt").exists()
    assert not (tmp_path / "vulnerable_users.txt").exists()
    assert not (tmp_path / "vulnerable_pass.txt").exists()
    assert not (tmp_path / "vulnerable_user_pass.txt").exists()
    assert not (tmp_path / "vulnerable_apikeys.txt").exists()
    assert not (tmp_path / "vulnerable_findings.md").exists()


def test_collect_stage_json_output_is_not_polluted_by_validate_txt_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "collect_validate.json"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/pprof/cmdline?debug=1"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "elasticsearch_exporter", "port": 9114}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        target = Path(str(kwargs["output_path"]))
        target.write_text(
            json.dumps(
                {
                    "type": "record",
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:password@elastic.mydomain.local",
                },
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9114,
                    "exporter": "elasticsearch_exporter",
                    "endpoint": "/debug/pprof/cmdline?debug=1",
                    "body": "--es.uri=https://elastic:password@elastic.mydomain.local\n",
                }
            )
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(output=str(output_path), output_format="json"), AttemptLogger())
    assert rc == 0

    contents = output_path.read_text(encoding="utf-8")
    assert '"exporter": "elasticsearch_exporter"' in contents
    assert "VALIDATE" not in contents


def test_collect_stage_argument_and_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    rc = run_collect_stage(_base_args(timeout=0), AttemptLogger())
    assert rc == 2
    rc = run_collect_stage(_base_args(retries=-1), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr("redposture_core.stage_collect.collect_scan_target_specs", lambda *_a, **_k: [])
    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_collect.collect_scan_target_specs",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad targets")),
    )
    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_collect.collect_scan_target_specs",
        lambda *_a, **_k: [argparse.Namespace(host="10.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("profiles fail")),
    )
    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda *_a, **_k: {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )
    monkeypatch.setattr(
        "redposture_core.stage_collect.collect_scan_ports",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad ports")),
    )
    rc = run_collect_stage(_base_args(ports="bad"), AttemptLogger())
    assert rc == 2


def test_collect_stage_explicit_port_groups_and_collect_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    target_specs = [
        argparse.Namespace(host="10.0.0.1", scheme=None, explicit_port=19100),
        argparse.Namespace(host="10.0.0.2", scheme=None, explicit_port=19101),
    ]
    scan_calls: list[list[int]] = []

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        ports = kwargs.get("custom_ports")
        assert isinstance(ports, list)
        scan_calls.append([int(ports[0])])
        port = int(ports[0])
        host = "10.0.0.1" if port == 19100 else "10.0.0.2"
        return 1, 1, {host: [{"exporter": "redis_exporter", "port": port}]}

    monkeypatch.setattr("redposture_core.stage_collect.collect_scan_target_specs", lambda *_a, **_k: target_specs)
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda *_a, **_k: {
            "discovery_exporters": [{"name": "redis_exporter", "port": 9121}],
            "collect_exporters": [{"name": "redis_exporter", "port": 9121}],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr(
        "redposture_core.stage_collect.collect_exporter_debug_data",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("collect write fail")),
    )

    rc = run_collect_stage(_base_args(targets="ignored"), AttemptLogger())
    assert rc == 2
    assert scan_calls == [[19100], [19101]]


def test_collect_stage_debug_emits_staged_markers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **_kwargs: object) -> tuple[int, int]:
        return 1, 1

    class _NoopValidator:
        def __init__(self, *, input_format: str, max_lines: int, precision_profile: str = "legacy") -> None:
            _ = (input_format, max_lines, precision_profile)

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, console, source, records_total)
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", _NoopValidator)

    rc = run_collect_stage(_base_args(debug=True), AttemptLogger())
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass=1 detect start total=1" in out
    assert "pass=2 deep start total=1" in out
    assert "stage2_gate=run reason=detected=1" in out
    assert "stage_timing_summary status=ok attempts=1/1" in out


def test_collect_stage_explicit_url_targets_use_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    # URL / explicit-port targets take the `has_target_overrides` path; it must own a
    # single command-level progress bar (per-group progress off), like `scan` does.
    monkeypatch.setattr(
        "redposture_core.stage_collect.load_profiles",
        lambda *_a, **_k: {
            "discovery_exporters": [{"port": 9353}],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )

    scan_show_progress_flags: list[bool] = []
    scan_calls = 0

    def fake_scan(*_a: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        nonlocal scan_calls
        scan_calls += 1
        scan_show_progress_flags.append(bool(kwargs.get("show_progress", True)))
        hosts = list(kwargs.get("hosts") or [])
        ports = list(kwargs.get("custom_ports") or [])
        return len(hosts) * len(ports), 0, {h: [] for h in hosts}

    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", lambda *_a, **_k: (0, 0))

    progress_totals: list[int] = []
    progress_advances: list[int] = []
    progress_closed = 0

    class _DummyProgress:
        def __init__(self, _label: str, total: int, **_kw: object) -> None:
            progress_totals.append(total)

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(amount)

        def close(self) -> None:
            nonlocal progress_closed
            progress_closed += 1

    monkeypatch.setattr(
        "redposture_core.stage_collect.start_command_progress",
        lambda _args, label, total, **kw: _DummyProgress(label, total, **kw),
    )

    rc = run_collect_stage(_base_args(targets="http://127.0.0.1:9353/,http://127.0.0.1:8008/"), AttemptLogger())
    assert rc == 0
    assert scan_calls == 2  # one execution group per distinct port
    assert scan_show_progress_flags == [False, False]  # per-group progress disabled
    assert len(progress_totals) == 1  # a single command-level bar owns the run
    assert sum(progress_advances) == 2  # advanced by discovery checks across groups
    assert progress_closed == 1


def test_collect_stage_large_list_uses_command_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    # The huge-target chunked path must also own a single command-level progress bar
    # (counted by hosts), instead of running with no progress at all.
    monkeypatch.setattr(collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(
        collect,
        "load_profiles",
        lambda *_a, **_k: {
            "discovery_exporters": [{"port": 9100}],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        },
    )

    scan_show_progress_flags: list[bool] = []

    def fake_scan(*_a: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        scan_show_progress_flags.append(bool(kwargs.get("show_progress", True)))
        hosts = list(kwargs.get("hosts") or [])
        # found>0 so the per-chunk collect runs and we can assert it owns no bar
        return len(hosts), len(hosts), {h: [{"exporter": "node_exporter", "port": 9100}] for h in hosts}

    collect_owner_args: list[object] = []

    def fake_collect(*_a: object, **kwargs: object) -> tuple[int, int]:
        collect_owner_args.append(kwargs.get("progress_owner"))
        return 0, 0

    monkeypatch.setattr(collect, "scan_exporter_presence", fake_scan)
    monkeypatch.setattr(collect, "collect_exporter_debug_data", fake_collect)

    progress_totals: list[int] = []
    progress_advances: list[int] = []
    progress_closed = 0

    class _DummyProgress:
        def __init__(self, _label: str, total: int, **_kw: object) -> None:
            progress_totals.append(total)

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(amount)

        def close(self) -> None:
            nonlocal progress_closed
            progress_closed += 1

    monkeypatch.setattr(
        "redposture_core.stage_collect.start_command_progress",
        lambda _args, label, total, **kw: _DummyProgress(label, total, **kw),
    )

    rc = run_collect_stage(_base_args(targets="10.0.0.0/30"), AttemptLogger())
    assert rc == 0
    assert scan_show_progress_flags and not any(scan_show_progress_flags)  # per-chunk scan progress off
    assert progress_totals == [2]  # one command-level bar for 10.0.0.1 + 10.0.0.2
    assert sum(progress_advances) == 2  # advanced by host count across chunks
    assert progress_closed == 1
    # per-chunk collect must NOT own its own bar (would close the command-level one)
    assert collect_owner_args and all(owner is None for owner in collect_owner_args)
