"""Performance debug must include actual output I/O, not a discarded callback."""

from __future__ import annotations

import hashlib
import io
import threading
from types import SimpleNamespace

import pytest

from scripts.profile_module_performance import configure_profile_debug, profile_output_files


@pytest.mark.parametrize("enabled", [True, False])
def test_public_cli_owns_its_debug_emitter_instead_of_a_noop(enabled):
    options = SimpleNamespace(debug=enabled, debug_emit=lambda _: None)
    configure_profile_debug(options, public=True)
    assert options.debug_emit is None


def test_detect_debug_cannot_silently_discard_output():
    with pytest.raises(ValueError, match="real output sink"):
        configure_profile_debug(SimpleNamespace(debug=True), public=False)
    options = SimpleNamespace(debug=False)
    configure_profile_debug(options, public=False)
    assert options.debug_emit is None


def test_owned_sink_keeps_full_lines_and_serializes_concurrent_emissions():
    class Sink(io.StringIO):
        flushes = 0

        def flush(self):
            self.flushes += 1
            return super().flush()

    sink = Sink()
    options = SimpleNamespace(debug=True)
    configure_profile_debug(options, public=False, sink=sink)

    def send(index):
        for i in range(25):
            options.debug_emit(f"worker-{index}-{i}:" + "полный вывод" * 100)

    workers = [threading.Thread(target=send, args=(i,)) for i in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(2)
        assert not worker.is_alive()
    lines = sink.getvalue().splitlines()
    assert set(lines) == {f"worker-{index}-{i}:" + "полный вывод" * 100 for index in range(4) for i in range(25)}
    assert len(lines) == sink.flushes == 100


def test_output_evidence_hashes_full_file_without_reading_it_in_one_piece(tmp_path):
    path = tmp_path / "debug.log"
    data = ("полный вывод\n" * 10000).encode()
    path.write_bytes(data)
    assert profile_output_files([path, tmp_path / "absent"]) == [
        {"path": "debug.log", "bytes": len(data), "newlines": 10000, "sha256": hashlib.sha256(data).hexdigest()}
    ]


def test_public_default_runtime_receives_the_real_console_emitter(monkeypatch):
    from redposture_core import stage_runtime

    options = SimpleNamespace(debug=True, command="grafana", output_format="json")
    configure_profile_debug(options, public=True)
    lines = []
    console = SimpleNamespace(set_structured_output=lambda _: None, info=lines.append)

    class Runner:
        def __init__(self, *, args, **_):
            self.args = args

        def run_plan(self, _plan):
            self.args.debug_emit("actual runtime debug marker")
            return SimpleNamespace(detected_count=1, operational_failure_count=0, summary_emitted=True)

    monkeypatch.setattr(stage_runtime, "AuditCommandRunner", Runner)
    code = stage_runtime.run_basic_host_audit(
        options,
        None,
        console=console,
        label="GRAFANA",
        validate=lambda *_: None,
        build_plan=lambda _: stage_runtime.AuditCommandPlan(),
        build_spec=lambda _: stage_runtime.ModuleAuditSpec("grafana", "GRAFANA", 3000),
    )
    assert code == 0 and "actual runtime debug marker" in lines
