from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from redposture_core.console import Console
from redposture_core.listener_runtime import stop_started_listeners
from redposture_core.validate import artifacts, engine


def test_validation_extracts_once_per_response_and_forgets_body(tmp_path):
    body = "\n".join(f"username=alice password=ProofValue{i}!" for i in range(8))
    accumulator = engine.ValidationRecordAccumulator(
        input_format="txt", max_lines=0, precision_profile="collect_strict"
    )
    with (
        patch.object(
            engine, "_extract_vulnerable_login_pairs_from_hit", wraps=engine._extract_vulnerable_login_pairs_from_hit
        ) as pairs,
        patch.object(
            engine, "_extract_vulnerable_credentials_from_hit", wraps=engine._extract_vulnerable_credentials_from_hit
        ) as credentials,
    ):
        accumulator.feed(dict(host="qa", port=9443, exporter="node_exporter", endpoint="/debug/vars", body=body))
        artifacts.write_vulnerable_targets_files(base_dir=str(tmp_path), validator=accumulator)
        artifacts.write_vulnerable_targets_files(base_dir=str(tmp_path), validator=accumulator)
    assert accumulator.shown_hit_count == 8
    assert pairs.call_count == 1 and credentials.call_count == 1
    assert all("body" not in hit for hit in accumulator.matches_raw + accumulator.matches_shown)
    assert len(accumulator.vulnerable_login_rows_from_shown_hits()) == 8


def test_validation_preserves_each_source_url(tmp_path):
    accumulator = engine.ValidationRecordAccumulator(input_format="txt", max_lines=1)
    for scheme in ("https", "http"):
        accumulator.feed(
            dict(
                host="qa",
                port=9443,
                exporter="node_exporter",
                endpoint="/debug/vars",
                url=f"{scheme}://qa:9443/debug/vars",
                body="username=alice password=ProofValue!",
            )
        )
    artifacts.write_vulnerable_targets_files(base_dir=str(tmp_path), validator=accumulator)
    assert (tmp_path / "vulnerable_urls.txt").read_text().splitlines() == [
        "http://qa:9443/debug/vars",
        "https://qa:9443/debug/vars",
    ]


def test_validation_unreadable_and_partially_read_input_are_incomplete(tmp_path, capsys):
    readable, unreadable = tmp_path / "a.txt", tmp_path / "b.txt"
    readable.write_text("nothing here")
    unreadable.write_text("not accessible")
    real_read = Path.read_text

    def read(path, *args, **kwargs):
        if path == unreadable:
            raise PermissionError("denied")
        return real_read(path, *args, **kwargs)

    with patch.object(Path, "read_text", read):
        assert engine.run_validation(str(unreadable), fail_on_creds=True, console=Console(no_color=True)) == 2
        assert engine.run_validation(str(tmp_path), fail_on_creds=True, console=Console(no_color=True)) == 2
    output = capsys.readouterr().out
    assert "validate incomplete" in output
    assert "[+] validate complete" not in output
    assert "\x1b[" not in output


def test_listener_close_attempted_even_when_shutdown_fails(tmp_path):
    failing, later = Mock(), Mock()
    failing.shutdown.side_effect = OSError("shutdown failed")
    stop_started_listeners([SimpleNamespace(server=failing), SimpleNamespace(server=later)], str(tmp_path))
    failing.server_close.assert_called_once()
    later.server_close.assert_called_once()
    assert not tmp_path.exists()


def test_validation_incomplete_summary_uses_unknown_color():
    from redposture_core.validate.render import _render_validate_complete_row

    colors = []
    console = Mock()
    console._paint.side_effect = lambda text, color, stream: colors.append((text, color)) or text
    _render_validate_complete_row(
        console, host="-", port="-", total_lines=0, credential_hits=0, unique_hits=0, ok=True, unreadable_files=1
    )
    assert any("validate incomplete" in text and color == "orange" for text, color in colors)
    assert not any(text == "[+]" for text, _ in colors)
