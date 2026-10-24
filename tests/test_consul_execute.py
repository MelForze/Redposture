"""Bounded one-shot Consul script-check execution contracts."""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import Mock

from redposture_core.modules.consul import execution


def _ctx(command: str = "printf hello; exit 7") -> SimpleNamespace:
    return SimpleNamespace(
        args=SimpleNamespace(execute=command, execute_timeout=1.0, execute_max_bytes=4096),
        host="consul.test",
        port=8500,
    )


def _state() -> SimpleNamespace:
    return SimpleNamespace(
        scheme="http",
        insecure=False,
        auth_headers=None,
        host="consul.test",
        port=8500,
        execution=None,
    )


def _record(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "is_consul": True,
        "detection_status": "confirmed",
        "status": "open_no_auth",
        "rce": True,
    }
    result.update(changes)
    return result


def test_collect_proves_exit_and_deregisters_temporary_check(monkeypatch) -> None:
    registered: list[dict[str, object]] = []
    monkeypatch.setattr(
        execution.actions,
        "_consul_put_json",
        Mock(side_effect=lambda *args, **kwargs: (registered.append(args[4]) or 200, None, None)),
    )
    marker_output: list[str] = []

    def checks(*_args, **_kwargs):
        payload = registered[0]
        command = payload["Args"][2]
        end_marker = "RP_EXEC_END_" + re.search(r"RP_EXEC_END_[0-9a-f]+", command).group(0).split("RP_EXEC_END_", 1)[1]
        marker_output.append(end_marker)
        return (
            200,
            {
                payload["ID"]: {
                    "Status": "critical",
                    "Output": f"hello\n{end_marker}:7\n",
                }
            },
            None,
        )

    monkeypatch.setattr(execution.actions, "_consul_get_checks", checks)
    deregister = Mock(return_value=(204, None))
    monkeypatch.setattr(execution.actions, "_consul_put_no_body", deregister)
    state = _state()

    result = execution.collect(_ctx(), _record(), state)

    assert result["execute_verified"] is True
    assert result["execution"]["executed"] is True
    assert result["execution"]["exit_code"] == 7
    assert result["execution"]["stdout"] == "hello"
    assert result["execution"]["stderr"] == ""
    assert result["execution"]["cleanup"] == "complete"
    assert len(deregister.call_args_list) == 1
    assert registered[0]["Args"][:2] == ["/bin/sh", "-c"]


def test_collect_does_not_send_for_unverified_consul(monkeypatch) -> None:
    put = Mock()
    monkeypatch.setattr(execution.actions, "_consul_put_json", put)

    result = execution.collect(_ctx(), _record(status="auth_required", rce=True), _state())

    assert result["execute_verified"] is False
    assert "not verified" in result["execution"]["error"]
    put.assert_not_called()


def test_collect_deregisters_when_polling_fails(monkeypatch) -> None:
    monkeypatch.setattr(execution.actions, "_consul_put_json", Mock(return_value=(200, None, None)))
    monkeypatch.setattr(execution.actions, "_consul_get_checks", Mock(side_effect=OSError("poll failed")))
    deregister = Mock(return_value=(204, None))
    monkeypatch.setattr(execution.actions, "_consul_put_no_body", deregister)

    result = execution.collect(_ctx(), _record(), _state())

    assert result["execute_verified"] is False
    assert result["execution"]["cleanup"] == "complete"
    assert result["execution"]["error"] == "poll failed"
    deregister.assert_called_once()


def test_collect_caches_before_request_and_does_not_replay(monkeypatch) -> None:
    put = Mock(side_effect=OSError("write failed"))
    monkeypatch.setattr(execution.actions, "_consul_put_json", put)
    state = _state()

    first = execution.collect(_ctx(), _record(), state)
    second = execution.collect(_ctx(), _record(), state)

    assert first["execution"] is second["execution"]
    assert put.call_count == 1
