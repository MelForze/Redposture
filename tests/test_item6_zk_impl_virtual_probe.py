"""NEXT_QA #6 — ZooKeeper implementation: обработчик исключения virtual-probe.

engine.py 225-229: когда fingerprint не определил is_keeper (None) и есть анонимный
клиент, движок пробует keeper virtual-znode probe; если проба бросает
Timeout/Connection/OS/ValueError — исключение ловится и превращается в
`ZkKeeperVirtualProbe(confirmed=False, reason=...)`, is_keeper остаётся None.

Запускается РЕАЛЬНЫЙ engine (подменены нижние detect_zookeeper и
fingerprint_zookeeper_implementation), чтобы пройти именно эту ветвь.

Now part of the ordinary pytest suite.
"""

from __future__ import annotations

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.zookeeper import ZkImplementationFingerprint
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine as impl
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


class _RaisingClient:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def probe_keeper_virtual_nodes(self):
        raise self._exc


def _run_detect(monkeypatch: pytest.MonkeyPatch, exc: Exception):
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(
        AuditHookContext(
            args=args,
            logger=None,
            host="127.0.0.1",
            port=9181,
            credential=AuditCredentialRun(source="anonymous"),
            lifecycle_state=None,
        )
    )

    def fake_detect(ctx, _options):
        # ctx здесь уже zookeeper_state (engine сделал replace); ставим клиент,
        # у которого virtual-probe бросает.
        ctx.lifecycle_state.anonymous_client = _RaisingClient(exc)
        return {
            "host": ctx.host,
            "port": ctx.port,
            "service": "keeper",
            "status": "open_no_auth",
            "auth_required": False,
            "is_zookeeper": True,
            "transport": "plaintext",
        }

    # fingerprint с is_keeper=None → движок зайдёт в virtual-probe ветвь
    fp = ZkImplementationFingerprint("zookeeper", None, "unconfirmed")
    monkeypatch.setattr(impl.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(impl, "fingerprint_zookeeper_implementation", lambda *_a, **_k: fp)

    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    return spec.detect(ctx).to_dict()


@pytest.mark.parametrize(
    "exc",
    [ConnectionError("reset"), TimeoutError("slow"), OSError("broken pipe"), ValueError("bad frame")],
)
def test_virtual_probe_exception_is_caught_and_marked_unconfirmed(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    payload = _run_detect(monkeypatch, exc)

    # проба не подтвердила, но и не уронила детект
    probe = payload.get("keeper_virtual_probe")
    assert isinstance(probe, dict)
    assert probe["confirmed"] is False
    assert isinstance(probe["reason"], str) and probe["reason"]
    # is_keeper остался неопределённым (апгрейда до clickhouse-keeper не было)
    assert payload.get("is_keeper") is None
    assert payload.get("implementation_evidence") == "unconfirmed"
