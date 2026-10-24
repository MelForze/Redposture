"""Native legacy-host adapters reuse the exact synchronous argument contract."""

from types import SimpleNamespace

from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def test_preparing_host_arguments_performs_no_host_work():
    from redposture_core.stage_runtime import _invoke_host_stage, _prepare_host_stage_call

    calls = []

    def hook(host, port, timeout, retries, *, run_deep_checks, username, password):
        calls.append((host, port, timeout, retries, run_deep_checks, username, password))
        return {"host": host, "port": port, "service": "probe", "status": "detected"}

    ctx = AuditHookContext(
        args=SimpleNamespace(timeout=2, retries=1),
        logger=None,
        host="127.0.0.1",
        port=1234,
        credential=AuditCredentialRun(username="u", password="p"),
        run_deep_checks=True,
    )
    func, pos, kw = _prepare_host_stage_call(hook, module="probe", ctx=ctx, run_deep_checks=False)
    assert not calls
    assert func is hook
    _invoke_host_stage(hook, module="probe", ctx=ctx, run_deep_checks=False)
    expected = calls[:]
    calls.clear()
    func(*pos, **kw)
    assert calls == expected == [("127.0.0.1", 1234, 2.0, 1, False, "u", "p")]
