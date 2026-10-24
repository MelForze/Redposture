"""Bounded native discovery feeding the existing cooperative spray scheduler."""

from __future__ import annotations

import copy
import importlib
import queue
import threading
from dataclasses import replace
from typing import Any

from .async_detection import AsyncDetectScheduler, async_detection_allowed
from .stage_runtime import AuditCommandRunner, AuditCredentialRun, AuditHookContext


async def prepare_target(job: Any, logger: Any) -> Any:
    module, base_ns, host, port, target = job
    ns = copy.copy(base_ns)
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(ns)
    if spec.detect_async is None or spec.detect is not spec.async_detect_sync_hook or not async_detection_allowed(ns):
        return None
    if module == "keeper":
        # Spray is read-only: ordinary Keeper detection also probes DDL create/delete.
        from .audit_models import AuditRecord
        from .clients import zookeeper as client
        from .clients.async_retained_socket import detect_native
        from .detection_io import DetectCall
        from .modules.keeper.stage import _build_keeper_lifecycle_options
        from .modules.zookeeper import actions, engine

        options = _build_keeper_lifecycle_options(ns)

        def steps(ctx: Any) -> Any:
            payload = engine.enforce_expected_implementation(
                (yield DetectCall(engine.detect_zookeeper_implementation, (ctx, options), {})), expected_is_keeper=True
            )
            payload.update(module="keeper", service="keeper")
            return AuditRecord.from_mapping(payload, module="keeper", service="keeper")

        async def readonly(ctx: Any, http: Any) -> Any:
            return await detect_native(
                steps(ctx),
                http,
                {**actions._ASYNC_RETAINED_STEPS, **engine._ASYNC_RETAINED_STEPS, **client._ASYNC_RETAINED_STEPS},
            )

        spec = replace(spec, detect_async=readonly)
    if module == "oracle":
        from .audit_models import AuditRecord
        from .clients.async_oracle_detect import spray_preflight

        oracle_backend = spec.detect_async

        async def guarded_oracle(ctx: Any, http: Any) -> Any:
            if not await spray_preflight(ctx.host, ctx.port, ctx.args):
                return AuditRecord(
                    host=ctx.host,
                    port=ctx.port,
                    module="oracle",
                    service="oracle",
                    status="not_oracle",
                    extra={"is_oracle": False},
                )
            assert oracle_backend is not None
            return await oracle_backend(ctx, http)

        spec = replace(spec, detect_async=guarded_oracle)
    runner = AuditCommandRunner(args=ns, spec=spec, logger=logger, emit_line=lambda _line: None)
    try:
        outcome = await runner._run_async_detect_with_state(host, port, target, None)
        if outcome is None:
            runner._close_all_lifecycle_states()
            return None
        ctx = AuditHookContext(
            ns,
            logger,
            host,
            port,
            AuditCredentialRun(source="anonymous"),
            target=target,
            run_deep_checks=False,
            phase="detect",
            lifecycle_state=outcome.lifecycle_state,
        )
        return ns, spec, runner, ctx, outcome
    except BaseException:
        runner._close_all_lifecycle_states()
        raise


_DONE = object()


class PreparedSource:
    """Pollable bounded source; waiting for I/O never blocks spray cooldowns."""

    def __init__(self, items: Any, logger: Any, gate: Any, journal: Any, limit: int, workers: int):
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max(1, workers * 2))
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._active: dict[int, Any] = {}
        self._error: BaseException | None = None

        def put(value: Any) -> bool:
            while not self._stop.is_set():
                try:
                    self._queue.put(value, timeout=0.02)
                    return True
                except queue.Full:
                    pass
            return False

        async def prepare(job: Any) -> Any:
            from .stage_spray import _attempt_id

            if gate.cancelled.is_set() or journal.job_finished(_attempt_id(job[0], job[4], job[3], -1)):
                return None
            value = await prepare_target(job, logger)
            if value is not None:
                with self._lock:
                    self._active[id(value)] = value
            return value

        def producer() -> None:
            outcomes: Any = AsyncDetectScheduler[Any, Any, Any](
                detect_workers=limit, deep_workers=1, max_inflight=limit + workers * 2
            ).iter_completed(items, prepare, lambda _job, value: value, cancel_event=self._stop)
            try:
                for job, value in outcomes:
                    if not put((job, value)):
                        break
            except BaseException as exc:
                self._error = exc
            finally:
                outcomes.close()
                put(_DONE)

        self._thread = threading.Thread(target=producer, name="redposture-spray-detect-source", daemon=True)
        self._thread.start()

    def __iter__(self):
        return self

    def __next__(self):
        value = self._queue.get_nowait()
        if value is _DONE:
            if self._error is not None:
                raise self._error
            raise StopIteration
        return value

    def release(self, value: Any) -> None:
        if value is not None:
            value[2]._close_all_lifecycle_states()
            with self._lock:
                self._active.pop(id(value), None)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.5)
        with self._lock:
            active = list(self._active.values())
            self._active.clear()
        for value in active:
            value[2]._close_all_lifecycle_states()
