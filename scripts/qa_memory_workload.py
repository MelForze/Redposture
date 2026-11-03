"""Run full-cardinality memory assertions without the parent's coverage tracer.

Callers cover the same functional branches on a smaller input in the parent.
The child retains all data/memory assertions and has its own stack/exit deadline.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run_memory_workload(path: str | Path, function: str, count: int, *, timeout: float = 150) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    source = Path(path)
    if not source.is_absolute():
        source = root / source
    program = """
import faulthandler, json, runpy, sys
if sys.flags.optimize:
    raise RuntimeError('memory workload requires enabled assertions')
namespace = runpy.run_path(sys.argv[1])
assert sys.gettrace() is None, 'memory workload unexpectedly inherited tracing'
active_coverage = sys.modules.get('coverage')
assert active_coverage is None or active_coverage.Coverage.current() is None, 'memory workload inherited coverage'
faulthandler.dump_traceback_later(float(sys.argv[4]), exit=True)
proof = namespace[sys.argv[2]](int(sys.argv[3]))
faulthandler.cancel_dump_traceback_later()
print(json.dumps(proof))
"""
    with tempfile.TemporaryDirectory(prefix="redposture-memory-workload-") as temporary:
        workload_env = os.environ.copy()
        workload_env.update(TMPDIR=temporary, TMP=temporary, TEMP=temporary, SQLITE_TMPDIR=temporary)
        completed = subprocess.run(
            [sys.executable, "-c", program, str(source), function, str(count), str(min(140, timeout))],
            cwd=root,
            env=workload_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    proof = json.loads(completed.stdout)
    assert isinstance(proof, dict) and proof.get("count") == count, proof
    return proof
