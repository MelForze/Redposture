"""Run emitted Groovy against a real JVM without starting a product stand."""

from __future__ import annotations

import base64
import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest


def run_groovy(script: str, *, after: str = "") -> str:
    java = shutil.which("java")
    classpath = os.environ.get("GROOVY_CLASSPATH")
    if not classpath:
        gradle = Path.home() / ".gradle" / "wrapper" / "dists"
        for jar in sorted(gradle.glob("gradle-*-bin/*/gradle-*/lib/groovy-[0-9]*.jar"), reverse=True):
            if list(jar.parent.glob("groovy-json-*.jar")):
                classpath = str(jar.parent / "*")
                break
    if not java or not classpath:
        pytest.skip("real Groovy regression needs Java and GROOVY_CLASSPATH or cached Gradle Groovy jars")
    encoded = base64.b64encode(script.encode()).decode()
    harness = (
        'def source = new String(java.util.Base64.decoder.decode("' + encoded + '"), "UTF-8")\n'
        "try { def value = new GroovyShell().evaluate(source); if (value != null) println(value) }\n"
        "catch (RuntimeException failure) { println(failure.toString()) }\n" + after
    )
    child = subprocess.Popen(
        [java, "-Xms16m", "-Xmx128m", "-cp", classpath, "groovy.ui.GroovyMain", "-e", harness],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, stderr
        return stdout
    finally:
        if os.name == "posix":
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif child.poll() is None:
            child.kill()
        child.wait(timeout=5)
