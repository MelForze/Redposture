"""Shared bounded process collection for administrative Groovy surfaces."""

from __future__ import annotations

import base64


def process_script(
    command: str, milliseconds: int, limit: int, *, login_shell: bool = False, windows: bool = False
) -> str:
    """Collect both pipes while the child runs and preserve data after a kill.

    Polling available bytes avoids reader threads that can outlive the script
    when a descendant inherits a pipe. Every stream operation after process
    termination tolerates the JVM closing that stream underneath us.
    """
    encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
    shell_flag = "-lc" if login_shell else "-c"
    return (
        r"""
def command = new String(java.util.Base64.decoder.decode("{{COMMAND}}"), "UTF-8")
def useSetsid = new File("/usr/bin/setsid").isFile()
def usePerlSetsid = !useSetsid && new File("/usr/bin/perl").isFile()
def procArgs = new File("C:/Windows").isDirectory()
  ? ["cmd.exe", "/c", command]
  : useSetsid
    ? ["/usr/bin/setsid", "/bin/sh", "{{SHELL_FLAG}}", command]
    : usePerlSetsid
      ? ["/usr/bin/perl", "-MPOSIX", "-e", "POSIX::setsid(); exec @ARGV", "/bin/sh", "{{SHELL_FLAG}}", command]
      : ["/bin/sh", "{{SHELL_FLAG}}", command]
def proc = new ProcessBuilder(procArgs as String[]).start()
def out = new ByteArrayOutputStream()
def err = new ByteArrayOutputStream()
int used = 0
boolean clipped = false
boolean timed = false
boolean isolatedGroup = !new File("C:/Windows").isDirectory() && (useSetsid || usePerlSetsid)
long deadline = new Date().time + {{MILLISECONDS}}L
def descendants = new LinkedHashMap()
def rememberChildren = {
  try {
    def children = proc.toHandle().descendants()
    try {
      children.forEach({ child -> descendants.put(child.pid(), child) } as java.util.function.Consumer)
    } finally { children.close() }
  } catch (Exception ignored) {}
}
def drain = { stream, dest ->
  int drained = 0
  try {
    for (int round = 0; round < 32; round++) {
      int ready = stream.available()
      if (ready <= 0) break
      byte[] buf = new byte[Math.min(8192, ready)]
      int n = stream.read(buf)
      if (n <= 0) break
      int keep = Math.min(n, Math.max(0, {{LIMIT}} - used))
      if (keep > 0) dest.write(buf, 0, keep)
      used += keep
      drained += n
      if (keep < n) clipped = true
    }
  } catch (java.io.IOException ignored) {}
  return drained
}
try {
  try { proc.outputStream.close() } catch (java.io.IOException ignored) {}
  while (true) {
    rememberChildren()
    int drained = drain(proc.inputStream, out) + drain(proc.errorStream, err)
    if (!proc.isAlive() && drained == 0) break
    if (new Date().time >= deadline) { timed = true; break }
    if (drained == 0) Thread.sleep(5)
  }
} finally {
  rememberChildren()
  if (isolatedGroup && proc.isAlive()) {
    try {
      def killer = new ProcessBuilder(["/bin/kill", "-KILL", "-" + proc.pid()]).start()
      killer.waitFor(500L, java.util.concurrent.TimeUnit.MILLISECONDS)
    } catch (Exception ignored) {}
  }
  if (proc.isAlive()) {
    try { proc.destroyForcibly() } catch (Exception ignored) {}
  }
  new ArrayList(descendants.values()).each { child ->
    try { if (child.isAlive()) child.destroyForcibly() } catch (Exception ignored) {}
  }
  new ArrayList(descendants.values()).each { child ->
    try { child.onExit().get(500L, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (Exception ignored) {}
  }
  if (proc.isAlive()) {
    try { proc.destroyForcibly() } catch (Exception ignored) {}
    try { proc.waitFor(500L, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (Exception ignored) {}
  }
  long drainDeadline = new Date().time + 250L
  for (int round = 0; round < 16 && new Date().time < drainDeadline; round++) {
    if (drain(proc.inputStream, out) + drain(proc.errorStream, err) == 0) break
  }
  for (def stream : [proc.outputStream, proc.inputStream, proc.errorStream]) {
    try { stream.close() } catch (java.io.IOException ignored) {}
  }
}
int exitCode = proc.isAlive() ? -1 : proc.exitValue()
byte[] stdout = out.toByteArray()
byte[] stderr = err.toByteArray()
""".replace("{{COMMAND}}", encoded)
        .replace("{{SHELL_FLAG}}", shell_flag)
        .replace("{{MILLISECONDS}}", str(max(1, milliseconds)))
        .replace("{{LIMIT}}", str(limit))
    )
