#!/bin/sh
set -eu
# Only the isolated, privileged execution profile mounts this private hierarchy.
# Docker exec health checks introduce processes into the parent cgroup during
# Nomad's v2 delegation and can cause EBUSY. Readiness is checked over HTTP.
[ "$(cat /proc/self/cgroup)" = "0::/" ] || { echo 'A private cgroup v2 namespace is required' >&2; exit 1; }
mount -o remount,rw /sys/fs/cgroup
mkdir -p /sys/fs/cgroup/agent
echo $$ > /sys/fs/cgroup/agent/cgroup.procs
exec /bin/nomad agent -config=/etc/nomad/qa.hcl
