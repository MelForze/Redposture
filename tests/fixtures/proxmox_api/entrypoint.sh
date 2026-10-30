#!/bin/bash
set -Eeuo pipefail

if [[ -z "${PVE_ROOT_PASSWORD:-}" ]]; then
  echo 'PVE_ROOT_PASSWORD must be set' >&2
  exit 2
fi

printf 'root:%s\n' "$PVE_ROOT_PASSWORD" | chpasswd
unset PVE_ROOT_PASSWORD

# pmxcfs identifies a node by a stable hostname and its locally resolved IP.
node_name="$(hostname -s)"
node_ip="$(hostname -i | awk '{print $1}')"
if [[ -z "$node_ip" || "$node_ip" == 127.* ]]; then
  echo "Cannot resolve $node_name to a non-loopback address" >&2
  exit 1
fi

mkdir -p /var/lib/pve-cluster /var/log/pve /run/pve-cluster /run/pveproxy /run/pvedaemon
mkdir -p /root/.ssh
chmod 0700 /root/.ssh
chown www-data:www-data /run/pveproxy
ssh-keygen -A
rsyslogd
for _ in $(seq 1 20); do
  [[ -S /dev/log ]] && break
  sleep 0.1
done
echo "Starting pmxcfs for standalone node $node_name ($node_ip)"
pmxcfs
for _ in $(seq 1 60); do
  if mountpoint -q /etc/pve; then
    break
  fi
  sleep 1
done
if ! mountpoint -q /etc/pve; then
  echo 'pmxcfs did not mount /etc/pve' >&2
  exit 1
fi

pvecm updatecerts --force
pvedaemon start
pveproxy start
pvestatd start

echo "Proxmox web/API starting on https://0.0.0.0:8006"
stop_services() {
  for name in pvestatd pveproxy pvedaemon; do
    pid_file="/run/$name/${name}.pid"
    [[ "$name" == pvestatd ]] && pid_file="/run/pvestatd.pid"
    if [[ -s "$pid_file" ]]; then
      kill "$(cat "$pid_file")" 2>/dev/null || true
    fi
  done
  killall pmxcfs 2>/dev/null || true
}
trap stop_services TERM INT
while :; do
  /usr/local/sbin/proxmox-lab-healthcheck || true
  sleep 10 & wait $!
done
