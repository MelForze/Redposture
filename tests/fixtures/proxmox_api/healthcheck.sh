#!/bin/sh
set -eu
mountpoint -q /etc/pve
pvedaemon status >/dev/null
pveproxy status >/dev/null
test -s /run/pvestatd.pid
kill -0 "$(cat /run/pvestatd.pid)"
curl --fail --silent --show-error --insecure --max-time 5 \
  https://127.0.0.1:8006/api2/json/access/domains \
  | grep -q '"realm":"pam"'
