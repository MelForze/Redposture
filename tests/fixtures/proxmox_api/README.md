# Real Proxmox API fixture, without a hypervisor

This versioned fixture runs genuine PVE packages (`pmxcfs`, `pveproxy`, `pvedaemon`) in a disposable Debian container. It uses the locally cached `redposture-proxmox-native-proxmox:latest` image or can be built from the supplied Dockerfile. Run it alone, after other QA stands have been removed. `/dev/fuse` and `SYS_ADMIN` are required for the cluster filesystem; the host Docker socket, host root directory and KVM are not mounted. CPU, memory and PID limits are explicit.

API users, ACLs, tokens, TLS login and API discovery can be checked here. VM/CT creation, guest execution, hypervisor/kernel, storage and hardware status are **not** validated by this container. A synthetic VM configuration used by a discovery test is just an API-readable fixture file, not a running guest.

Use a fresh artifact directory and a dedicated project. Set a disposable `PVE_ROOT_PASSWORD` before starting, determine the random loopback port with `docker compose port proxmox 8006`, and use the volume guard for startup and teardown. The guard removes only this run's new volumes; the historical persistent native stand and its volumes are not adopted or reset.

```bash
PVE_ROOT_PASSWORD=qa-local-only .venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-pve-api/volumes docker compose -p rp-pve-api -f tests/fixtures/proxmox_api/docker-compose.yml up -d --no-build --pull never --wait --wait-timeout 240
PVE_ROOT_PASSWORD=qa-local-only docker compose -p rp-pve-api -f tests/fixtures/proxmox_api/docker-compose.yml port proxmox 8006
.venv/bin/python redposture.py proxmox -t https://127.0.0.1:PORT -u root@pam -p qa-local-only --nodes --users
PVE_ROOT_PASSWORD=qa-local-only .venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-pve-api/volumes docker compose -p rp-pve-api -f tests/fixtures/proxmox_api/docker-compose.yml down --volumes
```
