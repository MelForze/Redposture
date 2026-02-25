# RedPosture

RedPosture is a Python security CLI for:

- exporter discovery / trigger / collect workflows (`exporters`)
- service exposure auditing (`redis`, `postgres`, `etcd`, `kafka`, `zookeeper`, `grafana`, `gitlab`, `registry`)
- listener-based callback capture for exporter SSRF/credential leaks (`exporters trigger --with-listen`)

Use only on systems you own or are explicitly authorized to assess.

## Modules by System Type

Use this as a quick map before reading examples below:

- Exporter workflows (discovery / trigger / collect):
  - `exporters scan`
  - `exporters trigger`
  - `exporters collect`
  - `--selfcert` (TLS listener helper for trigger/listen flows)
- Databases / KV stores:
  - `redis`
  - `postgres`
  - `etcd`
- Messaging / coordination:
  - `kafka`
  - `zookeeper`
- Observability platform:
  - `grafana`
- Dev platform / SCM:
  - `gitlab`
- Container registries / artifact platforms:
  - `registry --docker` (Docker Registry v2 / OCI)
  - `registry --harbor`
  - `registry --gitlab`
  - `registry --nexus`

## Install

`pipx` (recommended):

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
```

Local editable install:

```bash
python -m pip install -e .
```

Python support: `3.10+` (tested targets in project tooling: `3.10-3.13`).

## Quick Help

```bash
redposture --help
redposture exporters -h
redposture gitlab -h
redposture registry -h
```

Common quality-of-life flags (most modules):

- `-d, --debug` verbose diagnostics
- `-log <file>` tee console output to file
- `-o <file>` save output
- `-f txt|json` output format (`txt` default)

## Docker Lab (Local Testing)

Start lab:

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

Optional (real GitLab CE, x86_64-oriented; may fail under QEMU on arm64 hosts):

```bash
docker compose -f docker-compose.lab.yml --profile gitlab-real up -d gitlab gitlab-seed
```

Stop lab:

```bash
docker compose -f docker-compose.lab.yml down -v
```

Lab includes seeded/testable services for:

- exporters (real + synthetic): `9100`, `9115`, `9116`, `9121`, `9127`, `9187`, `9216`, `9221`, `9256`, `9308`, `9342`, `9349`, `9427`
- Grafana: `3000`
- GitLab web/API mock (default, clone-capable for module testing): `18080`
- GitLab CE (real, optional `gitlab-real` profile): `18081` (root: `root` / `redpostureRoot!2026`, PAT: `glpat-redposture-lab-root-2026`)
- Kafka: `9092` (open), `29092` (SASL/PLAIN: `metrics:metricspass`)
- ZooKeeper: `2181`
- etcd: `2379` (open), `22379` (auth-enabled)
- registries:
  - `15000` Docker Registry v2 (open)
  - `15001` Docker Registry v2 (basic auth proxy)
  - `15002` Harbor-like API mock
  - `15003` GitLab Container Registry-like mock
  - `15004` Nexus Repository (real, seeded REST API)

## Core Modules (Examples)

### Exporters: Scan / Trigger / Collect

Scan known exporter ports:

```bash
redposture exporters scan -t 127.0.0.1
```

Collect debug/runtime endpoints (with automatic validation):

```bash
redposture exporters collect -t 127.0.0.1
redposture exporters collect -t 127.0.0.1 --deep
redposture exporters collect -t 127.0.0.1 --save-responses-dir ./collect_raw
```

Trigger callbacks (listener mode):

```bash
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen
```

Trigger with custom listener ports (useful when default ports are busy):

```bash
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen --postgres-port 15432 --redis-port 16379 --proxmox-port 18006 --blackbox-port 19115
```

Generate local self-signed cert/key for TLS listener modes:

```bash
redposture --selfcert
```

### Redis

```bash
redposture redis -t 127.0.0.1
redposture redis -t 127.0.0.1 --defcreds
redposture redis -t 127.0.0.1 --show-keys
redposture redis -t 127.0.0.1 -key user:1001
redposture redis -t 127.0.0.1 --dump
```

### Postgres

```bash
redposture postgres -t 127.0.0.1
redposture postgres -t 127.0.0.1 --defcreds
redposture postgres -t 127.0.0.1 -u postgres -p postgres --show-databases
redposture postgres -t 127.0.0.1 -u postgres -p postgres --show-tables
redposture postgres -t 127.0.0.1 -u postgres -p postgres --table redposture.service_tokens --show-columns
redposture postgres -t 127.0.0.1 -u postgres -p postgres --dump
redposture postgres -t 127.0.0.1 -u postgres -p postgres -x "id"
```

### etcd

```bash
redposture etcd -t 127.0.0.1
redposture etcd -t 127.0.0.1 --show-keys
redposture etcd -t 127.0.0.1 -key /redposture/env
redposture etcd -t 127.0.0.1 --dump
redposture etcd -t 127.0.0.1 --port 22379
```

### Kafka

```bash
redposture kafka -t 127.0.0.1
redposture kafka -t 127.0.0.1 --show-topics
redposture kafka -t 127.0.0.1 --topic audit.logs
redposture kafka -t 127.0.0.1 --topic audit.logs --dump
redposture kafka -t 127.0.0.1 --dump --max-messages 1000
redposture kafka -t 127.0.0.1 --port 29092 -u metrics -p metricspass --dump
```

### ZooKeeper

```bash
redposture zookeeper -t 127.0.0.1
redposture zookeeper -t 127.0.0.1 --show-znodes
redposture zookeeper -t 127.0.0.1 -znode /config --dump
redposture zookeeper -t 127.0.0.1 --dump
```

### Grafana

```bash
redposture grafana -t 127.0.0.1
redposture grafana -t 127.0.0.1 --defcreds
redposture grafana -t 127.0.0.1 --defcreds --show-datasources
redposture grafana -t 127.0.0.1 --defcreds --ssrf-target host.docker.internal --ssrf-port 9115 --ssrf-path /debug/vars
```

### GitLab

```bash
redposture gitlab -t gitlab.example.com --https
redposture gitlab -t gitlab.example.com --https --token <PAT_OR_GAT>
redposture gitlab -t gitlab.example.com --https --project group/app
redposture gitlab -t gitlab.example.com --https --project group/app --clone
redposture gitlab -t gitlab.example.com --https --clone --clone-dir ./gitlab_clones
```

Lab (built into main compose via `gitlab-web-mock`):

```bash
docker compose -f docker-compose.lab.yml up -d gitlab-web-mock
redposture gitlab -t 127.0.0.1 --port 18080
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-analyst-2026
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-root-2026 --project redposture-lab/public-api --clone
```

Real GitLab CE (optional, x86_64 recommended):

```bash
docker compose -f docker-compose.lab.yml --profile gitlab-real up -d gitlab gitlab-seed
redposture gitlab -t 127.0.0.1 --port 18081
```

Note: on Apple Silicon / arm64 hosts the official `gitlab/gitlab-ce` omnibus image may crash under QEMU emulation during startup. For reliable CE runs, use an x86_64 Docker host/VM.

### Registry (Docker / Harbor / GitLab / Nexus)

Base detect (minimal output):

```bash
redposture registry -t 127.0.0.1 --port 15000
```

Docker Registry (OCI/v2):

```bash
redposture registry -t 127.0.0.1 --port 15000 --docker --images
redposture registry -t 127.0.0.1 --port 15000 --docker --repository redposture/demo-api --show-tags
redposture registry -t 127.0.0.1 --port 15000 --docker --repository redposture/demo-api --tag latest --metadata
redposture registry -t 127.0.0.1 --port 15000 --docker --inspect --image redposture/demo-api:latest
```

Harbor:

```bash
redposture registry -t 127.0.0.1 --port 15002 --harbor
redposture registry -t 127.0.0.1 --port 15002 --harbor --repository core/control-plane --show-tags
redposture registry -t 127.0.0.1 --port 15002 --harbor --repository core/control-plane --tag latest --metadata
```

GitLab Container Registry:

```bash
redposture registry -t 127.0.0.1 --port 15003 --token glrt-lab-token --gitlab
redposture registry -t 127.0.0.1 --port 15003 --token glrt-lab-token --gitlab --repository gitlab/project-api --show-tags
redposture registry -t 127.0.0.1 --port 15003 --token glrt-lab-token --gitlab --repository gitlab/project-api --tag latest --metadata
```

Nexus Repository:

```bash
redposture registry -t 127.0.0.1 --port 15004 --nexus
redposture registry -t 127.0.0.1 --port 15004 --nexus --assets
# Nexus Docker/OCI tag/metadata examples require a separate Docker connector
# (not exposed in the default lab on 15004, which is the Nexus UI/REST port).
```

## Development (Optional)

Run local checks:

```bash
tox
```

Or by environment:

```bash
tox -e py310
tox -e py311
tox -e py312
tox -e py313
tox -e lint
```

## Notes

- `txt` output is optimized for terminal readability; use `-f json` for piping/parsing.
- `exporters collect` runs validation automatically after collection.
- `registry --metadata` shows `ENV / LABELS / CMD`; `--inspect` is broader (history, labels, env, etc.).
- Use `-h` on each module for the full flag set and dependencies between flags.
