<p align="center">
  <a href="https://deepwiki.com/MelForze/Redposture">
    <img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki">
  </a>
  <a href="https://github.com/MelForze/Redposture/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/MelForze/Redposture?style=flat-square" alt="License">
  </a>
  <a href="https://github.com/MelForze/Redposture/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/MelForze/Redposture/ci.yml?branch=main&style=flat-square&label=CI" alt="CI">
  </a>
  <a href="https://github.com/MelForze/Redposture/actions/workflows/release-smoke.yml">
    <img src="https://github.com/MelForze/Redposture/actions/workflows/release-smoke.yml/badge.svg?branch=main" alt="Release smoke">
  </a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-2b2f36?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/install-pipx-2b2f36?style=flat-square" alt="Install with pipx">
  <a href="https://github.com/MelForze/Redposture/stargazers">
    <img src="https://img.shields.io/github/stars/MelForze/Redposture?style=flat-square&label=Stars" alt="GitHub Stars">
  </a>
</p>


# RedPosture

RedPosture is a Python CLI for authorized security auditing of exposed service APIs, data stores, observability endpoints, and selected post-auth risk paths. It helps verify what is reachable, whether authentication is required, what data or metadata is visible, and which high-risk capabilities are exposed.

Use it only on systems you own or are explicitly authorized to assess.

## Features

- Exporter workflows: discover, collect, and trigger Prometheus-style exporters and debug endpoints.
- Service audit modules: `registry`, `grafana`, `proxmox`, `gitlab`, `consul`, `kubeapi`, `postgres`, `mongodb`, `docker`, `oracle`, `clickhouse`, `redis`, `etcd`, `qdrant`, `elastic`, `grpc`, `kafka`, `zookeeper`.
- Multi-target and multi-port scans from comma-separated values, CIDR/ranges where supported, or target files.
- Authentication checks with explicit credentials, default-credential checks where implemented, and credential-file workflows in supported modules.
- Optional data enumeration and bounded dumps for data-store modules.
- JSON and text output, file output, debug traces, progress bars, and proxy support.
- Local-only lab and matrix scripts for release testing when a lab checkout is available.

## Install

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
```

Check the CLI:

```bash
redposture --version
redposture --help
```

## CLI Overview

Top-level commands:

```text
exporters   scan/collect/trigger observability endpoints
registry    Docker Registry v2, Harbor, GitLab Registry, Nexus
grafana     Grafana auth exposure and datasource access
proxmox     Proxmox API and credential discovery in API responses
gitlab      GitLab public endpoints, token access, and repository clone checks
consul      Consul API exposure, KV/services/agents/checks, SSRF check helpers
kubeapi     Kubernetes API exposure and visible resources
postgres    PostgreSQL auth, enumeration, dumps, privilege-risk checks
mongodb     MongoDB auth, databases, collections, indexes, documents
docker      Docker Engine TCP API, inventory, explicit container exec checks
oracle      Oracle listener, SID/service auth, PDB/CDB, privilege and explicit actions
clickhouse  ClickHouse auth, enumeration, dumps, explicit command checks
redis       Redis auth/default credentials, keys, dumps
etcd        etcd API auth and key/value visibility
qdrant      Qdrant collections, collection info, snapshot SSRF check helpers
elastic     Elasticsearch exposure, auth, cluster/user endpoints, discovery
grpc        gRPC transport/auth/reflection/health/invoke/OpenAPI
kafka       Kafka auth, topic visibility, bounded message dumps
zookeeper   ZooKeeper auth and znode visibility
```

Use command help for the complete, current flag list:

```bash
redposture <module> -h
redposture exporters scan -h
redposture exporters collect -h
redposture exporters trigger -h
```

Common flags used by most modules:

```text
-t, --targets        Target host/CIDR/URL/list/file, depending on module
--port              Single port or port spec
--ports             Additional port list/range/file
--timeout           Network timeout in seconds
-w, --workers       Worker count
-r, --retries       Retry attempts
--proxy             http(s), socks4(a), or socks5(h) proxy URL
-o, --output        Write output to file
-f, --format        txt or json
-log, --log         Tee console output to a log file
-d, --debug         Verbose diagnostics
--no-color          Disable ANSI colors
```

Target examples:

```bash
redposture redis -t 127.0.0.1
redposture redis -t 127.0.0.1,10.0.0.5 --ports 6379,16379
redposture elastic -t http://127.0.0.1:9200/
redposture grpc -t targets.txt --port 50051
```

Proxy examples:

```bash
redposture redis -t internal-redis --proxy socks5h://127.0.0.1:9050
redposture elastic -t http://elastic.internal:9200 --proxy http://127.0.0.1:8080
```

## Module Examples

Exporter scan and collect:

```bash
redposture exporters scan -t 127.0.0.1
redposture exporters collect -t 127.0.0.1 --deep --save-responses-dir /tmp/rp_collect_raw
```

Trigger workflow with a local listener window:

```bash
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen --listen-seconds 8
```

Registry metadata:

```bash
redposture registry -t 127.0.0.1 --port 5000 --docker --images
redposture registry -t 127.0.0.1 --port 5000 --docker --repository redposture/demo-api --show-tags
```

Grafana default credentials and datasource visibility:

```bash
redposture grafana -t 127.0.0.1 --defcreds
redposture grafana -t 127.0.0.1 --defcreds --show-datasources
```

GitLab public and token-backed checks:

```bash
redposture gitlab -t 127.0.0.1 --port 18080
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-example --project group/project
```

Consul KV and catalog details:

```bash
redposture consul -t 127.0.0.1 --dump 25
redposture consul -t 127.0.0.1 --keys --services --agents --checks --nodes
```

Kubernetes API visibility:

```bash
redposture kubeapi -t 127.0.0.1 --port 6443 --insecure --namespaces --pods
redposture kubeapi -t 127.0.0.1 --port 6443 --insecure --token "$KUBE_TOKEN" --secrets
```

PostgreSQL enumeration and privilege-risk check:

```bash
redposture postgres -t 127.0.0.1 --defcreds
redposture postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables 20
redposture postgres -t 127.0.0.1 -u postgres -p postgres --privesc-check
redposture postgres -t 127.0.0.1 -u postgres -p postgres --table 'public."offlineStocks:city_4949:552400"' --dump 5
```

MongoDB enumeration, query, and dump:

```bash
redposture mongodb -t 127.0.0.1 --defcreds
redposture mongodb -t 127.0.0.1 --show-databases --show-collections 20
redposture mongodb -t 127.0.0.1 --database redposture --collection demo_accounts --query '{"role":"admin"}' --dump 10
```

Docker Engine API inventory:

```bash
redposture docker -t 127.0.0.1
redposture docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
```

Oracle listener and post-auth enumeration:

```bash
redposture oracle -t 127.0.0.1 --port 1521 --listener-dump
redposture oracle -t 127.0.0.1 --service FREEPDB1 -u redposture -p 'OracleLab!2026' --show-pdbs --show-users --privesc-check
```

ClickHouse enumeration and bounded dump:

```bash
redposture clickhouse -t 127.0.0.1 --show-databases --show-tables 20
redposture clickhouse -t 127.0.0.1 -u default -p default --table secure.secrets_inventory --dump 5
```

Redis, etcd, Qdrant, Kafka, ZooKeeper:

```bash
redposture redis -t 127.0.0.1 --show-keys 20 --dump 10
redposture etcd -t 127.0.0.1 --show-keys 20 --dump 10
redposture qdrant -t 127.0.0.1 --collections --dump 10
redposture kafka -t 127.0.0.1 --show-topics --dump 10
redposture zookeeper -t 127.0.0.1 --show-znodes 20 --dump 10
```

Elasticsearch and gRPC:

```bash
redposture elastic -t http://127.0.0.1:9200/ --endpoints --cluster --discover
redposture grpc -t 127.0.0.1 --port 50051
redposture grpc -t 127.0.0.1 --port 50051 --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
```

## License

MIT License. See `LICENSE`.
