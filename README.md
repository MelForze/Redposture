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
  <a href="https://github.com/MelForze/Redposture/releases">
    <img src="https://img.shields.io/github/v/tag/MelForze/Redposture?style=flat-square&label=version" alt="Latest version">
  </a>
  <img src="https://img.shields.io/badge/modules-21-2b2f36?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/lint-ruff-2b2f36?style=flat-square" alt="Ruff">
  <img src="https://img.shields.io/badge/types-mypy-2b2f36?style=flat-square" alt="mypy">
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
- Service audit modules: `registry`, `grafana`, `proxmox`, `gitlab`, `consul`, `kubeapi`, `postgres`, `mongodb`, `docker`, `oracle`, `clickhouse`, `redis`, `etcd`, `qdrant`, `elastic`, `grpc`, `kafka`, `zookeeper`, `keeper`, and `minio`.
- Multi-target and multi-port scans from comma-separated values, per-target `host:port` entries, CIDR/ranges where supported, or target files.
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

### Developing

```bash
git clone https://github.com/MelForze/Redposture.git
cd Redposture
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pre-commit install   # one-time: wires ruff lint + format into `git commit`
pytest               # unit tests block external network; loopback remains available
scripts/check_ci_matrix.sh --worktree  # same locked Python 3.10-3.13 gate as GitHub CI
```

CI dependency versions are committed under `requirements/`. Regenerate the complete locks with
`scripts/update_ci_locks.sh` when intentionally upgrading the toolchain.

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
clickhouse  ClickHouse auth, enumeration, exhaustive secret discovery, dumps, explicit command checks
redis       Redis auth/default credentials, keys, dumps
etcd        etcd API auth and key/value visibility
qdrant      Qdrant collections, collection info, snapshot SSRF check helpers
elastic     Elasticsearch exposure, auth, cluster/user endpoints, discovery
grpc        gRPC transport/auth/reflection/health/invoke/OpenAPI
kafka       Kafka auth, topic visibility, bounded message dumps
zookeeper   Apache ZooKeeper identity, TLS, auth, health, and znode visibility
keeper      ClickHouse Keeper identity, TLS, auth, quorum, and znode visibility
minio       MinIO detection, anonymous access, credential/default-credential/admin checks, write-probe, streamed enumeration, secret discovery, object dump/download
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
-ot, --out-target    Exclude target files, IPs, CIDRs, DNS names, or URL hosts (repeatable)
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
redposture redis -t 127.0.0.1,10.0.0.5 --port 6379,16379
redposture elastic -t http://127.0.0.1:9200/
redposture grpc -t targets.txt --port 50051
redposture redis -t 10.0.0.0/24 -ot 10.0.0.1,10.0.0.128/25,skip.internal
redposture exporters scan -t targets.txt --out-target exclusions.txt
```

Targets and target files accept `IPv4:port`, `DNS:port`, and `[IPv6]:port` entries. A target-specific port
replaces module defaults for that target. If `--port` is supplied explicitly, its port or port set is added
to every bare `host:port` target; it does not replace the port stored in the target file.
`-ot/--out-target` removes matching hosts before ports are expanded and before any scan request is sent.
It accepts the same comma-separated and file inputs, ignores URL schemes, paths, and ports, subtracts IP/CIDR
ranges lazily, and compares DNS names case-insensitively.

Proxy examples:

```bash
redposture redis -t internal-redis --proxy socks5h://127.0.0.1:9050
redposture elastic -t http://elastic.internal:9200 --proxy http://127.0.0.1:8080
```

## Default credentials checked by `--defcreds`

| Module | Credential pairs checked |
| --- | --- |
| Grafana | `admin:admin`, `admin:changeme`, `admin:grafana`, `admin:password`, `grafana:grafana`, `grafana:password`, `root:password`, `root:root`, `user:password`, `user:user` |
| MinIO | `minioadmin:minioadmin`, `minio:minio123`, `minioadmin:minio123`, `minioadmin:password`, `admin:admin`, `admin:minioadmin`, `admin:password`, `root:minioadmin`, `root:password`, `minio:minio`, `access:secret` |
| Proxmox | `admin@pam:admin`, `admin@pve:admin`, `admin@pve:password`, `root@pam:admin`, `root@pam:changeme`, `root@pam:password`, `root@pam:proxmox`, `root@pam:Proxmox123`, `root@pam:root`, `root@pam:toor` |
| Postgres | `admin:admin`, `admin:password`, `admin:postgres`, `dev:dev`, `pgbouncer:pgbouncer`, `pgbouncer_exporter:pgbouncer_exporter`, `pgsql:pgsql`, `postgres:admin`, `postgres:changeme`, `postgres:password`, `postgres:postgres`, `service:service`, `test:test`, `user:password`, `user:user` |
| MongoDB | `admin:admin`, `admin:changeme`, `admin:mongo`, `admin:mongodb`, `admin:password`, `dev:dev`, `mongo:mongo`, `mongo:password`, `mongodb:mongodb`, `mongodb:password`, `root:admin`, `root:mongo`, `root:mongodb`, `root:password`, `root:root`, `test:test`, `user:password`, `user:user` |
| Oracle | `admin:admin`, `admin:changeme`, `admin:oracle`, `admin:password`, `dbsnmp:dbsnmp`, `dev:dev`, `hr:hr`, `outln:outln`, `pdbadmin:oracle`, `pdbadmin:pdbadmin`, `scott:scott`, `scott:tiger`, `sys:change_on_install`, `sys:oracle`, `sys:sys`, `system:manager`, `system:oracle`, `system:system`, `test:test`, `user:user` |
| ClickHouse | `admin:admin`, `admin:changeme`, `admin:password`, `clickhouse:clickhouse`, `clickhouse:password`, `default:<empty>`, `default:changeme`, `default:clickhouse`, `default:default`, `default:password`, `root:password`, `root:root`, `user:password`, `user:user` |
| Redis | `admin:admin`, `admin:changeme`, `admin:password`, `default:changeme`, `default:default`, `default:password`, `default:redis`, `dev:dev`, `redis:changeme`, `redis:password`, `redis:redis`, `root:password`, `root:root`, `service:service`, `test:test`, `user:password`, `user:user` |
| etcd | `admin:admin`, `admin:changeme`, `admin:etcd`, `admin:password`, `etcd:etcd`, `etcd:password`, `root:admin`, `root:etcd`, `root:password`, `root:root`, `root:rootpass`, `service:service`, `user:password`, `user:user` |
| Elastic/OpenSearch | `admin:admin`, `admin:changeme`, `admin:password`, `elastic:changeme`, `elastic:elastic`, `elastic:password`, `kibana:changeme`, `kibana:kibana`, `logstash:logstash`, `logstash_system:changeme`, `opensearch:opensearch`, `opensearch:password` |
| gRPC | Basic: `admin:admin`, `admin:changeme`, `admin:password`, `dev:dev`, `grpc:admin`, `grpc:grpc`, `grpc:password`, `guest:guest`, `root:admin`, `root:password`, `root:root`, `service:password`, `service:service`, `test:test`, `user:password`, `user:user`.<br>Bearer tokens: `admin`, `changeme`, `default-token`, `grpc`, `secret`, `token`. |
| Kafka | `admin:admin`, `admin:admin-secret`, `admin:changeme`, `admin:kafka`, `admin:password`, `broker:broker`, `broker:brokerpass`, `client:client`, `kafka:admin`, `kafka:changeme`, `kafka:kafka`, `kafka:password`, `kafka:zookeeper`, `service:password`, `service:service`, `user:password`, `user:user` |
| ZooKeeper | `admin:admin`, `admin:changeme`, `admin:kafka`, `admin:password`, `admin:zookeeper`, `broker:broker`, `broker:brokerpass`, `client:client`, `dev:dev`, `guest:guest`, `hadoop:hadoop`, `kafka:changeme`, `kafka:kafka`, `kafka:password`, `kafka:zookeeper`, `root:admin`, `root:password`, `root:root`, `root:rootpass`, `root:zookeeper`, `service:password`, `service:service`, `solr:solr`, `super:super`, `test:test`, `user:password`, `user:user`, `user1:12345`, `zk:password`, `zk:zk`, `zk:zookeeper`, `zookeeper:admin`, `zookeeper:password`, `zookeeper:zookeeper` |
| Keeper | `admin:admin`, `admin:changeme`, `admin:clickhouse`, `admin:keeper`, `admin:password`, `clickhouse:changeme`, `clickhouse:clickhouse`, `clickhouse:keeper`, `clickhouse:password`, `default:<empty>`, `default:changeme`, `default:clickhouse`, `default:default`, `default:password`, `keeper:changeme`, `keeper:clickhouse`, `keeper:keeper`, `keeper:password`, `root:clickhouse`, `root:keeper`, `root:password`, `root:root`, `service:password`, `service:service`, `user:password`, `user:user` |

## Module Examples

Every example is `redposture <module> …`; run `redposture <module> -h` for the full flag set. `--defcreds` runs
ordered online credential probes (see the table above) — exhaustive by default (`--stop-on-success` stops at the
first hit where supported) and able to trigger lockout/alerts, so use it only on authorized targets.

**Exporters** — Prometheus/metrics scan, collect, trigger:

```bash
redposture exporters scan -t 127.0.0.1
redposture exporters collect -t 127.0.0.1 --deep --save-responses-dir /tmp/rp_collect_raw
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --with-listen --listen-seconds 8
```

**Registry** — Docker registry metadata:

```bash
redposture registry -t 127.0.0.1 --port 5000 --docker --images
redposture registry -t 127.0.0.1 --port 5000 --docker --repository redposture/demo-api --show-tags
```

**Grafana** — default creds + datasources:

```bash
redposture grafana -t 127.0.0.1 --defcreds --show-datasources
```

**GitLab** — public + token-backed:

```bash
redposture gitlab -t 127.0.0.1 --port 18080
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-example --project group/project
```

**Consul** — KV + catalog (bare targets scan HTTP `8500/18500/28500`, HTTPS `8501/18501/28501`):

```bash
redposture consul -t 127.0.0.1 --keys --services --agents --checks --nodes --dump 25
redposture consul -t https://consul.internal --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --services
```

**KubeAPI** — Kubernetes API visibility (a token that gets 403 is verified with a non-persistent `SelfSubjectReview`):

```bash
redposture kubeapi -t 127.0.0.1 --port 6443 --insecure --namespaces --pods
redposture kubeapi -t 127.0.0.1 --port 6443 --insecure --token "$KUBE_TOKEN" --secrets
```

**PostgreSQL** — enumeration + privilege-risk check:

```bash
redposture postgres -t 127.0.0.1 --defcreds --stop-on-success
redposture postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables 20 --privesc-check
redposture postgres -t db.internal --sslmode verify-full --ssl-ca ca.pem --ssl-cert client.pem --ssl-key client.key
```

**MongoDB** — enumeration, query, dump (`--proxy` fails closed; use a tunnel):

```bash
redposture mongodb -t 127.0.0.1 --defcreds
redposture mongodb -t 127.0.0.1 --database redposture --collection demo_accounts --query '{"role":"admin"}' --dump 10
```

**Docker** — Engine API inventory:

```bash
redposture docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
```

**Oracle** — listener + post-auth enumeration:

```bash
redposture oracle -t 127.0.0.1 --port 1521 --listener-dump
redposture oracle -t 127.0.0.1 --service FREEPDB1 -u redposture -p 'OracleLab!2026' --show-pdbs --show-users --privesc-check
```

**ClickHouse** — native-first (HTTP fallback), enumeration, resumable secret discovery:

```bash
redposture clickhouse -t 127.0.0.1 --show-databases --show-tables 20
redposture clickhouse -t 127.0.0.1 -u default -p default --table secure.secrets_inventory --dump 5
redposture clickhouse -t 127.0.0.1 --discover --checkpoint clickhouse-discover.json   # + --resume to continue
```

**Redis / etcd / Qdrant / Kafka** — keys, collections, topics, dumps (add `--tls …` for TLS):

```bash
redposture redis -t 127.0.0.1 --show-keys 20 --dump 10
redposture etcd -t 127.0.0.1 --show-keys 20 --dump 10
redposture qdrant -t 127.0.0.1 --collections --dump 10
redposture kafka -t 127.0.0.1 --show-topics --dump 10
```

**Elasticsearch / gRPC**:

```bash
redposture elastic -t http://127.0.0.1:9200/ --endpoints --cluster --discover
redposture grpc -t 127.0.0.1 --port 50051 --analyze
redposture grpc -t 127.0.0.1 --port 50051 --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
redposture grpc -t 127.0.0.1 --port 50051 --openapi
```

### MinIO

```bash
redposture minio -t 127.0.0.1                                            # detect (transport auto)
redposture minio -t 127.0.0.1 --defcreds                                # try default credentials
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --show-buckets --show-objects
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --show-buckets --probe-write
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --bucket data --discover --max-objects 200
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --object bulk/creds.env --dump
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --object bulk/creds.env --download /tmp/rp-dl
```

- **Transport is automatic**: scheme (HTTP/HTTPS) is probed per target and TLS certificates are always accepted
  (no `--https`/`--insecure`/`--ca-file`). Credentials use the S3 model (`-u` access key, `-p` secret key,
  `--session-token`); a valid signature that gets `AccessDenied` is `valid_but_restricted`, never invalid. The
  detection line shows the server version (`(version:…)`) when an authenticated Admin API read exposes it.
- **Enumeration** (`--show-buckets`/`--show-objects`/`--bucket`/`--prefix`) is unbounded but memory-safe — objects
  are streamed (no `--limit`; JSON is emitted as NDJSON). `--discover` scans interesting-by-name objects for secrets
  and prints each finding **in real time** as it is found (large objects are read in chunks, not skipped), then a
  clickhouse-style `[*] Discover Secrets` summary. Secret values are shown in full; bounded by
  `--max-objects` / `--max-object-size` / `--discover-time`.
- **`--probe-write`** is the only mutating action: a canary object is PUT then DELETEd per bucket, reporting
  `(write:True/False)`. Otherwise every operation is GET/HEAD only.
- **`--object <bucket>/<key>`** with `--dump` prints content or `--download <dir>` saves it (read-only, capped by
  `--max-object-size`).

### ZooKeeper and ClickHouse Keeper

Strict routing: `zookeeper` accepts Apache ZooKeeper on `2181/12181/22181`, `keeper` accepts ClickHouse Keeper on
`9181/19181/29181`; wrong-vendor endpoints are diagnostics only. TLS/mTLS and znode flags are identical.
`--probe-write` (the only write action) creates and deletes an ephemeral znode in a separate session. `--defcreds`
needs an ACL-protected verifier (`--znode` or a root child) to confirm a pair — without one, defaults are skipped.

```bash
redposture zookeeper -t 127.0.0.1 --show-znodes 20 --dump 10
redposture zookeeper -t 127.0.0.1 --port 22185 --defcreds --znode /redposture-auth --probe-write
redposture keeper -t 127.0.0.1 --port 9181,19181,29181 --show-znodes 20 --dump 20 -d -f json
redposture keeper -t 127.0.0.1 --port 19281 --insecure --show-znodes 10 --dump 10
```

Focused Keeper lab (cluster + TLS + 4LW-disabled + Apache control):

```bash
docker compose -f lab/services/keeper/docker-compose.yml up -d --wait
docker compose -f lab/services/keeper/docker-compose.yml down -v --remove-orphans
```

## License

MIT License. See `LICENSE`.
