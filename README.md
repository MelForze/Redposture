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
- Service audit modules: `registry`, `grafana`, `proxmox`, `gitlab`, `consul`, `kubeapi`, `postgres`, `mongodb`, `docker`, `oracle`, `clickhouse`, `redis`, `etcd`, `qdrant`, `elastic`, `grpc`, `kafka`, and `zookeeper`.
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
clickhouse  ClickHouse auth, enumeration, dumps, explicit command checks
redis       Redis auth/default credentials, keys, dumps
etcd        etcd API auth and key/value visibility
qdrant      Qdrant collections, collection info, snapshot SSRF check helpers
elastic     Elasticsearch exposure, auth, cluster/user endpoints, discovery
grpc        gRPC transport/auth/reflection/health/invoke/OpenAPI
kafka       Kafka auth, topic visibility, bounded message dumps
zookeeper   ZooKeeper/Keeper identity, TLS, auth, health, and znode visibility
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

## Module Examples

Exporter scan and collect:

```bash
redposture exporters scan -t 127.0.0.1
redposture exporters collect -t 127.0.0.1 --deep --save-responses-dir /tmp/rp_collect_raw
redposture exporters scan -t https://metrics.internal:9100 --tls-ca ca.pem
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

`--defcreds` performs ordered online authentication probes in ClickHouse, Elastic/OpenSearch, etcd,
Grafana, gRPC, Kafka, MongoDB, Oracle, Postgres, Proxmox, Redis, and ZooKeeper. Explicit tokens,
username/password pairs, credential-file entries, and module-specific combo/spray inputs keep priority;
the curated module defaults are sorted case-insensitively by login and then password before they are appended
once with stable deduplication. With `--defcreds`, every candidate is checked and rendered even after a
credential succeeds; the first confirmed identity is retained for follow-up data and capability checks.
These requests can trigger account lockout, throttling, or security alerts, so use them only on authorized
targets.

GitLab public and token-backed checks:

```bash
redposture gitlab -t 127.0.0.1 --port 18080
redposture gitlab -t 127.0.0.1 --port 18080 --token glpat-example --project group/project
```

Consul KV and catalog details:

```bash
redposture consul -t 127.0.0.1 --dump 25
redposture consul -t 127.0.0.1 --keys --services --agents --checks --nodes
redposture consul -t https://consul.internal --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --services
```

Bare Consul targets scan both the HTTP `8500` and HTTPS `8501` defaults. HTTPS verification is never
disabled automatically; use `--insecure` explicitly for an authorized self-signed lab.

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
redposture postgres -t db.internal --sslmode verify-full --ssl-ca ca.pem --ssl-cert client.pem --ssl-key client.key
```

MongoDB enumeration, query, and dump:

```bash
redposture mongodb -t 127.0.0.1 --defcreds
redposture mongodb -t 127.0.0.1 --show-databases --show-collections 20
redposture mongodb -t 127.0.0.1 --database redposture --collection demo_accounts --query '{"role":"admin"}' --dump 10
redposture mongodb -t mongo.internal --tls --tls-ca ca.pem --tls-cert-key client.pem --show-databases
```

PyMongo does not expose a reliable HTTP/SOCKS proxy transport, so `mongodb --proxy` fails closed instead of
silently connecting directly; use an explicit network tunnel when proxying MongoDB.

Docker Engine API inventory:

```bash
redposture docker -t 127.0.0.1
redposture docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
```

Oracle listener and post-auth enumeration:

```bash
redposture oracle -t 127.0.0.1 --port 1521 --listener-dump
redposture oracle -t oracle.internal --port 2484 --protocol tcps --service FREEPDB1
redposture oracle -t 127.0.0.1 --service FREEPDB1 -u redposture -p 'OracleLab!2026' --show-pdbs --show-users --privesc-check
```

ClickHouse enumeration and bounded dump:

```bash
redposture clickhouse -t 127.0.0.1 --show-databases --show-tables 20
redposture clickhouse -t 127.0.0.1 -u default -p default --table secure.secrets_inventory --dump 5
redposture clickhouse -t clickhouse.internal --tls --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --show-databases
```

ClickHouse HTTP(S) mode can use the global HTTP proxy. Native ClickHouse mode rejects `--proxy` because the
installed native driver cannot guarantee that traffic is routed through it.

Redis, etcd, Qdrant, Kafka, and ZooKeeper-compatible services:

```bash
redposture redis -t 127.0.0.1 --show-keys 20 --dump 10
redposture redis -t redis.internal --port 6380 --tls --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --dump 10
redposture etcd -t 127.0.0.1 --show-keys 20 --dump 10
redposture qdrant -t 127.0.0.1 --collections --dump 10
redposture kafka -t 127.0.0.1 --show-topics --dump 10
redposture kafka -t 192.0.2.10 --port 9093 --tls --tls-server-name kafka.internal --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --dump 10
redposture zookeeper -t 127.0.0.1 --show-znodes 20 --dump 10
redposture zookeeper -t 127.0.0.1 --defcreds --show-znodes 20
redposture zookeeper -t 127.0.0.1 --port 9281 --insecure --show-znodes 20
```

ZooKeeper `--defcreds` tries a fixed set of 34 digest username/password pairs. Explicit credentials or
credential-file entries are attempted first, defaults are appended once with stable deduplication, and the
defaults are ordered alphabetically by login and then password. The full catalog is checked even after one
or more identities are confirmed. The first confirmed identity is retained for znode analysis. Candidates
are also probed when znodes are anonymously readable, while data collection falls back to the anonymous
session if none can be verified. A run therefore makes up to 34 digest authentication attempts per target
(plus unique explicit/file entries). Use this option only with authorization and account for server-side
lockout, throttling, and alerting policies.

The focused auth-required lab protects `/` and `/redposture-auth` with a digest ACL for
`zk:zookeeper`. In the alphabetical catalog that pair is intentionally the 31st default candidate:

```bash
docker compose -f lab/services/zookeeper-auth/docker-compose.yml up -d --wait
redposture zookeeper -t 127.0.0.1 --port 22185 --defcreds --znode /redposture-auth --dump -f json
docker compose -f lab/services/zookeeper-auth/docker-compose.yml down -v
```

### ZooKeeper and ClickHouse Keeper audit

`zookeeper` is the canonical ZooKeeper-protocol audit and scans bare targets on ports `2181`, `9181`, and
`12181`. It auto-detects plaintext/TLS and classifies the implementation as Apache ZooKeeper, ClickHouse
Keeper, or an unconfirmed ZooKeeper-compatible service. TLS trust and mTLS use `--ca-file`, `--insecure`,
`--tls-cert`, and `--tls-key`; an explicit `host:port` or `--port` still takes priority. Detection is
read-only. Znode traversal only runs with `--show-znodes` or `--dump`, while `--znode` reads that path
directly. A disabled or ambiguous four-letter interface never forces a Keeper label.

Start the focused lab (three-node Keeper cluster, TLS standalone, a Keeper with diagnostic four-letter commands disabled, seeded znodes, and an Apache ZooKeeper classification control):

```bash
docker compose -f lab/services/keeper/docker-compose.yml up -d --wait
docker compose -f lab/services/keeper/docker-compose.yml ps
```

Run high-signal plaintext, TLS, unconfirmed-fallback, and Apache-classification audits:

```bash
redposture zookeeper -t 127.0.0.1 --port 9181,19181,29181 --show-znodes 20 --dump 20 --enum-workers 3 -d -f json
redposture zookeeper -t 127.0.0.1 --port 19281 --insecure --show-znodes 10 --dump 10 -d -f json
redposture zookeeper -t 127.0.0.1 --port 39181 --znode /keeper/api_version --dump -f json
redposture zookeeper -t 127.0.0.1 --port 12181 --show-znodes 5 -d -f json
```

Remove containers, network, certificates, snapshots, and Raft logs:

```bash
docker compose -f lab/services/keeper/docker-compose.yml down -v --remove-orphans
```

Elasticsearch and gRPC:

```bash
redposture elastic -t http://127.0.0.1:9200/ --endpoints --cluster --discover
redposture grpc -t 127.0.0.1 --port 50051
redposture grpc -t 127.0.0.1 --port 50051 --analyze
redposture grpc -t 127.0.0.1 --port 50051 --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
redposture grpc -t 127.0.0.1 --port 50051 --openapi
redposture grpc -t 192.0.2.10 --port 50051 --tls --tls-server-name grpc.internal --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --analyze
```

Elastic scans bare targets on ports `9200`, `19200`, and `29200` by default. Use `host:port` for a
target-specific port or `--port` for an explicit port set; when both are supplied, the explicit set is
added without removing the target-specific port. Transient transport retries are opt-in through
`-r/--retries`. Plans with at least 10,000 expanded endpoints also automatically use up to 200 workers
within the process file-descriptor limit (up to 64 through a proxy) and a one-second timeout. Explicit
`-w/--workers`, `-r/--retries`, and `--timeout` values always win.

Elastic `--discover` uses mappings to target sensitive fields, then performs a bounded `_source` sweep and
audits readable settings, templates, mappings, and ingest pipelines. Findings are deduplicated by secret
value and include confidence plus coverage; partial authorization, disabled/filtered `_source`, closed
indices, timeouts, and scan limits are reported without claiming that no secrets exist. Found secret values
are intentionally written in full to the terminal, `-o`, debug output, and logs. Normal TXT keeps each
finding compact (`secret_type`, JSON-escaped `value`, and its first source location) and highlights the
`value` token in orange on color-capable terminals; confidence, score, detectors, occurrence counts, and
the first location remain available in `--debug`, while JSON preserves every retained location.

The inventory and search path falls back to Elasticsearch 1.x-compatible CAT, mapping, settings, and
search requests only when a server explicitly rejects a modern parameter. If a PIT or scroll context is
lost between pages, discovery restarts that index once from page one and deduplicates replayed documents;
a second loss remains a structured partial error with its original status, type, reason, and root cause.

The default gRPC scan only fingerprints transport, protocol, Reflection availability, and separate
Health/Reflection access policies. Public Health is not treated as endpoint-wide anonymous access.
`--analyze` enables service, method, descriptor, and per-service Health enumeration. `--invoke` and
`--openapi` enable that analysis automatically. Without a transport flag, gRPC tries the scheme-aware
automatic transport sequence; `--tls` and `--plaintext` constrain probes to one mode. Kafka retains its
port/protocol auto-detection unless either transport flag is supplied. Both modules accept
`--tls-server-name` for TLS SNI and certificate verification when the connection target is an IP or alias.

Kafka dumps decode gzip without extra packages. Snappy, LZ4, and Zstandard batches are supported by the
`kafka-codecs` extra (`pip install 'redposture[kafka-codecs]'`); when a codec is unavailable, the dump
keeps other partitions and reports the affected partition explicitly.

`--openapi` merges and deduplicates descriptors discovered across every target. The artifact is still
written when no descriptors are available; `x-redposture.descriptors_obtained` and
`x-redposture.targets_without_descriptors` make complete and partial exports explicit. Generated schemas
follow protobuf JSON rules for maps and 64-bit integers, preserve oneof/optional semantics, and model the
protobuf well-known JSON types. Conflicting same-name descriptor variants are reported in
`x-redposture.descriptor_conflicts`; selection uses the lowest normalized schema SHA-256 and ignores
source-location-only differences. Malformed inputs are listed in `descriptor_errors`, while duplicate
message, enum, or service symbols from different files are listed in `descriptor_symbol_conflicts`.
When no path follows `--openapi`, a single endpoint is written to `openapi_HOST_PORT.json`; a multi-target
scan is written to the merged `openapi_merged.json`. The analysis performed implicitly for export stays
compact on the console; combine `--analyze --openapi [path]` to print the full service inventory as well.
Generated OpenAPI `servers` entries use the detected endpoint addresses and transport (`http` for plaintext,
`https` for TLS), so Swagger clients do not silently substitute `localhost`.

## License

MIT License. See `LICENSE`.
