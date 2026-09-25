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
  <img src="https://img.shields.io/badge/modules-22-2b2f36?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/Python-3.10%2B-2b2f36?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/install-pipx-2b2f36?style=flat-square" alt="Install with pipx">
</p>


# RedPosture

RedPosture is a Python CLI for authorized security auditing of exposed service APIs, data stores, observability endpoints, and selected post-auth risk paths. It helps verify what is reachable, whether authentication is required, what data or metadata is visible, and which high-risk capabilities are exposed.

Use it only on systems you own or are explicitly authorized to assess.

## Features

- Exporter workflows: discover, collect, and trigger Prometheus-style exporters and debug endpoints.
- Service audit modules: `registry`, `grafana`, `proxmox`, `gitlab`, `consul`, `kubeapi`, `postgres`, `mongodb`, `docker`, `oracle`, `clickhouse`, `redis`, `etcd`, `qdrant`, `elastic`, `grpc`, `kafka`, `zookeeper`, `keeper`, `minio`, `airflow`, and `rabbitmq`.
- Multi-target and multi-port scans from comma-separated values, per-target `host:port` entries, CIDR, inclusive IPv4 ranges (`10.0.0.1-10.0.0.10`), or target files. IPv4 ranges also work in `-ot` exclusions; select their ports with the module's port option. Both endpoints must be full IPv4 addresses in ascending order (equal endpoints select one host).
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
airflow     Airflow REST API detection, auth/role checks, and bounded secret discovery in DAG task logs
rabbitmq    RabbitMQ Management auth, tags, permissions, and queue/exchange/vhost topology
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
--enum-cve          Match the detected version against the bundled CVE catalog
-o, --output        Write output to file
-f, --format        txt or json
-log, --log         Tee console output to a log file
-d, --debug         Verbose diagnostics
--no-color          Disable ANSI colors
```

For audit modules, the default worker count is selected after target and port
expansion: 64 workers below 1000 `host:port` tasks and 128 workers from 1000
tasks onward. An explicit `-w/--workers` value always wins. Exporter workflows
keep their own concurrency profiles.

Commands share one lazy pool for nested work. Its limit is 32 below 1000 tasks
and 64 from 1000 tasks onward, capped by the effective main worker count. The
per-target discovery limits are MinIO 8, Elasticsearch/OpenSearch 8, Proxmox 8,
and ClickHouse 4. ClickHouse uses a fixed server-side `max_threads=1` for each
discovery query. Debug output reports the effective
main and nested limits.

Airflow, MinIO, Elasticsearch/OpenSearch, ClickHouse, and Proxmox share
`--discover`, `--discover-time`, and `--discover-max-bytes`. The default content
budget is 50 MiB per target. Airflow and MinIO have no default time limit or
item-count limit; Elasticsearch/OpenSearch retains its 300-second time limit.
ClickHouse and Proxmox have no default time or item-count limit. Set
`--discover-time` to bound the elapsed time explicitly.

| Module | Default `--discover-time` | Default `--discover-max-bytes` | Counted content |
| --- | ---: | ---: | --- |
| Airflow | Unlimited | 50 MiB | DAG source, Variable/Connection data, and task-log text |
| MinIO | Unlimited | 50 MiB | Object content |
| Elasticsearch/OpenSearch | 300 s | 50 MiB | Document source content |
| ClickHouse | Unlimited | 50 MiB | Returned row values |
| Proxmox | Unlimited | 50 MiB | Successful GET response bodies |

When a limit interrupts discovery, the result is marked partial. ClickHouse
`--resume` continues a partially read chunk from its checkpoint. Time limits
are cooperative: requests already in flight may finish after the deadline. The
50 MiB limit is a total per target, not a per-chunk quota; increase
`--discover-max-bytes` when a larger target must be fully inspected.

TXT discovery output is live. As soon as a target is confirmed, its service
line is printed; a successful authentication line is printed before the longer
content scan starts. Each new finding is then written immediately to both the
terminal and `-o` file in one common form:

```text
AIRFLOW  10.0.0.1  8080  [!] Pass Value="secret" Place="dag/run/task/try:1/map:-1$"
```

The `[!]` finding marker is red and the finding payload is orange. Severity
remains available in structured JSON but is omitted from compact TXT lines. The
`Discover Secrets`, `Discover Complete`, and
`CVE's Enumeration` labels are white; discovery status is green for complete,
orange for partial, and red for failure, while a non-zero findings count is red
and zero is green. JSON output stays one complete structured record per target
and is emitted after that target finishes.

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
| Airflow | `airflow:airflow`, `admin:admin`, `admin:airflow`, `airflow:admin`, `airflow:password`, `airflow:changeme`, `airflow:airflow123`, `admin:password`, `admin:changeme`, `admin:airflow123`, `root:root`, `root:password`, `user:user`, `user:password`, `test:test`, `dev:dev`, `service:service`, `guest:guest` |
| RabbitMQ | `admin:admin`, `admin:changeme`, `admin:password`, `admin:rabbitmq`, `guest:guest`, `guest:password`, `rabbitmq:admin`, `rabbitmq:password`, `rabbitmq:rabbitmq`, `root:password`, `root:root`, `service:password`, `service:service`, `test:test`, `user:password`, `user:user` |

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

**Airflow** — search DAG source, Variables, Connections, and task-instance logs for secrets using anonymous access or verified credentials:

```bash
redposture airflow -t https://airflow.internal:8080 --discover -u auditor -p 'password' -o airflow_results.txt
redposture airflow -t https://airflow.internal:8080 --show-keys 100 -u auditor -p 'password'
redposture airflow -t https://airflow.internal:8080 --show-connections 100 -u auditor -p 'password'
```

When a protected browser flow redirects to a recognized OIDC/SAML identity
provider, Airflow, Grafana, and an independently confirmed GitLab instance use
`(auth required:sso)` in TXT. A detected provider is added as
`(provider:keycloak)`, for example. JSON keeps `auth_required: true` for schema
compatibility and adds `auth_method: "sso"`, `sso_provider`, `sso_protocol`, and
non-sensitive evidence labels. A plain Bearer challenge, mTLS request, generic
login form, or the word `oauth` alone is not classified as SSO. Airflow skips
`--defcreds` when its API is protected only by a browser SSO flow.

The reproducible Airflow-to-Keycloak QA fixture uses the official Keycloak
container and a small Airflow 2.11.1-compatible gateway:

```bash
docker compose -f tests/fixtures/airflow_sso_lab/docker-compose.yml up -d --wait
redposture airflow -t http://127.0.0.1:18081 --defcreds
docker compose -f tests/fixtures/airflow_sso_lab/docker-compose.yml down -v
```

The service line includes `(Dags allowed anonymously:True/False)` from an unauthenticated
`/dags` request. A successful credential line reports exact read access as
`(Dags:N) (Keys:N) (Connections:N)`. A 401/403 is shown as `Access Denied`;
transport failures, unsupported endpoints, and malformed HTTP 200 responses are
shown as `Unknown`. Counts are accepted only from a valid Airflow collection
containing the expected list and a non-negative integer `total_entries`; the
module does not infer Viewer, Operator, or Admin roles from endpoint access.
Available access is red, denied access is green, and unknown access is orange.
`--show-keys [count]` lists Airflow Variable names without printing their
values. `--show-connections [count]` prints the complete Connection objects
returned by Airflow, including any credentials present in them, and therefore
should be written to an appropriately protected output file. `--discover` uses read-only Airflow REST API v1/v2
endpoints and inspects DAG source code, Variable values, Connection data, and
all recorded task attempts. Collections are paged without a default count
limit. Inspected content shares the 50 MiB per-target budget; an optional
`--discover-time` sets a time limit. TXT and JSON include each finding's source
kind and exact location. An incomplete or permission-limited scan reports its
reason.

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

When anonymous KV, catalog, and agent access is available, the detection line includes
`(kv:N) (services:N) (agent:N)`. These counts are omitted when authentication prevents enumeration.

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
redposture docker -t 127.0.0.1 --port 2376 --insecure --tls-cert client-cert.pem --tls-key client-key.pem --system
```

Docker retries the exact HTTP 400 `Client sent an HTTP request to an HTTPS server` over HTTPS. `--insecure`
disables server-certificate verification only; an mTLS listener still requires `--tls-cert` and `--tls-key`.

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

An authentication-protected Elasticsearch/OpenSearch target is reported once on the detection line; a duplicate
`authentication required` detail line is omitted when no credentials were supplied. A version is shown from an
anonymous response body or explicit product-version header; servers that hide it behind authentication show `-`.

### MinIO

```bash
redposture minio -t 127.0.0.1                                            # detect (transport auto)
redposture minio -t 127.0.0.1 --defcreds                                # try default credentials
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --show-buckets --show-objects
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --show-buckets --probe-write
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --bucket data --discover
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --object bulk/creds.env --dump
redposture minio -t 127.0.0.1 -u minioadmin -p minioadmin --object bulk/creds.env --download
```

- **Transport is automatic**: scheme (HTTP/HTTPS) is probed per target and TLS certificates are always accepted
  (no `--https`/`--insecure`/`--ca-file`). Credentials use the S3 model (`-u` access key, `-p` secret key,
  `--session-token`); a valid signature that gets `AccessDenied` is `valid_but_restricted`, never invalid. The
  detection line shows the server version (`(version:…)`) when an authenticated Admin API read exposes it.
  A redirect from the S3 listener to the Console does not replace the S3 origin. When a target points only to
  the Console and credentials were requested, the module also checks HTTP and HTTPS on port 9000 of the same
  host using unsigned discovery requests. Credentials are tested only after confirming the S3 API. If the API
  is on another host or a different port, include its URL in the targets file. MinIO Admin API JSON errors and
  the Console's canonical `S3 API Requests must be made to API port` response are handled during verification.
- **Enumeration** (`--show-buckets`/`--show-objects`/`--bucket`) is unbounded but memory-safe — objects
  are streamed (no `--limit`; JSON is emitted as NDJSON). `--discover` scans interesting-by-name objects for secrets
  and prints findings after each scanned object (large objects are read in chunks, not skipped), then a
  clickhouse-style `[*] Discover Secrets` summary. Secret values are shown in full; the
  object count is not capped. The 50 MiB per-target content budget is enforced across
  all objects; use `--discover-max-bytes` to change it. Findings are emitted after
  each scanned object, while ClickHouse and Proxmox emit findings after each completed
  chunk or endpoint. A partial result identifies a budget or read limit reached.
- **`--probe-write`** is the only mutating action: a canary object is PUT then DELETEd per bucket, reporting
  `(write:True/False)`. Otherwise every operation is GET/HEAD only.
- **`--object <bucket>/<key>`** with `--dump` prints content or `--download` saves it below `./<bucket>/`
  (read-only, capped at 100 MiB per object).

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

## HTTP redirects

HTTP audit modules and exporter discovery/collection follow redirects across
schemes, hosts and ports, retaining supplied credentials. This is intentional
for operator-controlled audits. Redirect chains are bounded; TLS verification
continues to use the configured settings. A scheme in a target URL selects the
first attempt; after discovery, later checks reuse the redirect's final origin.
During safe `GET`/`HEAD` discovery, an HTTP 400 response whose body is exactly
`Client sent an HTTP request to an HTTPS server` also selects HTTPS. Discovery
may accept an untrusted server certificate where the module supports automatic
TLS detection. The resolved origin is retained before credentials or changing
requests are sent; `POST` and other changing requests are never replayed to
select another scheme.

## Audit output

Normal text output is a findings report. Per-target failures before service
identity is confirmed (wrong service, foreign protocol banners, TLS handshake
failures, timeouts, and similar discovery noise) are hidden from stdout and
`-o`; `--debug` shows those diagnostics, while JSON retains the full record for
every target. If no service is confirmed, the command emits one aggregate
summary so an empty result is distinguishable from missing output. Errors that
happen after a service was confirmed remain visible in normal text output.

## Offline CVE enumeration

Every service audit module accepts `--enum-cve`. The option matches a confirmed
product and its exact detected version against the CVE catalog bundled with the
installed Redposture release. It never contacts NVD, a vendor, DNS, or another
external lookup service, and it does not attempt exploitation. The catalog is a
reviewed snapshot rather than a complete or live vulnerability feed.

The catalog includes only High and Critical findings with CVSS `AV:N`,
`PR:N` or `PR:L`, and `UI:N` whose documented impact is remote code/command execution,
authentication bypass or account takeover, arbitrary file read/write, or SSRF.
Pure denial-of-service findings and advisories without a reliable
affected-version range are excluded. A version match is reported as
`potentially affected` because deployment configuration and vendor backports
cannot be proven from a banner alone.

`PR:N` findings are matched from the confirmed product and version alone.
`PR:L` findings are emitted only when the target reports
`auth required:False`, or after explicitly supplied application credentials
such as `-u/--username` and `-p/--password` have been successfully verified
(token and API-key forms count as credentials as well). Merely passing invalid
credentials does not enable `PR:L`; a `--defcreds` sweep by itself does not
enable them either. Structured findings record `PR:N`/`PR:L` in
`privileges_required` and the decision in `access_basis`. Credential checks are
completed before the CVE block. Every confirmed target then receives a
`CVE's Enumeration` header, including no-match and unknown-version cases;
matching findings follow it from newest to oldest (descending year and
sequence).

```text
GRAFANA         10.0.0.1        3000  [*] Grafana Service (auth required:False) (version:8.2.6)
GRAFANA         10.0.0.1        3000  [*] CVE's Enumeration
GRAFANA         10.0.0.1        3000  [!] CVE-2021-43798 potentially affected (HIGH 7.5) Unauthenticated path traversal and arbitrary file read
```

Product/version resolution is available for Airflow, ClickHouse, Consul,
Docker Engine, Elasticsearch, OpenSearch, etcd, GitLab, Grafana, Kubernetes,
MinIO, MongoDB, Oracle Database, PostgreSQL, Proxmox VE, Qdrant, RabbitMQ,
Redis, Valkey, ZooKeeper, ClickHouse Keeper, Harbor, and Nexus Repository.
Kafka `ApiVersions` does not identify an exact broker release, generic gRPC
reflection does not identify the application product, and a generic OCI/Docker
Registry does not identify its implementation; these cases are marked
`unsupported` in JSON/debug output. A confirmed product whose exact version is
not readable is marked `version_unknown`. Normal TXT stays quiet for
`no_matches`, `version_unknown`, and `unsupported` results.

The bundled `2026-09-20` catalog contains 186 reviewed product/CVE records:

| Product | CVEs | Product | CVEs |
|---|---:|---|---:|
| GitLab | 72 | Redis | 23 |
| PostgreSQL | 22 | Airflow | 11 |
| Grafana | 10 | Elasticsearch | 6 |
| MongoDB | 6 | MinIO | 4 |
| Nexus Repository | 5 | Qdrant | 5 |
| RabbitMQ | 4 | ClickHouse | 3 |
| Valkey | 3 | ZooKeeper | 2 |
| Harbor | 2 | Oracle Database | 2 |
| OpenSearch | 1 | Proxmox VE | 1 |
| Consul | 1 | Docker Engine | 1 |
| etcd | 1 | Kubernetes | 1 |
| **Total** | **186** | | |

ClickHouse Keeper currently has no bundled entry that passes every catalog
condition. It still resolves product/version normally and returns `no_matches`;
Redposture does not transfer Apache ZooKeeper or ClickHouse Server findings to
Keeper without an advisory explicitly covering Keeper.

Qdrant's specialized `CVE-2026-25628` `/logger` probe remains available as
additional endpoint evidence. Its version finding follows the same `PR:L`
access rule as the rest of the catalog.

With `-f json`, the target record contains `cve_enumeration` with the catalog
version, resolved products, status, and structured findings including the CVE,
CVSS vector, detected version, affected range, fixed version, impact, and source
references. Without `--enum-cve`, TXT and JSON records keep their existing
shape.

The opt-in vendor-image QA matrix checks both sides of real fixed-version
boundaries for Redis and Grafana:

```bash
./scripts/run_real_cve_matrix.sh
```

## Extended QA profiles

The default `pytest` suite includes deterministic concurrency, transport fault
injection, real local mTLS, output/checkpoint I/O failures, signal handling,
proxy protocol tests, and a bounded 10,000-target soak test. The following
opt-in profiles use local vendor containers or system `proxychains4`:

```bash
# Real MinIO and K3s: HTTP-to-HTTPS, self-signed TLS, credentials and RBAC.
./scripts/run_minio_kubeapi_lab.sh

# Real PostgreSQL, MongoDB, Elasticsearch, RabbitMQ and Kafka authentication.
./scripts/run_auth_service_matrix.sh

# Actual proxychains4 subprocess with proxy DNS and HTTP-to-HTTPS redirect.
pytest -q tests/test_proxy_end_to_end.py
```

For a longer resource-leak run, choose the target count, duration and rounds.
The runner fails on leaked worker threads, file descriptors, or excessive
retained Python memory:

```bash
python scripts/run_soak_qa.py --targets 100000 --workers 128 --duration 7200 --rounds 2
```

Mutation smoke tests exercise selected transport, scheduler, CVE and output
branches locally. Set `REDPOSTURE_MUTATION_STRICT=1` to fail when the optional
`mutmut` dependency is unavailable:

```bash
python scripts/run_mutation_smoke.py
```

The complete Docker release profile is intentionally local-only because it
starts every service fixture, including the extended matrix. It runs the
deterministic suite, CLI fuzzing, expanded mutations, real authentication,
MinIO/Kubernetes transport, CVE boundary, proxy, and full service matrices:

```bash
./scripts/run_full_local_qa.sh
# Optional explicit artifact directory:
./scripts/run_full_local_qa.sh /tmp/redposture-full-qa
```

Weekly and manually dispatched GitHub workflows cover the minimum declared
dependency versions, the newest versions allowed by `pyproject.toml`, nightly
CLI parameter fuzzing, expanded mutation checks, and a free-threaded Python
3.13t concurrency smoke. The same dependency profiles can be reproduced
locally (they create and remove an isolated temporary virtual environment):

```bash
./scripts/run_dependency_compat.sh min
./scripts/run_dependency_compat.sh max
```

The regular suite also replays stable Kafka, ZooKeeper, and Oracle binary wire
samples, checks the detect/auth/capabilities/data lifecycle as a state machine,
enforces at-most-once transport behavior for mutating requests, validates the
common JSON contract for every audit module, and exercises the complete HTTP
redirect matrix.

## License

MIT License. See `LICENSE`.
