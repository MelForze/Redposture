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
  <img src="https://img.shields.io/badge/modules-24-2b2f36?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/Python-3.10%2B-2b2f36?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/install-pipx-2b2f36?style=flat-square" alt="Install with pipx">
</p>


# RedPosture

CLI for authorized audits of exposed services: identify the product, verify access,
enumerate data, find secrets, and match versions against an offline CVE catalog.
Python 3.10+; 24 audit modules plus exporter scan/collect/trigger workflows.

## Install

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
redposture --version
```

## Usage

- `-t` accepts a host, URL, CIDR, IPv4 range, comma-separated list, or target file.
  `--port` selects a port or port list/range.
- `-ot, --out-target` accepts the same host exclusions or a file:
  `--out-target exclusions.txt` removes matching hosts before ports are expanded.
- `-u` / `-p` supply credentials; token/API-key flags depend on the module.
  `--defcreds` checks the built-in pairs below. It performs real login attempts.
- `-o results.txt` saves TXT; `-f json` saves structured results. `--debug` includes diagnostics.
  Full options: `redposture <module> -h`.

Normal TXT shows confirmed services, credentials and findings. Unconfirmed services
and pre-detection failures stay in debug/JSON; a scan with no confirmed service prints
one `No MODULE service detected` summary. If some targets could not be checked,
the same line includes their count, uses `[!]`, and the command exits nonzero.
Errors after service confirmation remain visible. SSO is shown as `auth required:sso`.
The HTTP-facing audit modules require a product-specific API or protocol fingerprint:
generic login/SSO pages, status codes and a lone `version` field do not start credential,
discovery or CVE checks. JSON includes `detection_status` (`confirmed`, `probable`,
`not_service`, `transport_failure`) and `detection_signals`; an older module-specific
status, when present, is retained as `detection_detail_status`.

Main workers default to 64 below 1000 expanded `host:port` tasks, otherwise 128;
`-w` overrides this. The shared nested pool uses 32/64, capped by `-w`.
Per-target discovery limits: MinIO/Elastic/Proxmox 8, ClickHouse 4; each ClickHouse
query uses server-side `max_threads=1`. Exporters use separate schedulers.

`--discover` is available in Airflow, MinIO, Elastic/OpenSearch, ClickHouse and Proxmox.
The content budget defaults to 50 MiB per target. Only Elastic/OpenSearch has a default
time limit (300 s); the others have no default time or item-count cap.
Use `--discover-max-bytes` and `--discover-time` to change the budgets.
Findings stream during scanning; interrupted or permission-limited scans are marked partial.
ClickHouse supports `--checkpoint` and `--resume`.

HTTP discovery follows redirects across scheme, host and port, including supplied
credentials, by design for operator-controlled audits. A URL scheme selects the first
attempt; the canonical HTTP 400 `Client sent an HTTP request to an HTTPS server` can
switch GET/HEAD discovery to HTTPS. Later checks reuse the resolved origin; changing
requests are not replayed to select a scheme. Automatic TLS detection can accept untrusted
server certificates. mTLS still needs a client certificate; `--insecure` does not supply one.
For an HTTP service behind a reverse proxy, supply its mounted URL (for example
`https://host/airflow/api/v1/version`); known API suffixes are removed from the
base path and later checks retain `/airflow`. Use the DNS name required by an nginx
virtual host so Host and SNI select the intended site; an IP alone cannot identify it.
A verified credential prints `[+]` and a definitive rejection prints `[-]`.
Inconclusive per-pair checks never appear as rejected pairs in ordinary TXT.
JSON preserves the aggregate verification state without disclosing attempted
secrets.

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

These are weak-password candidates, not claims about factory passwords. [Harbor](https://goharbor.io/docs/edge/install-config/run-installer-script/)
documents `admin:Harbor12345` for its initial setup; [GitLab](https://docs.gitlab.com/install/next_steps/)
and [Nexus](https://help.sonatype.com/en/install-nexus-repository.html) generate per-installation
initial passwords. [Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
has no universal Basic pair. KubeAPI checks these pairs
only when the confirmed API advertises Basic authentication. A public `/v2/` or HTTP 200
alone does not prove a registry credential; inconclusive checks stay in debug/JSON.
The eight-character numeric candidate is a common weak password, not a product default.
If a login endpoint reports HTTP 429, rate limiting or an account lock, the credential sweep
stops for that target; a blocked attempt is not proof that a pair is invalid.

## Module Examples

Each block has three independent workflows. Replace hosts, credentials and token
variables with your own; `targets.txt` contains one target per line.
Most blocks start with detection/CVEs, then default credentials, then inventory/data.
Keeper/ZooKeeper default checks need an ACL-protected verifier znode (`--znode /app`).
Enumeration/discovery reads service data; explicit write/exec/SSRF actions are omitted here.
Exporter trigger is a separate callback workflow.

### Airflow

```bash
redposture airflow -t targets.txt --enum-cve
redposture airflow -t targets.txt --defcreds
redposture airflow -t https://airflow.example:8080 -u auditor -p 'password' --show-keys --show-connections --discover
```

In the first Airflow line, `Dags/Keys/Connections allowed` describe anonymous read access; the credential line reports access after login. With `--enum-cve --show-keys --show-connections --discover`, live TXT follows service → credentials → CVE → keys → connections → discovery.

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

GitLab detects the web/API, Container Registry, or both. `--token` belongs to the
web/API; `--registry-token` belongs to the Container Registry. OCI inventory appears
in the nested `container_registry` JSON object. Web login pairs use an isolated
CSRF session per attempt and stop at SSO, CAPTCHA or rate limiting.
GitLab, Harbor, Nexus and Docker Registry share the Airflow-style TXT layout:
one product line, then verified credentials and requested inventory sections
with item counts. Terminal colors distinguish access and nonzero counts; `-o`
keeps four tab-separated fields without ANSI escapes. JSON fields are unchanged.
Inventory values are orange in the terminal. The product version stays on the
service line; `version:unknown` means the endpoint did not disclose a server
version. In particular, the OCI `registry/2.0` header identifies the API
protocol, not the Docker Registry server release.

### Grafana

```bash
redposture grafana -t targets.txt --enum-cve
redposture grafana -t targets.txt --defcreds
redposture grafana -t https://grafana.example -u auditor -p 'password' --show-datasources --enum-cve
```

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
```

### Keeper

```bash
redposture keeper -t targets.txt
redposture keeper -t targets.txt --defcreds --znode /app
redposture keeper -t keeper.example -u auditor -p 'password' --show-znodes 20 --dump 10
```

Keeper reports `(ddl access:Write/Read/Denied/Absent/Unknown)` for the anonymous
session against the default `/clickhouse/task_queue/ddl` path. The check runs
by default: it reads the queue and attempts to create and delete an empty,
ephemeral child whose name is not a DDL task. `Write` confirms child creation,
not execution of SQL; `Read` confirms reading while writing remains unproved.
`Absent` means this default path was not found, including installations that
configure a different DDL path. This temporary write can trigger Keeper
watches. The separate `--probe-write` flag still tests create/delete under `/`.

With explicit `--create-user NAME --create-userpass PASSWORD`, Keeper can queue a
ClickHouse `CREATE USER` task when anonymous DDL access is `Write`. It stores a
SHA-256 password hash in the task, waits for the DDL worker result, and reports
creation only after a worker confirms it. `--grant-admin` queues a separate
`GRANT ALL ON *.* WITH GRANT OPTION` task only after successful creation. Both
operations change ClickHouse accounts. On one target in a terminal, the command
shows detected clusters and DDL worker host IDs. Choose numbered items or `a`
for all, then confirm user creation with `y`. When `--grant-admin` is present,
each successfully created cluster gets a separate grant confirmation. A blank
answer, `n`, EOF, or Ctrl-C declines the pending write. Selecting only some
workers creates the account only on those workers and is warned about before
confirmation. The password is never printed in the prompt. For example:

```bash
redposture keeper -t keeper.example:9181 --create-user audituser --create-userpass 'strong-password' --grant-admin
```

Interactive creation requires exactly one Keeper target and a terminal. For
automation, add `--yes` to skip menus and both prompts; with multiple clusters,
also specify `--clickhouse-cluster`. Without a usable DDL task, provide both
`--clickhouse-host` and `--clickhouse-cluster` as before. `--yes` can affect
multiple targets, so use an explicit target list you control.

The module reads DDL worker host IDs and the cluster name from the newest valid
task per cluster when exactly one cluster is identifiable. It does not merge
older host lists, which may include retired workers. If the queue is empty, or
the desired cluster has no usable task, specify `--clickhouse-host`, `--clickhouse-port`
(native port, default 9000), and `--clickhouse-cluster`. If tasks from multiple
clusters are present, `--clickhouse-cluster` selects one; the module never
guesses a cluster or substitutes Keeper's IP for a ClickHouse worker host.
Automatic selection stops with a diagnostic if the DDL queue has more than 512
tasks; explicit host and cluster still work.
`--show-cluster` and `--show-hosts` list names and worker IDs from existing DDL
tasks (formats 5–8) without changing data. New tasks use the minimal format 5
entry and do not inherit another task's settings or initiator identity. Replica
names under `/clickhouse/tables`, session
entries, optional cluster-discovery paths, and Keeper peer addresses are not
reliable substitutes for DDL worker IDs; they are not used to enqueue tasks.
`{cluster}` works in ClickHouse only when that macro is configured on the server;
normal `ON CLUSTER '{cluster}'` submission stores the expanded cluster name in
the DDL queue. Redposture never substitutes a literal `{cluster}` itself.

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
SNMP and IPMI exporters. Select a type with `-e mysql`, `-e json`, `-e elasticsearch`,
`-e snmp` or `-e ipmi`; matching callback listeners start automatically.
All nine matching listener types are enabled by default; `-e` narrows the
exporters and their listeners, while `-s` selects listeners explicitly.
Exporter scan, collect and trigger skip HTTPS certificate and hostname verification
by default; use `--no-insecure` to verify against system roots or `--tls-ca file`
to verify against a supplied CA. In trigger, `--no-postgres-tls` disables the
Postgres callback listener's default TLS, and `--no-with-listen` skips listeners.
SNMP and IPMI callbacks use UDP. An accepted exporter request alone is inconclusive;
the listener must observe the outbound request. Percona MongoDB exporter is excluded:
its `/scrape?target=` only selects hosts already configured in `--mongodb.uri`.

After detecting an exporter, trigger tries its default probe and a bounded list of
common named profiles (`auth_module`, `module`, or SNMP `auth`) serially. It keeps
testing after a callback because another profile may forward credentials. Guessed
profiles are paced, not retried, and stop after repeated exporter failures. The
`CRED!` marker requires credential material actually received by the callback;
an HTTP callback can capture Basic, Bearer, API-key or `X-API-Key` authentication.
For MySQL `mysql_native_password`, the callback records the username, random
challenge (`auth_salt`) and 20-byte `auth_response`, **not the plaintext password**.
The response is bound to that challenge. Custom profile names can be provided
through `--profiles-file` or each exporter's
explicit profile flag (for example `--mysql-auth-module`, `--elastic-auth-module`,
`--postgres-auth-module`, `--blackbox-module` or `--snmp-auth`). These flags use
the exporter's own query parameter, rather than a shared `auth_mode`; Redis has
no named probe profile. Use `-check` to verify captured Redis/Postgres credentials.
SNMPv1/v2c callbacks additionally show the community string. SNMPv3 and IPMI
callbacks confirm SSRF without claiming a captured password.

## Offline CVE enumeration

`--enum-cve` matches a confirmed product and exact version against the bundled catalog.
No external lookup or exploitation is performed. Matches are **potentially affected**,
not proof of exploitation; vendor backports and deployment settings may change applicability.

The catalog primarily covers High/Critical network CVEs with a reliable version range:
code execution, auth bypass, account takeover, data disclosure, arbitrary file access,
or SSRF. Pure DoS is excluded. `PR:L` normally appears only with anonymous access or
verified **explicit** credentials/token/API key; invalid credentials and `--defcreds`
alone do not enable it. A few selected entries are version-only exceptions: the
Nexus script/licensing CVEs require the elevated permissions named in their titles;
Grafana Image Renderer requires the separately detected plugin version and a reachable
renderer with a known/default token. Other prerequisites in titles, such as Enterprise
SCIM configuration or a write-enabled MinIO access key, are not verified by version
matching. These findings remain `potentially affected`, not confirmed exploitation.

Credential checks precede CVEs. Findings sort newest first. The `CVE's Enumeration`
header appears only with matches. Unknown versions, no matches and unsupported products
are quiet in normal TXT; JSON/debug retain the status and evidence.

```text
GRAFANA         10.0.0.1        3000  [*] Grafana Service (auth required:False) (version:8.2.6)
GRAFANA         10.0.0.1        3000  [*] CVE's Enumeration
GRAFANA         10.0.0.1        3000  [!] CVE-2021-43798 potentially affected (HIGH 7.5) Unauthenticated path traversal and arbitrary file read
```

The bundled `2026-10-03` catalog contains 197 reviewed product/CVE records:

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
| **Total** | **197** | | |

Products are matched separately: Elasticsearch/OpenSearch, Redis/Valkey and
ZooKeeper/Keeper do not share findings. Harbor, Nexus and GitLab match only their
confirmed product. Plain Docker Registry and gRPC are unsupported; Kafka cannot determine
an exact broker release. Keeper currently has no catalog matches. Version access may
require authentication; Oracle needs the exact Database version, not the listener version.
With `-f json`, `cve_enumeration` includes ranges, fixed versions, CVSS and source references.

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

CI locks are in `requirements/`; update with `scripts/update_ci_locks.sh`.
Heavy QA stays local: `./scripts/run_qa_handoff.sh full` or `versions` on a checkout
with the local lab. Run them sequentially and use fresh artifact directories.
Focused HTTP detection QA: `./scripts/run_http_detection_qa.sh` writes a report under
`.redposture/qa/` and uses the real Docker service matrix when Docker is available.
`lab/`, `lab_tests/`, `qa_tests/` and `.redposture/` are excluded from Git.

## License

[MIT](LICENSE).
