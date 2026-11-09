# Reproducible performance profiles

These opt-in tools run the actual module detectors/runtime or public command
entrypoints against deterministic protocol fixtures. They do not test physical
hosts or replace integration checks against real products. Run one profile at a
time, separately from CI and Docker stands.

## Short regression gate for changed paths

```bash
python scripts/check_performance_regressions.py --before /path/to/before-source --output /tmp/redposture_short_plan --container-image redposture-detect-performance:local --plan
python scripts/check_performance_regressions.py --before /path/to/before-source --output /tmp/redposture_short_gate --container-image redposture-detect-performance:local
```

Use a new output directory and an unchanged baseline. The planner retains all
32 modules and their UI surfaces. Direct module paths select their consumers;
shared runtime changes select PostgreSQL, Redis, Grafana, Kafka and
collect/trigger/spray. Shared scanner changes select every supported discover
route. `--all-modules` explicitly selects all modules. No standalone Place
download is implemented by these profiles.

Selected wire cases exercise detect, invalid supplied credentials and seeded
read-only inventory. Every case uses one warmup per side and at least three
alternating measured pairs in separate offline containers. First-finding,
wall, peak RSS and sampled FD have repeated thresholds. The default is 64
logical targets; Redis credential checks use 512 to observe the sustained FD
peak rather than a startup burst shorter than the sampler interval. Input,
ports, attempts and timeouts match between the two sides of each comparison.

All 32 modules have a data recipe: 25 use seeded wire/CLI actions; Redis,
PostgreSQL, ClickHouse, MongoDB, Oracle, ZooKeeper and Keeper instead use the
production read/format helpers with independently authored socket/SDK peers.
These seven adapter profiles explicitly exclude network/session/TLS and SDK
internals. They do not certify full native data transport. Discover quality
uses independently labelled DTO/reader corpora and UI cases; shared JSON
processing has a separate paired 10 MB profile. Those are distinct evidence,
not full product traversal or production recall.

`--case CASE_ID` is an explicit focused rerun. Its report retains the complete
plan and filter so a partial rerun cannot masquerade as all selected cases.
Original failed runs remain separate artifacts. Missing artifacts, inaccurate
values/types/paths, duplicates, changed instruments or failed cleanup fail the
gate. A timing difference within the threshold is noise, not a speedup claim.
This optional gate does not remove or replace the full CI/QA release checks.

## Prepare an offline measurement image

From the repository root:

```bash
docker build -f tests/fixtures/performance/Dockerfile -t redposture-detect-performance:local .
```

Build before measuring. Each sample resolves that local image to its immutable
ID and runs with `--pull never`, network `none`, 2 CPUs, 1 GiB RAM and a PID limit
of 512. Source and measurement tools are mounted read-only. Output and owned
container leases are saved in the selected artifact directory. Cleanup failure
stops a batch; investigate its lease instead of starting another sample.

Use two separate source directories containing `redposture_core/`. Keep the
baseline unchanged. The tools record source hashes and retain the exact Python
measurement/fixture files and the HTML payload catalogue, package versions and image ID. Existing snapshots/manifests must match; corruption is rejected. Replaying an older
comparison requires its retained instrument, not an updated working copy.

## Compare all 32 detectors

```bash
python scripts/compare_module_performance.py --before /path/to/before-source --after /path/to/after-source --modules all --mode detect --models mixed --targets 1000 --workers 16 --concurrency 64 --timeout 0.5 --delay-ms 2 --repeats 3 --container-image redposture-detect-performance:local --output /tmp/redposture_module_comparison
```

The output directory must be new. One warmup and at least three measured pairs
are required; the before/after order alternates. `results.json` retains every
sample, including original baseline failures. Missing results, failed candidate
warmups, inconsistent settings/instrument/environment and unverified cleanup
cannot become PASS. Timing gates account for a 25% relative threshold, 0.25 s
absolute threshold and three times the observed spread. `WITHIN_NOISE` is not a
speedup claim. Counts, identities, duplicates and cleanup are checked separately.

The same complete comparison is an optional local QA section:

```bash
REDPOSTURE_MODULE_PROFILE_BASELINE=/path/to/before-source REDPOSTURE_MODULE_PROFILE_IMAGE=redposture-detect-performance:local bash scripts/run_full_local_qa.sh /tmp/redposture_module_gate --section module-performance
```

This section uses the current repository as the candidate, all 32 modules,
mixed 1000, 16 workers, 64 detect, timeout 0.5 s, 2 ms fixture delay and three
measured pairs. It is **detection-only**, is not part of default QA and does not
certify auth, inventory, discover, UI or execution paths.

## Inspect public auth/data and workflow paths

```bash
python scripts/profile_module_performance.py --source /path/to/source --module grafana --mode defcreds --auth-case valid --model positive --targets 40 --workers 4 --concurrency 16 --timeout 1 --save --format json --container-image redposture-detect-performance:local --output /tmp/grafana_profile.json
python scripts/profile_module_performance.py --source /path/to/source --module jenkins --mode actions --auth-case limited --action=--show-jobs --model positive --targets 40 --workers 4 --timeout 1 --save --format json --container-image redposture-detect-performance:local --output /tmp/jenkins_profile.json
python scripts/profile_workflow_performance.py --source /path/to/source --workflow collect --model positive --targets 1000 --workers 16 --timeout 0.5 --delay-ms 50 --container-image redposture-detect-performance:local --output /tmp/collect_profile.json
```

Use fresh output paths for every sample. These commands produce individual
measurements, **not** statistical before/after conclusions. `--inventory` on the
module profiler writes the registry/parser/UI coverage map without network I/O.

Auth fixtures are less complete than the detection corpus. Valid/limited cases
currently require Grafana, Jenkins, Airflow, Vault, Nomad, Jupyter, Keycloak, Consul, KubeAPI, Qdrant,
GitLab, Docker Registry, Proxmox, MinIO, RabbitMQ, Harbor, Nexus, Portainer, Elastic Basic auth or etcd v3 pairs. Seeded action matchers cover Grafana datasources, Jenkins jobs, Vault
mounts, Nomad jobs, Jupyter kernels, Consul services, Kubernetes namespaces, a
selected Qdrant collection, a selected GitLab web project on page two, Registry
selected tags/full images and Proxmox nodes/users. Additional seeded matchers cover Airflow DAGs/variables/connections, MinIO buckets, RabbitMQ queues/vhost ACLs, Harbor API projects/repositories/artifacts plus separate V2 reads, and Nexus REST repositories/cursor-paginated images/selected asset metadata, and Portainer selected environments with Docker containers/images/networks/volumes/system ACL. Portainer pair profiles retain actual login requests, issued JWTs, matching received Bearer identities and denied automatic exec bodies; they do not certify API-key/SSO or successful execution. Other valid/limited scenarios are rejected rather
than silently simulated. An unsupported auth reply or result schema remains a
FAIL; a scenario is NOT_APPLICABLE only when the parser lacks the corresponding
flag. Full credential identities and known verdicts must agree, not merely the
number of attempted pairs or the presence of one accepted identity. Token-only
root verdicts are correlated with the exact token actually received on an identity
endpoint; ambiguous or missing wire identity never becomes a fabricated attempt.
Credential verdicts on known foreign/unreachable roots fail the profile. Foreign HTTP responses are recorded before returning, so an empty ledger is not inferred from skipped observation. Elastic profiles retain complete received Basic pairs, identity and CRUD bodies/replies with SHA-256; seeded mutations are restricted to transient probe indices and cleanup counters must return to zero. Its limited role independently permits write, denies document-delete and permits index cleanup. Seeded actions cover cat endpoints/plugins, cluster nodes/health and security users. This is Elasticsearch 8 protocol emulation, not certification of a real cluster, OpenSearch/Kibana/SSO/API-key routes or discover content. Public JSON credential redaction remains unchanged; full wire credentials are separate QA evidence. etcd profiles independently verify the complete JSON login pair, issued raw token and gRPC metadata header, count/range/page requests, selectors and UTF-8 key values. A limited role can read one selected key while global range is forbidden; explicit authentication failure remains separate. The model is read-only and unknown routes do not return fabricated success. No v2/mTLS or real-cluster performance claim is implied.

For startup-scale checks, use `--auto-concurrency` to leave the product helper in
control. The artifact records the actual configured limit from the runtime
observer, rather than a guessed requested value. Use `--http-peer process` to
place the HTTP server in a separate interpreter/GIL within the same limited
container. Its CPU and sampled FD/threads are included; RSS is a conservative
sum of both OS high-water marks. A same-interpreter `async` peer and historical
`threaded` peer remain available as explicit controls. Different peer policies
or detect policies cannot silently become a matched before/after comparison.
Native protocol controls have a separate `--native-peer threaded|async|process`
option; its default remains `threaded` for historical comparisons. Use
`--native-peer process` to run a single-loop native peer in the owned child,
with the same resource accounting and limits as the HTTP process peer. The
blocking and async transports use the same bounded wire programs; their
detection replies are also checked against the independent original corpus.
All nine native families are supported for detection. Seeded rejected-credential
wire programs currently cover PostgreSQL, Redis, MongoDB and gRPC only. The
gRPC auth corpus returns HTTP/2 trailers with status16 (`UNAUTHENTICATED`),
separate from the detection corpus's status12 (`UNIMPLEMENTED`). This models
known denied credentials, not valid/limited users or every auth mechanism. A Kafka
metadata response, Oracle listener or ZooKeeper permission error does not prove
the rejection of supplied credentials.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module mongodb --mode defcreds --auth-case invalid --model positive --targets 40 --workers 4 --concurrency 16 --timeout 0.5 --delay-ms 2 --native-peer process --save --format json --container-image redposture-detect-performance:local --output /tmp/mongodb_native_profile.json
```

Native peer policy is retained in `native_peer` and in the historical shared
comparison field `http_peer` as `native_threaded`, `native_async` or
`native_process`. Changing the peer cannot silently become a product speedup.
Keep original failed samples and rerun both source versions with the same peer
for a new before/after comparison.

gRPC default sweeps omit token values in their public product ledger. The QA
peer therefore observes Authorization from complete received HTTP/2 streams,
matched by actual destination, and the profiler saves a separate `.wire.jsonl`
receipt with header hashes. It never inserts identities from the expected plan.
For the seeded denied sweep, each ledger row requires the corresponding
health/reflection pair, status16, the same wire identity and a conclusive product
rejection. Incomplete, conflicting, duplicate or overflowing evidence remains
FAIL. Product TXT/JSON is unchanged; the enriched observation is QA-only.

The native wire observer retains at most130 calls per target,32768 pending calls
in total and8192 targets, with authorization limited to1KiB per call. This is an
explicit measurement-fixture limit, not a product credential limit: exceeding it
invalidates evidence instead of truncating a value or passing the profile.
Completed roots consume their observations. Shutdown clears storage while
retaining the pre-cleanup pending/overflow counters, so cleanup cannot hide
unconsumed calls. The profile reports `grpc_wire_summary`, `grpc_wire_errors` and
the receipt's SHA-256. The fixture observes request completion; response receipt
still requires the independent module verdict.

The workflow profiler exercises real collect/trigger/spray CLI entrypoints.
Spray fixtures currently cover Grafana and Jenkins with known accepted/rejected
pairs. Trigger uses an emulated exporter probe, with no listener or real backend;
its PASS is not a callback integration result. The 20 ms sampled first nonempty
saved file may contain a negative record and is not a confirmed first finding.
The module profiler's `first_finding_seconds` is the callback of a completed
detected root; auth/data can delay it beyond the early service line. It is not
a measurement of first terminal output.

## Resource and model limits

- All targets are logical loopback routes in an isolated network namespace.
  One million physical hosts are not represented by one million fixture routes.
- CPU, RSS, FD and threads include the fixture and sampler. FD/thread peaks use
  20 ms sampling; RSS is the OS high-water mark.
- The module profiler's threaded native fixture can itself constrain high
  concurrency. PyMongo monitor/cursor threads can hit the PID 512 limit during
  full catalogues. Such failures remain visible; product workers and credential
  catalogues are not reduced to turn a measurement green. The process native
  peer removes per-socket server threads, but does not remove the driver's
  monitor threads. A passing seeded case is not proof of bounded driver thread
  growth at all target counts or worker settings.
- `--engine native` requests a path; the runtime retains its small-batch gate and
  compatibility fallbacks. Inspect recorded evidence rather than assuming every
  connection was native.
- Module-profile debug currently discards its debug sink: it measures observer
  cost, not terminal/file logging overhead. Workflow CLI logs are retained, but
  a dedicated debug on/off comparison is still required.
- A passing seed corpus does not establish discovery or credential correctness
  for all versions, proxies, TLS configurations or unavailable API surfaces.

Real Kafka UI checks are tracked separately from the native Kafka performance
fixture. Provectus v0.7.2 LOGIN_FORM uses `/auth`; protected API redirects with
JSON Accept can finish as406 on its HTML login page. Kafbat v1.5.0 uses `/login`
and exposes anonymous `userInfo:null`, which never proves credential acceptance.
Focused regressions are `tests/test_kafka_ui_provectus_form.py` and
`tests/test_kafka_ui_credential_colors.py`. Passing these or a real UI login stand
does not certify the profiler's native Kafka fixture as a full UI performance
model: selected/paged inventory, complete per-attempt session receipts and
matched before/after measurements remain separate requirements.


## Compare full credential and selected action paths

```bash
python scripts/compare_module_performance.py --before /path/to/before-source --after /path/to/after-source --modules consul kubeapi qdrant gitlab --mode credentials --auth-case valid --http-peer process --models positive --targets 40 --workers 4 --concurrency 16 --timeout 0.5 --delay-ms 2 --repeats 3 --save --format json --container-image redposture-detect-performance:local --output /tmp/redposture_token_comparison
```

The paired runner also accepts `--mode actions` with repeated `--action=...`,
`--target-style`, `--auto-concurrency`, `--debug`, `--save` and `--format`. Every
control is forwarded identically to both source versions. Unsupported action
matchers remain FAIL; adding an arbitrary action does not certify its result.
Neither CI thresholds nor normal product workers/timeouts are changed.


## Full credential catalogue parity

For credentials, defcreds and seeded actions, each sample retains
`credential_expected_sha256`, `credential_identity_digests` (at most 32
identities plus a visible overflow counter) and
`credential_expectation_per_positive`. The hashes cover full per-target
credential catalogues before output redaction. They contain no literal secrets.
The comparison requires identical catalogue size/hash across sources and checks
that every positive root has the expected observed digest; a faster reduced
catalogue cannot pass. Missing evidence, conflicting counts or observed hashes
fail the gate independently of a sample's `quality:PASS` claim.

Historical auth profiles without these fields are preserved with their original
instruments and are rejected by the current comparison gate. Do not add guessed
hashes to an old sample or silently replay it under the new instrument. Retain
its limitations and run a fresh matched pair when final acceptance requires the
new contract. Detection-only comparisons do not need credential evidence.

Registry emulation uses a protected V2 Basic challenge, real pagination and
independent read ACLs. It does not test a real registry or its Bearer-token
service. Proxmox emulation issues a non-persistent fixture ticket and read-only
node/user responses; it does not run a hypervisor, VM/CT, guest commands, 2FA or
API-token/TLS scenarios. Default catalogues are unchanged: all configured pairs
are attempted, including pairs after the successful seeded identity.


## PostgreSQL pacing and resumable finish measurements

PostgreSQL credential pacing and overload cooldown remain per host, including
across ports. The audit runtime can park these socket-free waits in a bounded
continuation window while another host uses the same synchronous auth worker.
The direct/interactive compatibility path still waits synchronously.

For this opt-in path, `finish` and `queue_wait` count continuation advances,
which can exceed the number of logical targets. Compare complete public results,
credential catalogues, network messages and elapsed run time across versions;
do not interpret fewer aggregate `auth` seconds as fewer attempted credentials.
With debug enabled, `finish_wait` separately reports the number and cumulative
duration of parked continuations. It is not a busy network-worker count. All
parked jobs still count against `max_inflight`; cancellation closes idle
continuations and their lifecycle state. Observer labels and histograms stay
bounded and contain no target or credential values.

## Explicit native rejection and prepared token identities

ClickHouse auth profiles receive the complete native ClientHello before sending
Exception516. Detection-only profiles retain their independent fingerprint
corpus. A normalized credential alias is counted as rejected only when the
matching full identity has an explicit native `ok=False`/516 proof. Permission
errors, transport failures and unavailable verification stay unverified. Every
unclassified observed attempt is included in the unverified summary count.

Keycloak token profiles distinguish a verified UserInfo subject from access to
administrator endpoints. Limited tokens keep their identity when those APIs
return403. The peer emulates a token with UserInfo/openid access; it is not a
real Keycloak server or JWT verifier. The expected catalogue uses the module's
own prepared token when its one internal plan entry is a redaction marker;
CLI values and reduced catalogues cannot substitute for that evidence. The
observed token comes from actual verifier headers and is consumed per root.
Persisted HTTP route/header hashes are aggregate; unlike gRPC receipts they do
not yet provide a per-root retained wire log. Product JSON is unchanged.

## Harbor and Nexus Basic/API controls

These peers emulate explicit local Basic deployments, not actual products or every authentication mode. Harbor API identity is `/api/v2.0/users/current`; the V2 endpoint models a separate Basic-protected registry gateway. Nexus models a Basic-protected REST status endpoint and no V2 connector. A restricted Nexus identity requires the complete 403/users → 200/status → 401/invalid-control differential proof; 403 alone never verifies credentials. Unknown API/asset paths fail and all mutations return an error.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module harbor --mode actions --auth-case valid --action=--show-images --model positive --targets 40 --workers 4 --http-peer process --auto-concurrency --save --format json --container-image redposture-detect-performance:local --output /tmp/harbor_images.json
python scripts/profile_module_performance.py --source /path/to/source --module nexus --mode actions --auth-case valid --action=--show-repositories --action=--show-assets --action=--repository --action=release-assets --action=--asset --action=release-notes/stable/artifact.bin --model positive --targets 40 --workers 4 --http-peer process --auto-concurrency --save --format json --container-image redposture-detect-performance:local --output /tmp/nexus_asset.json
```

Each complete received Basic identity/status and client verdict is retained in a bounded per-root ledger. Nexus automatic Script API probes are denied with HTTP405 and never executed. Their complete request bodies, credentials and status remain in wire receipts; the nonce is grouped only in request statistics. The body ledger has an 8 MiB pending UTF-8 byte cap in addition to per-root/total limits. Corruption or overflow fails the profile. This validates the received echo command and denied response; it does not certify the full Groovy template or successful execution.

Closed vendor peers must produce a transport failure, not a clean absence. Source snapshots predating QUALITY02 may therefore remain explicit baseline FAIL. Before/after comparisons must use the same frozen instrument; old partial statistics cannot silently be re-labelled complete.


Workflow debug profiles run the public CLI with its actual stdout/stderr writers.
Artifacts retain full file SHA-256, byte/newline counts after writers close, plus
bounded route/auth-identity counts. Scheduler capacity is observed at the actual
constructor; a workflow with no constructed scheduler records zero, not a guessed
limit. Multiple capacities are listed explicitly. The profiler does not change
ports, concurrency, credential candidates or retries. Current spray JSON debug emits bounded runtime diagnostics to stderr: separate
detect/work limits, phases, queue peaks and periodic progress, using one reporter
thread that is joined on completion/cancellation. Saved credential records remain
unchanged. Older snapshots lacked these lines; their debug-switch comparisons
must not be presented as measuring diagnostic I/O they did not emit.
The first-saved-record metric is sampled and may be a negative record; it is not
the time of the first confirmed finding. HTTP fixtures share the measured process,
so their CPU/RSS are included. They are not real services or a trigger listener.

## Read-only Docker, Spark and YARN public workflows

`--mode run` exercises the ordinary public CLI with no credentials or data action.
`--mode actions` adds explicitly supplied inventory flags. These three modules
have no portable pair/token verifier: their credentials/defaults profiles are
`NOT_APPLICABLE` before starting a peer, rather than fabricated successful login.
Docker client-certificate scenarios require a separate TLS stand.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module spark --mode actions --access-case open --action=--show-workers --action=--show-apps --model positive --targets 40 --workers 4 --http-peer process --auto-concurrency --save --format json --container-image redposture-detect-performance:local --output /tmp/spark_inventory.json
```

Run one module/stand at a time. `--access-case open|limited|denied` selects the
explicit API model. Docker limited permits containers and system info only;
YARN limited permits cluster info and metrics while denying apps/nodes. Spark
limited means submission-REST-only, with no Master UI inventory; it does not
represent a validated limited user. Generic denied Spark replies cannot prove
the product and are rejected as a positive profile configuration.

The new `.read-wire.jsonl` stores the full received request/response and result
per root, with SHA-256, bounded pending bodies/headers and overflow checks. The
corpora have multiple known apps/workers/nodes or daemon objects and UTF-8 app
names. No allocation, submission or execution succeeds: non-GET returns405.
These are protocol emulators, not actual Docker/Spark/YARN products. Validate
ordinary and selected inventory separately; do not infer discover, mTLS,
Kerberos or execute coverage. `first_finding_seconds` means the first completed
positive root callback, not the first detection line printed by the CLI.

## Native gRPC full credential and protobuf controls

Use `--auth-surface grpc-auth` for the seeded Basic pair or `grpc-bearer` for
Bearer, with `--native-peer process` (or `async` for a scoped local control).
The legacy default surface remains an explicitly denied gRPC16 corpus.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module grpc --mode actions --auth-surface grpc-auth --auth-case limited --action=--analyze --model positive --targets 40 --workers 4 --native-peer process --auto-concurrency --save --format json --container-image redposture-detect-performance:local --output /tmp/grpc_limited.json
```

Full controls retain received Basic/Bearer identities and complete protobuf
request/response frames in `.wire.jsonl`, consumed per root with byte/stream
bounds. They verify Health, Reflection v1, complete descriptors and per-service
metadata. Valid and limited models accept the supplied Basic pair and the seeded
Bearer token `admin`; defaults still use the full 23-entry product catalogue,
including two successes. Invalid controls deny every supplied identity.
Limited means protected Health accepts credentials while Reflection is denied;
the auth verdict must remain verified and the requested analysis unavailable.

This peer is protocol emulation, not an actual deployment or coverage of TLS,
mTLS, gRPC-Web, all reflection versions, arbitrary RPCs or unary invocation.
Negative native RPC evidence does not retain HTTP fallback headers. Preserve
known baseline FAIL and never replace the full wire proof with CLI guesses.

## Kafka LOGIN_FORM UI profiles

Use `--module kafka --auth-surface provectus-ui` or `kafbat-ui` for the
separate HTTP form/session model. The default Kafka profile stays native.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module kafka --auth-surface kafbat-ui --mode defcreds --auth-case valid --model mixed --targets 1000 --workers 4 --concurrency 64 --timeout 1 --save --format json --http-peer process --container-image redposture-detect-performance:local --output /tmp/kafbat_defaults.json
```

`actions` supports `--show-clusters`, `--show-topics`, `--show-brokers` and
`--show-consumer-groups`, including pagination and limited cluster permissions.
Form pairs, origin-bound issued session cookies and matching protected identities
are verified from complete received wire data. Mutation/execute requests are
denied by this read-only peer. No real broker, TLS, SSO or other Kafka HTTP
surface is certified by this model.

The actual saved JSON footer is a quality gate, independently of host records.
Pending UI wire evidence uses a private temporary SQLite database (256 MiB
encoded pending budget, 8 MiB per root, bounded cache). These are QA-evidence
limits, not product scan limits. Overflow, disk errors or missing cleanup fail
the sample. RAM and disk observer policies cannot form one timing comparison.
A replayable scratch database uses synchronous OFF; an interrupted sample is
not resumed as successful. Each receipt retains full bodies/headers/SHA-256.

## Other Kafka HTTP gateways

`--module kafka --auth-surface` also accepts `akhq`, `redpanda-console`,
`rest-proxy`, `connect`, `ksqldb` and `schema-registry`. Use `run` or `actions`
with `--action=--show-topics`; the latter enumerates topics only for Redpanda
Console and REST Proxy. Other gateways are checked for the product's explicit
unsupported-action result, not counted as a successful topic enumeration.
Credentials/defcreds are deliberately rejected by this profile: these six
product adapters do not implement a credential verifier. That gap is not a
passed authentication test. Form/session profiles above remain separate.

```bash
python scripts/compare_module_performance.py --before /path/to/before-source --after /path/to/after-source --modules kafka --auth-surface rest-proxy --mode run --models mixed --targets 1000 --workers 4 --concurrency 64 --timeout 1 --delay-ms 2 --repeats 3 --container-image redposture-detect-performance:local --output /tmp/kafka_rest_proxy_comparison
```

The peers retain 201 known topic/connector/subject names, complete received
HTTP headers and bodies with hashes, per-target origin, the actual JSON footer,
and cleanup evidence. They permit only bodyless GET; no broker work, commands,
login or mutations are implemented. UI fingerprints and HTTP catalogues are
not proof of backend Kafka connectivity, TLS, SSO or arbitrary API versions.

Protocol provenance: [AKHQ 0.25.1 current-user DTO](https://github.com/tchiotludo/akhq/blob/0.25.1/src/main/java/org/akhq/controllers/AkhqController.java),
[Redpanda Console v2.7.2 legacy topics envelope](https://github.com/redpanda-data/console/blob/v2.7.2/backend/pkg/api/handle_topics.go)
and [startup booleans](https://github.com/redpanda-data/console/blob/v2.7.2/backend/pkg/api/handle_probes.go),
[REST Proxy v2 topics/v3 cluster API](https://docs.confluent.io/platform/8.0/kafka-rest/api.html),
[Kafka Connect 3.7.0 root resource](https://github.com/apache/kafka/blob/3.7.0/connect/runtime/src/main/java/org/apache/kafka/connect/runtime/rest/resources/RootResource.java),
[ksqlDB 0.29.0 server DTO](https://github.com/confluentinc/ksql/blob/v0.29.0/ksqldb-rest-model/src/main/java/io/confluent/ksql/rest/entity/ServerInfo.java),
and [Schema Registry subject API/media type](https://docs.confluent.io/platform/current/schema-registry/develop/api.html).
These protocol models do not replace running those products.

## Keycloak read-only Admin REST inventory

The Keycloak bearer-token model supports three realms (`master`, `corp`,
`partners`) and 201 known clients per realm. The Admin REST shapes follow the
[Keycloak OpenAPI](https://www.keycloak.org/docs-api/latest/rest-api/openapi.yaml):
realm details are top-level `RealmRepresentation` objects and client lists use
`first`/`max` pagination. This is a protocol model, not a running Keycloak.

```bash
python scripts/profile_module_performance.py --source /path/to/source --module keycloak --mode actions --auth-case valid --model positive --targets 40 --workers 4 --auto-concurrency --http-peer process --format json --save --action=--show-realms --action=--show-clients --action=--realm --action=master --action=--realm --action=corp --action=--realm --action=partners --container-image redposture-detect-performance:local --output /tmp/keycloak-inventory.json
```

The quality gate checks exact ordered client names, realm policies, client
types, flows, redirect URIs and origins. `--realm` selects client scope;
`--show-realms` continues to list all realms visible to this identity.
Optional counts on `--show-clients` are checked against actual retained rows.
With `--auth-case limited`, userinfo verifies the master-realm identity while
Admin REST responds 403; the inventory must retain explicit denied/partial
fields, without converting a valid token into an invalid credential.

The QA token is a master-realm token. Userinfo in another realm rejects it;
the allowed model can still verify identity through the admin console's
authenticated user response. This does not model cross-realm token exchange,
SSO, TLS or arbitrary server versions. The fixture only allows bodyless GET
on the enumerated routes. Tests separately inject repeat pages, 503, malformed
JSON and timeout after one completed page; those are not real product tests.

## Offline XML/HTML and duplicate-value processing

`profile_processing_performance.py` exercises the actual shared discovery
member reader, classifier, deduplication and JSON serialization. Its three
fixed corpora contain exactly two distinct password findings, at the beginning
and end; neutral XML attributes, HTML elements or duplicate assignments fill
the middle. Exact ordered type/value/Place, complete status, JSON roundtrip,
no ANSI, FD/thread cleanup and source provenance are checked.

```bash
python scripts/profile_processing_performance.py --source /path/to/source --case xml-dense --megabytes 10 --container-image redposture-detect-performance:local --output /tmp/xml-processing-10mb.json
```

Cases: `xml-dense`, `html-inputs`, `duplicate-lines`. Sizes `1`, `10`, `100`
are decimal megabytes; the default is 10. Each invocation uses a fresh offline
Linux process, 2 CPUs/1 GiB, no external network and an owned container removed
afterward. The existing container helper has a 600-second outer timeout;
exceeding it fails the sample and still performs cleanup. The collector's
default deadline remains 900 seconds. Neither value changes product timeouts.

For comparisons use the same pinned image/instrument and exact input SHA,
one warmup plus at least three alternating before/after repetitions. Compare
spread before claiming a speedup. Candidate-only 10/100 MB runs establish
resource growth, not a before/after throughput claim. RSS includes imports;
FD/thread/temp-file peaks are sampled every 20 ms and may miss shorter peaks.
Temporary file sizes include input and anonymous spool files, counted once.
One measurement thread is included in the sampled thread peak.

The member reader first validates/spools the entire file to avoid reporting
text from a binary prefix. First-finding latency includes this first pass;
it does not prove output before network EOF. This offline profile is separate
from product integration, network faults and the module/workflow profiles.

## Many distinct findings and full saved output

`profile_result_performance.py` complements the two-unique-value processing
corpora with one distinct password every 1024 input bytes. Decimal 10/100 MB
contain 9765/97656 findings. The actual member scanner emits complete TXT;
the full collector result, including emitted fingerprint IDs, passes through
the shared streaming JSON serializer. The product display label is `Pass`.

```bash
python scripts/profile_result_performance.py --source /path/to/source --megabytes 10 --container-image redposture-detect-performance:local --output /tmp/distinct-results-10mb.json
```

Generation and expected SHA-256 identities use a temporary SQLite catalogue.
Verification reads one small JSON finding at a time with an independent
stdlib decoder and compares all ordered values, types, paths, fingerprints,
emitted IDs and exact TXT lines. Missing, extra, duplicate, reordered,
truncated, partial or ANSI-containing output fails the profile. Its bounded
record decoder applies only to this fixed small-value QA corpus; it does not
limit product findings. Large individual values have separate tests.

The profile freezes its instrument and helpers under `instrument-SHA/`, pins
the image and guards source/tool hashes. Sizes 1/10/100 MB are supported;
default 10 MB, unchanged collector deadline 900 seconds. Each offline
container has 2 CPUs/1 GiB, a 600-second outer timeout and mandatory cleanup.
Scan+live-TXT and JSON serialization costs are timed separately. Input
generation, validation and provenance are outside those times, but resource
peaks include the bounded verifier, its SQLite cache and temporary files.
FD/thread/disk peaks are sampled every 20 ms; RSS includes imports. Input,
TXT, JSON and spools are removed after full verification; hashes/counts and
the reproducible source/tool corpora remain. A Python-level failure writes
an explicit FAIL artifact and traceback. This is shared offline processing,
not the complete public CLI, a network stream or physical-host throughput.
