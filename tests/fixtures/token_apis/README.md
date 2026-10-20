# Vault / Nomad / Jupyter API labs

Run one profile at a time. All published ports bind to loopback. No Docker socket,
privileged container, Nomad client or kernel execution is required by these read-only profiles. Explicit execution profiles are documented below. Images remain
cached after `down`. Use a fresh artifact directory for each verifier run.

## Vault

Dev Vault: `28200`, common token `root`. Uninitialized Vault: `28201` (left sealed).
Only fixture preparation writes a synthetic KV secret; audit requests are read-only.

```bash
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile vault up -d --wait
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml exec -T vault vault kv put secret/reporting database_password=qa-vault-password endpoint=https://warehouse.example.test
.venv/bin/python scripts/verify_token_apis_lab.py vault /tmp/rp-vault-qa
.venv/bin/python redposture.py vault -t http://127.0.0.1:28200 --defcreds --show-mounts --show-auth --discover --enum-cve
.venv/bin/python redposture.py vault -t http://127.0.0.1:28200
.venv/bin/python redposture.py vault -t http://127.0.0.1:28200 --enum-cve
.venv/bin/python redposture.py vault -t http://127.0.0.1:28200 --token root --discover
.venv/bin/python redposture.py vault -t http://127.0.0.1:28201 --enum-cve
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml stop vault vault-uninitialized
```

## Nomad

ACL-enabled server: `24646`. ACL-disabled server: `24647`. Bootstrap once per
new container; keep the generated token file private. No job is submitted.
The verifier checks an empty real job inventory; nonempty specs, pagination and
namespace traversal are covered by HTTP integration tests.

```bash
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile nomad up -d --wait
(umask 077; docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml exec -T nomad nomad acl bootstrap -json > /tmp/rp-nomad-token.json)
.venv/bin/python scripts/verify_token_apis_lab.py nomad /tmp/rp-nomad-qa --token-file /tmp/rp-nomad-token.json
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24647 --show-jobs --show-nodes --show-members --enum-cve
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml stop nomad nomad-open
```

## Jupyter

Token-protected Server: `28888`, token `qa-jupyter-token`. Open Server: `28889`.
The image contains a synthetic notebook under `reports/`; it is only read.

```bash
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml build jupyter
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile jupyter up -d --wait
.venv/bin/python scripts/verify_token_apis_lab.py jupyter /tmp/rp-jupyter-qa
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --show-contents --show-sessions --show-kernels --discover --enum-cve
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28889 --show-contents --discover
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml stop jupyter jupyter-open
```

Remove only this project's containers/network after all profiles:

```bash
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile vault --profile nomad --profile jupyter down --remove-orphans
```

## Explicit execution labs

Run these profiles sequentially. Detection, inventory and `--discover` remain
read-only; only `--probe-submit` and `--execute` create resources. Temporary jobs,
kernels and terminals are deleted after the command, including on failure.
An existing `--allocation` is kept. Cleanup failures are reported with the resource
ID in JSON. A nonzero command exit code still confirms execution.

### Nomad execution

Port `24648` is an isolated server/client with `raw_exec` enabled. The optional
`nomad-execute-root.yml` override runs the client privileged with a **private cgroup
namespace**, no Docker socket and no host directories. It remounts this container's
cgroup hierarchy and moves the agent into its own child group. This is needed for
reliable allocation exec on the tested Docker Desktop ARM environment. The base
unprivileged profile supports batch commands, but allocation exec crashed the
vendor executor there, including with the official Nomad CLI.

```bash
docker compose -p rp-token-execute -f tests/fixtures/token_apis/docker-compose.yml -f tests/fixtures/token_apis/nomad-execute-root.yml --profile nomad-execute up -d --wait nomad-execute
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --enum-cve
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --probe-submit
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --execute 'id; uname -a' --execute-timeout 30
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --execute 'printf stdout; printf stderr >&2; exit 7' -f json -o nomad_execute.json
docker compose -p rp-token-execute -f tests/fixtures/token_apis/docker-compose.yml exec -T nomad-execute nomad job run -detach /etc/nomad/keepalive.json
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --show-jobs --show-nodes --show-members
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --discover
docker compose -p rp-token-execute -f tests/fixtures/token_apis/docker-compose.yml exec -T nomad-execute nomad job status -verbose redposture-qa-keepalive
.venv/bin/python redposture.py nomad -t http://127.0.0.1:24648 --allocation ALLOCATION_UUID --task hold --execute 'id; uname -a'
docker compose -p rp-token-execute -f tests/fixtures/token_apis/docker-compose.yml exec -T nomad-execute nomad job stop -purge redposture-qa-keepalive
docker compose -p rp-token-execute -f tests/fixtures/token_apis/docker-compose.yml --profile nomad-execute down
```

Replace `ALLOCATION_UUID` with the **full** ID from the status command above. The seeded
job sleeps for 600 seconds and has a synthetic password in its environment for
`--discover`. Temporary command jobs need the `raw_exec` driver and a Unix shell;
missing placement capacity/driver returns an explicit error, not confirmed RCE.
`--probe-submit` proves registration permission, not execution permission.

### Jupyter execution and terminals

The fixture image includes `ipykernel`. Default `--execute-via auto` creates a
Python kernel. It falls back to a terminal only after a definitive kernel-creation
rejection before execution; a lost stream never causes a second command attempt.

```bash
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile jupyter up -d --build --wait jupyter jupyter-open
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --enum-cve
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --show-contents --show-sessions --show-kernels --show-terminals
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --discover
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --execute 'id; uname -a'
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --execute-via terminal --execute 'id; pwd'
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28889 --execute 'id; uname -a'
.venv/bin/python redposture.py jupyter -t http://127.0.0.1:28888 --token qa-jupyter-token --execute 'printf stdout; printf stderr >&2; exit 7' -f json -o jupyter_execute.json
docker compose -p rp-token-apis -f tests/fixtures/token_apis/docker-compose.yml --profile jupyter down
```

Kernel mode uses a Python kernel with Unix process-group support for timeout
cleanup. Terminal mode uses the server's Unix shell and merges stdout/stderr.
The output cap applies to stdout and stderr combined. Truncation/timeouts are
reported as partial; command completion requires an exit result, not merely a
WebSocket connection or visible output.

Vault has no `--execute`: its module checks API access and reads KV secrets.
