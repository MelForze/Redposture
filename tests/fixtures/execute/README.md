# Execute QA stands

The opt-in profile in `tests/fixtures/execute/docker-compose.yml` verifies only
the four supported command-execution surfaces. It runs one profile at a time
and removes its containers and volumes after each profile.

Run the complete sequential check with a fresh directory:

```bash
.venv/bin/python scripts/run_execute_qa.py /tmp/redposture_execute_qa all
```

Run one stand while investigating it:

```bash
.venv/bin/python scripts/run_execute_qa.py /tmp/redposture_execute_kafka kafka
.venv/bin/python scripts/run_execute_qa.py /tmp/redposture_execute_portainer portainer
.venv/bin/python scripts/run_execute_qa.py /tmp/redposture_execute_jenkins jenkins
.venv/bin/python scripts/run_execute_qa.py /tmp/redposture_execute_consul consul
```

The runner uses these loopback-only targets:

| Profile | Product | Target | Proof |
|---|---|---|---|
| `kafka` | Provectus Kafka UI v0.7.2 + a real single-node Kafka broker | `http://127.0.0.1:19089` | Groovy marker, stdout/stderr, exit `7` |
| `portainer` | Portainer 2.39.7 + disposable Docker-in-Docker engine | `https://127.0.0.1:19443` | exec in `qa-execute-container`, stdout/stderr, exit `7` |
| `jenkins` | the repository Jenkins review image | `127.0.0.1:19580` | Script Console marker, stdout/stderr, exit `7` |
| `consul` | Consul 1.17.3 with script checks enabled | `127.0.0.1:19500` | temporary check marker, exit `7`, deregistration |

The Portainer engine is published only on loopback at `19237` for seeding and
is never the user's Docker socket. `report.json`, per-profile Compose logs,
CLI output, and cleanup logs are written under the selected output directory.
The runner fails a profile if structured execution evidence is missing and
continues to the next profile only after cleanup.

To inspect the Kafka stand manually (the configured broker is required for
the verifier to prove anonymous UI access):

```bash
docker compose -p redposture-execute-manual --profile kafka -f tests/fixtures/execute/docker-compose.yml up -d --wait
.venv/bin/python redposture.py kafka -t http://127.0.0.1:19089 --execute 'printf kafka-ok; printf kafka-err >&2; exit 7'
docker compose -p redposture-execute-manual --profile kafka -f tests/fixtures/execute/docker-compose.yml down -v --remove-orphans
```
