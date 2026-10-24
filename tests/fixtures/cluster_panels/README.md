# Spark / YARN / Portainer QA

Run profiles sequentially. These services are bound to loopback. Portainer connects
only to the disposable `engine` service, never the host Docker socket.

```bash
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile spark up -d
.venv/bin/python redposture.py spark -t http://127.0.0.1:28085 --show-workers --show-apps --discover --enum-cve
.venv/bin/python redposture.py spark -t http://127.0.0.1:26066 --probe-submit
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile spark down -v
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile yarn up -d
.venv/bin/python redposture.py yarn -t http://127.0.0.1:28088 --show-apps --show-nodes --show-metrics --discover --enum-cve
.venv/bin/python redposture.py yarn -t http://127.0.0.1:28088 --probe-submit
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile yarn down -v
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile portainer up -d
.venv/bin/python tests/fixtures/cluster_panels/seed_portainer.py
.venv/bin/python redposture.py portainer -t https://127.0.0.1:29443 -u admin -p qa-portainer-password --show-endpoints --show-containers --show-images --show-networks --show-volumes --show-system --discover --enum-cve
docker compose -p redposture-cluster-qa -f tests/fixtures/cluster_panels/docker-compose.yml --profile portainer down -v
```

`--probe-submit` does not submit or execute an application. Spark sends an invalid
create request, YARN requests a new application ID. Neither proves full execution
permission. Spark's native cluster port 7077 is separate from HTTP UI / REST.
The fixture password is public test data, not a deployment secret.
