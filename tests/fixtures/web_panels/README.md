# Disposable UI fixtures

Run one profile at a time. Cached images are used (`--pull never`); each service has CPU/RAM limits and random loopback ports. No host Docker socket or user database is mounted. The values below are synthetic QA credentials, not defaults advertised by the products.

Use a fresh artifact directory and the volume guard for **both** startup and teardown. It records Mounts before removing containers and deletes only new proven-owned volumes; an external or pre-existing volume is preserved.

## mongo-express

```bash
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-mongo/volumes docker compose -p rp-ui-mongo -f tests/fixtures/web_panels/docker-compose.yml --profile mongo up -d --pull never
docker compose -p rp-ui-mongo -f tests/fixtures/web_panels/docker-compose.yml port mongo-express 8081
.venv/bin/python redposture.py mongodb -t http://127.0.0.1:PORT --database qa --dump
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-mongo/volumes docker compose -p rp-ui-mongo -f tests/fixtures/web_panels/docker-compose.yml --profile mongo down --volumes
```

## Redis Insight

After startup, wait for `/api/info`, accept the EULA explicitly and register the password-protected fixture Redis connection. Setting `RI_ACCEPT_TERMS_AND_CONDITIONS` alone does not replace API onboarding in this image. The bootstrap is idempotent and does not replace existing connections.

```bash
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-redis/volumes docker compose -p rp-ui-redis -f tests/fixtures/web_panels/docker-compose.yml --profile redis up -d --pull never
docker compose -p rp-ui-redis -f tests/fixtures/web_panels/docker-compose.yml port redisinsight 5540
.venv/bin/python scripts/bootstrap_ui_lab.py http://127.0.0.1:PORT
.venv/bin/python redposture.py redis -t http://127.0.0.1:PORT --show-keys --dump
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-redis/volumes docker compose -p rp-ui-redis -f tests/fixtures/web_panels/docker-compose.yml --profile redis down --volumes
```

## pgAdmin

The UI account and the PostgreSQL account are different identities. The fixture imports the server definition but does not store the backend password in it. Supply `--pgadmin-server-password` to read its known table. A successful UI login alone does not prove database access.

```bash
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-pgadmin/volumes docker compose -p rp-ui-pgadmin -f tests/fixtures/web_panels/docker-compose.yml --profile pgadmin up -d --pull never
docker compose -p rp-ui-pgadmin -f tests/fixtures/web_panels/docker-compose.yml port pgadmin 80
.venv/bin/python redposture.py postgres -t http://127.0.0.1:PORT -u qa@example.com -p admin-password-22 --pgadmin-server-password reader-pass-22 --database qa --table public.known --show-columns --dump
.venv/bin/python scripts/qa_owned_volumes.py /tmp/rp-ui-pgadmin/volumes docker compose -p rp-ui-pgadmin -f tests/fixtures/web_panels/docker-compose.yml --profile pgadmin down --volumes
```

Replace `PORT` with the actual published port. Opt-in verification of all three profiles runs serially:

```bash
REDPOSTURE_REAL_QA=1 .venv/bin/python -m pytest tests/test_ui_fixture_live.py -q --no-cov
```

These three UI adapters currently report `--discover` as unsupported/unavailable. Their readable inventory/dump data must not be mistaken for a complete secret-discovery pass. The live test checks this distinction explicitly.
