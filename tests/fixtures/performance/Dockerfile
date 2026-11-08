FROM python:3.12.14-slim

# Build once from the repository root. Timed samples run offline, with the
# exact installed environment recorded in every result and a pinned image ID.
COPY requirements/ci-py312.txt /tmp/constraints.txt
RUN python -m pip install --no-cache-dir -c /tmp/constraints.txt \
    pytest pymongo h2 oracledb clickhouse-driver clickhouse-connect grpcio-tools

WORKDIR /profile-source
