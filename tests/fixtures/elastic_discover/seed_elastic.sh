#!/bin/sh
set -eu

ELASTIC_URL="${ELASTIC_URL:-http://elastic-open:9200}"
SEARCH_VENDOR="${SEARCH_VENDOR:-elasticsearch}"
CORPUS_INDEX="redposture-discover-corpus-v2"
CORPUS_DIR="${CORPUS_DIR:-/seed}"

curl_es() {
  if [ -n "${ELASTIC_USER:-}" ] || [ -n "${ELASTIC_PASSWORD:-}" ]; then
    if [ "${ELASTIC_INSECURE:-0}" = "1" ]; then
      curl -kfsS -u "${ELASTIC_USER:-elastic}:${ELASTIC_PASSWORD:-changeme}" "$@"
    else
      curl -fsS -u "${ELASTIC_USER:-elastic}:${ELASTIC_PASSWORD:-changeme}" "$@"
    fi
  elif [ "${ELASTIC_INSECURE:-0}" = "1" ]; then
    curl -kfsS "$@"
  else
    curl -fsS "$@"
  fi
}

put_json() {
  path="$1"
  payload="$2"
  curl_es -X PUT "${ELASTIC_URL}${path}" \
    -H 'Content-Type: application/json' \
    -d "${payload}" >/dev/null
}

put_index() {
  put_json "/$1" "$2"
}

bulk_stdin() {
  response="$(curl_es -X POST "${ELASTIC_URL}/_bulk?refresh=true" \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary @-)"
  case "${response}" in
    *'"errors":false'*) ;;
    *)
      echo "[search-seed] bulk indexing failed: ${response}" >&2
      return 1
      ;;
  esac
}

bulk_file() {
  source_file="$1"
  response="$(curl_es -X POST "${ELASTIC_URL}/_bulk?refresh=true" \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary "@${source_file}")"
  case "${response}" in
    *'"errors":false'*) ;;
    *)
      echo "[search-seed] bulk indexing failed file=${source_file}: ${response}" >&2
      return 1
      ;;
  esac
}

echo "[search-seed] waiting for ${SEARCH_VENDOR} at ${ELASTIC_URL}"
for _ in $(seq 1 180); do
  if curl_es "${ELASTIC_URL}/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl_es "${ELASTIC_URL}/_cluster/health" >/dev/null

disable_opensearch_query_insights() {
  [ "${SEARCH_VENDOR}" = "opensearch" ] || return 0
  put_json "/_cluster/settings" '{
    "persistent":{
      "search.insights.top_queries.latency.enabled":false,
      "search.insights.top_queries.cpu.enabled":false,
      "search.insights.top_queries.memory.enabled":false
    }
  }'
  curl_es -X DELETE "${ELASTIC_URL}/top_queries-*?expand_wildcards=all" >/dev/null 2>&1 || true
}

# OpenSearch 2.19 enables Query Insights latency collection by default.  Its
# local exporter would recursively index discover's own queries and make this
# deterministic corpus grow while it is being scanned.
disable_opensearch_query_insights

# Keep the seed idempotent after a container restart while touching lab-owned
# resources only.
for index in \
  redposture-logs-2026.05 \
  redposture-secrets-2026.05 \
  finance-transactions-2026.05 \
  "${CORPUS_INDEX}"
do
  curl_es -X DELETE "${ELASTIC_URL}/${index}" >/dev/null 2>&1 || true
done

echo "[search-seed] creating baseline and discover-v2 corpus indices"
put_index "redposture-logs-2026.05" '{
  "settings":{"number_of_shards":1,"number_of_replicas":0},
  "mappings":{"properties":{"@timestamp":{"type":"date"},"service":{"type":"keyword"},"env":{"type":"keyword"},"level":{"type":"keyword"},"message":{"type":"text"},"trace_id":{"type":"keyword"},"client_ip":{"type":"ip"},"latency_ms":{"type":"integer"},"attrs":{"type":"object","enabled":true}}}
}'
put_index "redposture-secrets-2026.05" '{
  "settings":{"number_of_shards":1,"number_of_replicas":0},
  "mappings":{"properties":{"owner":{"type":"keyword"},"kind":{"type":"keyword"},"value":{"type":"keyword"},"source":{"type":"keyword"},"created_at":{"type":"date"}}}
}'
put_index "finance-transactions-2026.05" '{
  "settings":{"number_of_shards":1,"number_of_replicas":0},
  "mappings":{"properties":{"transaction_id":{"type":"keyword"},"customer_id":{"type":"keyword"},"amount":{"type":"scaled_float","scaling_factor":100},"currency":{"type":"keyword"},"status":{"type":"keyword"},"metadata":{"type":"object","enabled":true}}}
}'
curl_es -X PUT "${ELASTIC_URL}/${CORPUS_INDEX}" \
  -H 'Content-Type: application/json' \
  --data-binary "@${CORPUS_DIR}/discover_corpus_mapping.json" >/dev/null

bulk_stdin <<'NDJSON'
{"index":{"_index":"redposture-logs-2026.05","_id":"log-1"}}
{"@timestamp":"2026-05-15T08:00:00Z","service":"api-gateway","env":"prod","level":"info","message":"request completed","trace_id":"9fd4f6b27f4e4b9a","client_ip":"10.20.30.40","latency_ms":42,"attrs":{"route":"/api/v1/orders","method":"GET"}}
{"index":{"_index":"redposture-logs-2026.05","_id":"log-2"}}
{"@timestamp":"2026-05-15T08:01:00Z","service":"worker","env":"prod","level":"warn","message":"retrying kafka publish","trace_id":"a7f1d30a5a884f22","client_ip":"10.20.30.41","latency_ms":980,"attrs":{"topic":"orders.events","sasl_username":"metrics","sasl_password":"metricspass"}}
{"index":{"_index":"redposture-secrets-2026.05","_id":"secret-1"}}
{"owner":"observability","kind":"api_key","value":"elastic-prod-api-key-2026","source":"kibana_saved_object","created_at":"2026-05-15T07:55:00Z"}
{"index":{"_index":"redposture-secrets-2026.05","_id":"secret-2"}}
{"owner":"payments","kind":"dsn","value":"postgresql://payments:PayDb!2026@postgres.internal:5432/payments?sslmode=require","source":"service_config","created_at":"2026-05-15T07:56:00Z"}
{"index":{"_index":"finance-transactions-2026.05","_id":"txn-1001"}}
{"transaction_id":"txn-1001","customer_id":"cust-4421","amount":1299.50,"currency":"USD","status":"settled","metadata":{"provider":"stripe","payment_ref":"pi_redposture_2026"}}
{"index":{"_index":"finance-transactions-2026.05","_id":"txn-1002"}}
{"transaction_id":"txn-1002","customer_id":"cust-8842","amount":88.10,"currency":"EUR","status":"pending","metadata":{"provider":"adyen","risk":"review"}}
NDJSON

bulk_file "${CORPUS_DIR}/discover_corpus.ndjson"

echo "[search-seed] creating discover-v2 configuration surfaces"
put_json "/_cluster/settings" '{"persistent":{"cluster.routing.allocation.exclude.password":"CorpusClusterSettingPassword!2026"}}'
put_json "/_index_template/redposture-corpus-index-template-v2" '{
  "index_patterns":["redposture-corpus-template-v2-*"],
  "priority":17,
  "template":{"mappings":{"_meta":{"client_secret":"CorpusIndexTemplateSecret!2026"}}}
}'
put_json "/_component_template/redposture-corpus-component-v2" '{
  "template":{"mappings":{"_meta":{"api_token":"CorpusComponentTemplateToken!2026"}}},
  "_meta":{"description":"RedPosture discover-v2 corpus component"}
}'
put_json "/_template/redposture-corpus-legacy-v2" '{
  "index_patterns":["redposture-corpus-legacy-v2-*"],
  "order":17,
  "mappings":{"_meta":{"client_secret":"CorpusLegacyTemplateSecret!2026"}}
}'
put_json "/_ingest/pipeline/redposture-corpus-pipeline-v2" '{
  "description":"Deterministic discover-v2 corpus pipeline",
  "processors":[{"set":{"field":"credentials.api_token","value":"CorpusPipelineToken!2026"}}],
  "on_failure":[{"set":{"field":"credentials.password","value":"CorpusPipelineFailurePassword!2026"}}]
}'

if [ "${SEARCH_VENDOR}" = "opensearch" ]; then
  put_json "/${CORPUS_INDEX}/_mapping" '{
    "derived":{"corpus_derived":{"type":"keyword","script":{"source":"emit(params.client_secret)","params":{"client_secret":"CorpusDerivedParamSecret!2026"}}}}
  }'
else
  put_json "/${CORPUS_INDEX}/_mapping" '{
    "runtime":{"corpus_runtime":{"type":"keyword","script":{"source":"emit(params.client_secret)","params":{"client_secret":"CorpusRuntimeParamSecret!2026"}}}}
  }'
fi

if [ -n "${ELASTIC_USER:-}" ]; then
  echo "[search-seed] creating least-privilege lab user"
  if [ "${SEARCH_VENDOR}" = "opensearch" ]; then
    put_json "/_plugins/_security/api/roles/redposture_observer" '{
      "cluster_permissions":["cluster_monitor"],
      "index_permissions":[
        {
          "index_patterns":["redposture-*","finance-*"],
          "allowed_actions":[
            "read",
            "indices_monitor",
            "indices:admin/mappings/get",
            "indices:admin/resolve/index"
          ]
        },
        {
          "index_patterns":["*"],
          "allowed_actions":[
            "indices_monitor",
            "indices:admin/mappings/get",
            "indices:admin/resolve/index"
          ]
        }
      ],
      "tenant_permissions":[]
    }'
    put_json "/_plugins/_security/api/internalusers/observer" '{
      "password":"V13w-Only!2026",
      "opendistro_security_roles":["redposture_observer"],
      "backend_roles":[],
      "attributes":{}
    }'
  else
    curl_es -X POST "${ELASTIC_URL}/_security/role/redposture_observer" \
      -H 'Content-Type: application/json' \
      -d '{"cluster":["monitor"],"indices":[{"names":["redposture-*","finance-*"],"privileges":["read","view_index_metadata"]}]}' >/dev/null
    curl_es -X POST "${ELASTIC_URL}/_security/user/observer" \
      -H 'Content-Type: application/json' \
      -d '{"password":"ObserverRead!2026","roles":["redposture_observer"],"full_name":"RedPosture Observer","email":"observer@example.local"}' >/dev/null
  fi
fi

disable_opensearch_query_insights
curl_es "${ELASTIC_URL}/_cat/indices?format=json" >/dev/null
echo "[search-seed] done"
touch /tmp/redposture-search-seed-ready
tail -f /dev/null
