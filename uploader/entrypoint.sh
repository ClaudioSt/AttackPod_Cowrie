#!/bin/sh
set -e
exec python /opt/uploader/uploader.py \
  --cowrie-json "${COWRIE_JSON:-/cowrie/log/cowrie.json}" \
  --collector-url "${COLLECTOR_URL}" \
  --api-key "${API_KEY}" \
  --sensor-id "${SENSOR_ID}" \
  --batch-count "${BATCH_MAX_COUNT:-100}" \
  --batch-bytes "${BATCH_MAX_BYTES:-262144}" \
  --batch-seconds "${BATCH_MAX_SECONDS:-5}" \
  --rate-limit "${RATE_LIMIT_POSTS_PER_MIN:-60}"
