#!/bin/sh
set -e

# Create out dir
mkdir -p "${OUT_DIR:-/data/out}"
mkdir -p "${PCAP_DIR:-/data/pcap}"

# Run extractor
exec python /opt/extractor/extractor.py \
  --pcap-dir "${PCAP_DIR:-/data/pcap}" \
  --cowrie-json "${COWRIE_JSON:-/cowrie/log/cowrie.json}" \
  --out-dir "${OUT_DIR:-/data/out}" \
  --sensor-id "${SENSOR_ID:-unknown}"
