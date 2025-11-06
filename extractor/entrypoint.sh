#!/bin/sh
set -e

# Dirs anlegen
mkdir -p "${OUT_DIR:-/data/out}"
mkdir -p "${PCAP_DIR:-/data/pcap}"

# Optionales Health-Log
echo "[entrypoint] OUT_DIR=${OUT_DIR:-/data/out} PCAP_DIR=${PCAP_DIR:-/data/pcap} COWRIE_JSON=${COWRIE_JSON:-/cowrie/log/cowrie.json}"

# Trigger starten (übernimmt das Starten des Extractors pro Session-Ende)
exec python /opt/extractor/trigger.py
