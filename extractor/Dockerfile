FROM python:3.11-slim

# Systemtools: tshark (für optionales KEX/HASSH), tcpdump (falls nötig)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten
RUN pip install --no-cache-dir scapy requests

# Files
WORKDIR /opt/extractor
COPY extractor.py /opt/extractor/extractor.py
COPY trigger.py   /opt/extractor/trigger.py
COPY healthcheck.py /opt/extractor/healthcheck.py
COPY entrypoint.sh /opt/extractor/entrypoint.sh
RUN chmod +x /opt/extractor/entrypoint.sh

ENV COWRIE_JSON=/cowrie/log/cowrie.json \
    PCAP_DIR=/data/pcap \
    OUT_DIR=/data/out

ENTRYPOINT ["/opt/extractor/entrypoint.sh"]
