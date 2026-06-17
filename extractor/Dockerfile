FROM python:3.11-slim

# tshark fragt sonst interaktiv per debconf nach (Build würde hängen).
ENV DEBIAN_FRONTEND=noninteractive

# Systemtools: tshark (für optionales KEX/HASSH), tcpdump (falls nötig)
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends \
    tshark tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten (gepinnt für reproduzierbare Builds)
COPY requirements.txt /opt/extractor/requirements.txt
RUN pip install --no-cache-dir -r /opt/extractor/requirements.txt

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
