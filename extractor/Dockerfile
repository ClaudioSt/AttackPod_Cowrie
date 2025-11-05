FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    COWRIE_JSON=/cowrie/log/cowrie.json PCAP_DIR=/data/pcap OUT_DIR=/data/out \
    SENSOR_ID=honeypot-01 SEND_URL=http://host.docker.internal:8000/add_attack
ARG INSTALL_TSHARK=0
SHELL ["/bin/sh","-c"]

RUN set -eux; \
  apt-get update; \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates tini curl ${INSTALL_TSHARK:+tshark}; \
  rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN set -eux; python -m pip install --upgrade pip; \
  pip install --no-cache-dir scapy==2.5.0 requests==2.32.3

RUN mkdir -p /opt/extractor
COPY extractor.py /opt/extractor/extractor.py
# optional:
COPY trigger.py /app/trigger.py
COPY healthcheck.py /app/healthcheck.py

# non-root
RUN addgroup --system app && adduser --system --ingroup app --home /app app && \
    mkdir -p /data/pcap /data/out && chown -R app:app /app /data
USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD [ -f "/app/healthcheck.py" ] && python /app/healthcheck.py || exit 0

# tini as init; run python directly
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python","/opt/extractor/extractor.py"]
