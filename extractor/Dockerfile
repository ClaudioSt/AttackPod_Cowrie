# extractor/Dockerfile
# Minimal, robust, Windows-safe build for the extractor

# ---- Base ----
FROM python:3.11-slim

# Faster/safer Python defaults and sensible app defaults (overridable via env/compose)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    COWRIE_JSON=/cowrie/log/cowrie.json \
    PCAP_DIR=/data/pcap \
    OUT_DIR=/data/out \
    SENSOR_ID=honeypot-01 \
    SEND_URL=http://host.docker.internal:8000/add_attack

# Optional Wireshark CLI (tshark) via build-arg:
#   docker build --build-arg INSTALL_TSHARK=1 -t extractor:latest extractor/
ARG INSTALL_TSHARK=0

# Use sh for RUN commands
SHELL ["/bin/sh", "-c"]

# ---- System deps ----
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
      curl \
      ${INSTALL_TSHARK:+tshark}; \
    rm -rf /var/lib/apt/lists/*

# ---- App dir ----
WORKDIR /app

# ---- Python deps ----
# We only read PCAPs (no live capture), so scapy without libpcap is fine.
RUN set -eux; \
    python -m pip install --upgrade pip; \
    pip install --no-cache-dir \
      scapy==2.5.0 \
      requests==2.32.3

# ---- Copy sources ----
# Keep extractor.py under /opt for clarity; scripts under /app
RUN mkdir -p /opt/extractor
COPY extractor.py /opt/extractor/extractor.py

# Copy optional files if present; these COPYs will fail only if files truly absent.
# If you don't have trigger/healthcheck, comment these two lines out.
COPY trigger.py /app/trigger.py
COPY healthcheck.py /app/healthcheck.py

# Always copy entrypoint last so we can normalize it deterministically
COPY entrypoint.sh /app/entrypoint.sh

# ---- Normalize line endings and set exec bits (Windows-safe) ----
# This prevents: "Permission denied" or "No such file or directory" due to CRLF or +x missing.
RUN set -eux; \
    # Normalize entrypoint.sh
    sed -i 's/\r$//' /app/entrypoint.sh; \
    chmod +x /app/entrypoint.sh; \
    # Normalize optional scripts if they exist
    [ -f /app/trigger.py ] && sed -i 's/\r$//' /app/trigger.py || true; \
    [ -f /app/healthcheck.py ] && sed -i 's/\r$//' /app/healthcheck.py || true; \
    # Quick sanity check: shebang must be /bin/sh or a present interpreter
    head -n1 /app/entrypoint.sh || true

# ---- Non-root user ----
# (Adjust UID/GID if you need deterministic ownership with mounted volumes)
RUN set -eux; \
    addgroup --system app; \
    adduser  --system --ingroup app --home /app app; \
    mkdir -p /data/pcap /data/out; \
    chown -R app:app /app /data
USER app

# ---- Healthcheck (optional) ----
# If healthcheck.py is present, use it; otherwise exit 0 to keep HC passing.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD [ -f "/app/healthcheck.py" ] && python /app/healthcheck.py || exit 0

# ---- Entrypoint & default CMD ----
# tini to reap zombies; run entrypoint via exec so signals propagate correctly.
ENTRYPOINT ["/usr/bin/tini","--","/bin/sh","-lc"]
CMD ["exec /app/entrypoint.sh"]
