# extractor/Dockerfile
# Minimal, sicher & reproduzierbar

# ---- Base ----
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # sinnvolle Defaults; via Compose/ENV überschreiben
    COWRIE_JSON=/cowrie/log/cowrie.json \
    PCAP_DIR=/data/pcap \
    OUT_DIR=/data/out \
    SENSOR_ID=honeypot-01 \
    SEND_URL=http://host.docker.internal:8000/add_attack

# Optionale Installation von tshark steuerbar:
# docker build --build-arg INSTALL_TSHARK=1 -t extractor:latest extractor/
ARG INSTALL_TSHARK=0

# System deps für Build & Runtime (ohne unnötigen Ballast)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
      curl \
      # für optionales tshark
      ${INSTALL_TSHARK:+tshark} \
    && rm -rf /var/lib/apt/lists/*

# ---- App Verzeichnis ----
WORKDIR /app

# ---- Python deps ----
# Pinne Versionen für Reproduzierbarkeit
# (Scapy reicht ohne libpcap, da wir nur PCAPs lesen; live-capture ist nicht nötig)
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir \
      scapy==2.5.0 \
      requests==2.32.3

# ---- Dateien kopieren ----
# Erwartet deine Struktur:
# extractor/
#   ├─ Dockerfile
#   ├─ entrypoint.sh
#   ├─ extractor.py
#   ├─ trigger.py        (neu, falls verwendet)
#   └─ healthcheck.py    (optional)
RUN mkdir -p /opt/extractor
COPY extractor.py /opt/extractor/extractor.py
COPY entrypoint.sh /app/entrypoint.sh
# Trigger & Healthcheck sind optional – kopiere, wenn vorhanden
COPY trigger.py /app/trigger.py
COPY healthcheck.py /app/healthcheck.py

# Skripte ausführbar machen
RUN chmod +x /app/entrypoint.sh && \
    [ -f /app/trigger.py ] && chmod +x /app/trigger.py || true && \
    [ -f /app/healthcheck.py ] && chmod +x /app/healthcheck.py || true

# ---- Nicht-root User ----
RUN addgroup --system app && adduser --system --ingroup app --home /app app && \
    mkdir -p /data/pcap /data/out && chown -R app:app /app /data
USER app

# ---- Healthcheck (optional) ----
# Wenn /app/healthcheck.py existiert, prüft er z. B. Pfade & Schreibrechte.
# Du hast auch eine healthcheck.py in deiner Struktur – sonst kannst du die Zeilen entfernen.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD [ -f "/app/healthcheck.py" ] && python /app/healthcheck.py || exit 0

# ---- Entrypoint & Default CMD ----
# tini als Signal-Reaper
ENTRYPOINT ["/usr/bin/tini", "--"]

# Standardmäßig startet der "klassische" Extractor-Loop aus entrypoint.sh.
# Für den Session-Trigger überschreibst du im docker-compose das command:
#   command: ["python", "/app/trigger.py"]
CMD ["/app/entrypoint.sh"]
