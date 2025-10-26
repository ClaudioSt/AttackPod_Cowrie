FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY extract_pcap_features.py /app/
RUN pip install --no-cache-dir scapy python-dateutil

# Default: einmal durchlaufen und Ergebnis schreiben
CMD ["python", "/app/extract_pcap_features.py"]
