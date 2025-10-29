FROM python:3.11-slim

RUN apt-get update && apt-get install -y tcpdump libpcap0.8-dev build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/extractor
COPY extractor.py /opt/extractor/extractor.py
COPY entrypoint.sh /opt/extractor/entrypoint.sh
COPY healthcheck.py /opt/healthcheck.py

RUN pip install --no-cache-dir scapy==2.5.0 pygeoip python-dateutil

RUN chmod +x /opt/extractor/entrypoint.sh

ENTRYPOINT ["/opt/extractor/entrypoint.sh"]
