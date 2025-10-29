FROM python:3.11-slim

WORKDIR /opt/uploader
COPY uploader.py /opt/uploader/uploader.py
COPY entrypoint.sh /opt/uploader/entrypoint.sh
COPY healthcheck.py /opt/healthcheck.py

RUN pip install --no-cache-dir requests python-dateutil

RUN chmod +x /opt/uploader/entrypoint.sh

ENTRYPOINT ["/opt/uploader/entrypoint.sh"]
