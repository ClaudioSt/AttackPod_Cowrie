FROM python:3.11-slim

ARG COWRIE_REF=v2.5.0

# Tools + Build Deps + gosu zum Drop auf non-root
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates gcc build-essential libssl-dev libffi-dev libpython3-dev gosu \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone https://github.com/cowrie/cowrie.git
WORKDIR /opt/cowrie
RUN git checkout "${COWRIE_REF}" \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Non-root User anlegen (wir droppen im Entrypoint darauf)
RUN useradd -r -m -d /home/cowrie -s /usr/sbin/nologin cowrie

# Deine Configs
COPY cowrie.cfg etc/cowrie.cfg
COPY data/userdb.txt data/userdb.txt
COPY etc/banner.txt etc/banner.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Keine USER-Anweisung hier → Container startet als root und droppt später
ENV COWRIE_LOG_DIR=/cowrie/log
VOLUME ["/cowrie/log"]
EXPOSE 2222/tcp

ENTRYPOINT ["/entrypoint.sh"]
