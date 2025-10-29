#!/usr/bin/env python3
"""
uploader/healthcheck.py

Healthcheck für den Uploader-Container:
- Prüft, ob die Cowrie-NDJSON-Datei existiert und lesbar ist.
- Prüft, ob COLLECTOR_URL gesetzt, parsebar, Host DNS-auflösbar und TCP-Port erreichbar ist.
- Sendet KEINE HTTP-Requests (nur TCP connect), somit side-effect frei.

Exit codes:
  0 = OK
  1 = Fehlkonfiguration/Fehler
"""

import os
import sys
import socket
from urllib.parse import urlparse

def fail(msg):
    print(f"[HEALTHCHECK] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)

def ok(msg):
    print(f"[HEALTHCHECK] OK: {msg}")
    sys.exit(0)

def check_cowrie_json():
    path = os.environ.get("COWRIE_JSON", "/cowrie/log/cowrie.json")
    if not path:
        fail("COWRIE_JSON env not set")
    if not os.path.exists(path):
        fail(f"cowrie.json not found at {path}")
    if not os.path.isfile(path):
        fail(f"{path} exists but is not a file")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            # nur einen winzigen Read, um Rechte zu prüfen
            f.read(1)
    except Exception as e:
        fail(f"cannot read cowrie.json ({path}): {e}")

def check_collector_url():
    url = os.environ.get("COLLECTOR_URL", "")
    if not url:
        fail("COLLECTOR_URL env not set")
    try:
        parsed = urlparse(url)
    except Exception as e:
        fail(f"invalid COLLECTOR_URL parse error: {e}")

    if parsed.scheme not in ("http", "https"):
        fail(f"unsupported scheme in COLLECTOR_URL: {parsed.scheme}")

    host = parsed.hostname
    port = parsed.port
    if host is None:
        fail("no host in COLLECTOR_URL")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    # DNS-Auflösung testen
    try:
        socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception as e:
        fail(f"DNS/addrinfo failed for {host}:{port} -> {e}")

    # TCP reachability testen (kurzer connect, 2s Timeout)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((host, port))
    except Exception as e:
        fail(f"cannot connect to collector {host}:{port} -> {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    check_cowrie_json()
    check_collector_url()
    ok("cowrie.json readable & collector TCP reachable")
