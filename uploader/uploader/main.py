import os, sys, time, hmac, hashlib, requests, json
from typing import List
from .io_cowrie import follow_json_lines  # stellt sicher, dass diese Funktion existiert!

COLLECTOR_URL = os.getenv("COLLECTOR_URL", "http://host.docker.internal:8000/add_attack")
CLIENT_ID     = os.getenv("CLIENT_ID", "edge-dev-001")
API_KEY       = os.getenv("API_KEY", "dev-replace-me")
SOURCE_LOG    = os.getenv("SOURCE_LOG", "/cowrie/log/cowrie.json")

BATCH_MAX_EVENTS  = int(os.getenv("BATCH_MAX_EVENTS", "500"))
BATCH_MAX_BYTES   = int(os.getenv("BATCH_MAX_BYTES",  "5242880"))
BATCH_MAX_SECONDS = float(os.getenv("BATCH_MAX_SECONDS", "2"))
DEBUG = os.getenv("UPLOADER_DEBUG", "1") not in ("0","false","False","no","No")

def log(msg: str): 
    print(f"[uploader] {msg}", flush=True)

def sign_payload(ndjson_bytes: bytes) -> str:
    sig = hmac.new(API_KEY.encode("utf-8"), ndjson_bytes, hashlib.sha256).hexdigest()
    return "v1=" + sig

def flush(batch: List[str]):
    if not batch:
        return
    payload = ("\n".join(batch) + "\n").encode("utf-8")
    headers = {
        "Content-Type": "application/x-ndjson",
        "X-Client-ID": CLIENT_ID,
        "X-API-Key": API_KEY,
        "X-Payload-Signature": sign_payload(payload),
    }
    try:
        r = requests.post(COLLECTOR_URL, data=payload, headers=headers, timeout=10)
        log(f"POST {COLLECTOR_URL} -> {r.status_code} ({len(payload)} bytes)")
        if r.status_code >= 300 and DEBUG:
            log(f"RESP: {r.text[:400]}")
    except Exception as e:
        log(f"ERROR sending batch: {e}")

def main():
    log(f"watching: {SOURCE_LOG}")
    if not os.path.exists(SOURCE_LOG):
        log("WARN: source file does not exist yet; waiting...")
        while not os.path.exists(SOURCE_LOG):
            time.sleep(0.5)

    batch, batch_bytes, last_flush = [], 0, time.time()
    for obj in follow_json_lines(SOURCE_LOG, sleep=0.2):
        try:
            line = json.dumps(obj, separators=(",", ":"))
        except Exception:
            # Falls obj schon String ist
            line = str(obj)

        batch.append(line)
        batch_bytes += len(line) + 1
        now = time.time()
        if (len(batch) >= BATCH_MAX_EVENTS) or (batch_bytes >= BATCH_MAX_BYTES) or (now - last_flush >= BATCH_MAX_SECONDS):
            flush(batch)
            batch.clear()
            batch_bytes = 0
            last_flush = now

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped.")
