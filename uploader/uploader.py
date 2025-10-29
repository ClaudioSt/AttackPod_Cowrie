#!/usr/bin/env python3
"""
uploader.py

- Tails a NDJSON cowrie log file robustly (reopen on inode change)
- Batches events by count/bytes/time
- Signs each POST body with HMAC-SHA256 header X-Payload-Signature: v1=<hex>
- Retries with exponential backoff on transient errors
- Rate-limits outgoing posts (simple token-bucket / per-minute limiter)
"""

import os
import sys
import time
import json
import argparse
import hashlib
import hmac
import requests
from datetime import datetime, timezone

# --- Helpers ---
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def compute_hmac(api_key, body_bytes):
    mac = hmac.new(api_key.encode('utf-8'), body_bytes, hashlib.sha256).hexdigest()
    return f"v1={mac}"

# --- File tail that reopens on rotation/inode change ---
class NDJSONTail:
    def __init__(self, path):
        self.path = path
        self._fh = None
        self._inode = None
        self._pos = 0
        self.open()

    def open(self):
        # wait until file exists (do NOT create; mount may be read-only)
        while not os.path.exists(self.path):
            time.sleep(1)
        fh = open(self.path, 'r', encoding='utf-8', errors='ignore')
        st = os.fstat(fh.fileno())
        self._inode = (st.st_dev, st.st_ino)
        self._fh = fh
        # start at end (we want new events)
        fh.seek(0, os.SEEK_END)
        self._pos = fh.tell()

    def close(self):
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def check_reopen(self):
        try:
            cur = os.stat(self.path)
            cur_inode = (cur.st_dev, cur.st_ino)
            if cur_inode != self._inode:
                try:
                    self.close()
                finally:
                    self.open()
        except FileNotFoundError:
            # file removed/rotated and not yet re-created: wait and reopen
            time.sleep(1)
            self.open()

    def tail_lines(self):
        while True:
            self.check_reopen()
            line = self._fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip('\n')

# --- Batching & sending ---
class RateLimiter:
    def __init__(self, per_min):
        self.per_min = per_min
        self.allowance = per_min
        self.last_check = time.time()

    def allow(self, tokens=1):
        now = time.time()
        elapsed = now - self.last_check
        self.last_check = now
        self.allowance += elapsed * (self.per_min / 60.0)
        if self.allowance > self.per_min:
            self.allowance = self.per_min
        if self.allowance >= tokens:
            self.allowance -= tokens
            return True
        return False

def post_with_retry(url, headers, data, rate_limiter, max_retries=5):
    # Respect rate limiter
    if not rate_limiter.allow():
        return False, "rate_limited"

    attempt = 0
    while attempt <= max_retries:
        try:
            resp = requests.post(url, headers=headers, data=data, timeout=10)
            if 200 <= resp.status_code < 300:
                return True, resp.text
            elif resp.status_code >= 500:
                # server error -> retry
                attempt += 1
                sleep = (2 ** attempt) + (0.1 * attempt)
                time.sleep(sleep)
                continue
            else:
                # client error -> do not retry
                return False, f"status_{resp.status_code}:{resp.text}"
        except requests.RequestException:
            attempt += 1
            sleep = (2 ** attempt) + (0.2 * attempt)
            time.sleep(sleep)
            continue
    return False, "max_retries_exceeded"

def run_tail_and_upload(args):
    tail = NDJSONTail(args.cowrie_json)
    buffer = []
    buffer_bytes = 0
    last_flush = time.time()
    rate_limiter = RateLimiter(args.rate_limit)

    for line in tail.tail_lines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except Exception:
            # skip malformed lines
            continue
        # add metadata
        ev['_sensor_id'] = args.sensor_id
        ev['_collected_at'] = now_iso()
        b = (json.dumps(ev) + "\n").encode('utf-8')
        buffer.append(ev)
        buffer_bytes += len(b)

        now = time.time()
        # flush conditions
        if (len(buffer) >= args.batch_count) or (buffer_bytes >= args.batch_bytes) or (now - last_flush >= args.batch_seconds):
            # prepare payload
            payload = "".join(json.dumps(x) + "\n" for x in buffer).encode('utf-8')
            sig = compute_hmac(args.api_key, payload)
            headers = {
                "Content-Type": "application/x-ndjson",
                "X-Payload-Signature": sig
            }
            ok, info = post_with_retry(args.collector_url, headers, payload, rate_limiter)
            if ok:
                print(f"[{now_iso()}] POST OK count={len(buffer)} bytes={len(payload)}")
            else:
                print(f"[{now_iso()}] POST FAIL count={len(buffer)} err={info}", file=sys.stderr)
            # reset
            buffer = []
            buffer_bytes = 0
            last_flush = now

# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cowrie-json", required=True)
    parser.add_argument("--collector-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--sensor-id", default="unknown")
    parser.add_argument("--batch-count", type=int, default=100)
    parser.add_argument("--batch-bytes", type=int, default=256*1024)
    parser.add_argument("--batch-seconds", type=int, default=5)
    parser.add_argument("--rate-limit", type=int, default=60)
    args = parser.parse_args()

    # normalize field names
    args.batch_count = int(args.batch_count)
    args.batch_bytes = int(args.batch_bytes)
    args.batch_seconds = int(args.batch_seconds)
    args.rate_limit = int(args.rate_limit)

    # wait until the log file exists (do NOT create; volume is read-only)
    while not os.path.exists(args.cowrie_json):
        print(f"[{now_iso()}] waiting for log file {args.cowrie_json} ...")
        time.sleep(1)

    run_tail_and_upload(args)

if __name__ == "__main__":
    main()
