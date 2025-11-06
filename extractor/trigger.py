#!/usr/bin/env python3
import os, sys, time, json, shlex, subprocess
from datetime import datetime, timezone, timedelta

COWRIE_JSON = os.getenv("COWRIE_JSON", "/cowrie/log/cowrie.json")
PCAP_DIR    = os.getenv("PCAP_DIR", "/data/pcap")
OUT_DIR     = os.getenv("OUT_DIR", "/data/out")
SEND_URL    = os.getenv("SEND_URL", "")  # leer = nur Dateien schreiben
API_KEY     = os.getenv("API_KEY", "")
EXTRACTOR_BIN = os.getenv("EXTRACTOR_BIN", "python /app/extractor.py")
USE_TSHARK = os.getenv("USE_TSHARK", "0") in ("1","true","True","yes")

def log(msg): print(f"[trigger] {msg}", flush=True)

def iso_to_utc_naive(s):
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None

def tail_reopen(path):
    pos = 0; inode = None; f = None
    while True:
        try:
            st = os.stat(path)
            if inode != st.st_ino:
                if f: f.close()
                f = open(path, "r", encoding="utf-8", errors="ignore")
                inode = st.st_ino
                f.seek(0, os.SEEK_END)
                pos = f.tell()
            else:
                f.seek(pos)
            line = f.readline()
            if line:
                pos = f.tell()
                yield line
            else:
                time.sleep(0.2)
        except FileNotFoundError:
            time.sleep(0.5)
        except Exception as e:
            log(f"tail error: {e}"); time.sleep(0.5)

def run_extractor_for(sid, sess):
    first = sess.get("first") or datetime.utcnow()
    last  = sess.get("last")  or datetime.utcnow()
    start = (first - timedelta(seconds=5)).isoformat(timespec="seconds") + "Z"
    end   = (last  + timedelta(seconds=5)).isoformat(timespec="seconds") + "Z"

    flow_arg = ""
    if sess.get("src_ip") and sess.get("dst_ip") and sess.get("src_port") and sess.get("dst_port"):
        flow_arg = f' --flow "{sess["src_ip"]}:{sess["src_port"]}->{sess["dst_ip"]}:{sess["dst_port"]}" '

    cmd = (
        f"{EXTRACTOR_BIN}"
        f" --pcap-dir {shlex.quote(PCAP_DIR)}"
        f" --cowrie-json {shlex.quote(COWRIE_JSON)}"
        f" --out-dir {shlex.quote(OUT_DIR)}"
        f" --only-session {shlex.quote(sid)}"
        f"{flow_arg}"
        f' --time-window "{start},{end}"'
        + (" --send-url " + shlex.quote(SEND_URL) if SEND_URL else "")
        + (" --api-key " + shlex.quote(API_KEY) if (SEND_URL and API_KEY) else "")
        + (" --use-tshark" if USE_TSHARK else "")
    )
    log(f"exec: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=False)
    except Exception as e:
        log(f"extractor failed: {e}")

def main():
    log(f"watching {COWRIE_JSON}")
    s_cache = {}
    for line in tail_reopen(COWRIE_JSON):
        line = line.strip()
        if not line: continue
        try:
            ev = json.loads(line)
        except Exception:
            continue

        sid = ev.get("session")
        if not sid: continue
        eventid = ev.get("eventid", "")
        ts_raw = ev.get("timestamp") or ev.get("time") or ev.get("@timestamp")
        ts = iso_to_utc_naive(ts_raw) if ts_raw else None

        entry = s_cache.get(sid, {})
        if ts:
            if not entry.get("first") or ts < entry["first"]:
                entry["first"] = ts
            if not entry.get("last") or ts > entry["last"]:
                entry["last"] = ts
        for k in ("src_ip","src_port","dst_ip","dst_port"):
            if ev.get(k) is not None and not entry.get(k):
                entry[k] = ev.get(k)
        s_cache[sid] = entry

        if eventid == "cowrie.session.closed":
            run_extractor_for(sid, entry)
            s_cache.pop(sid, None)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopping")
