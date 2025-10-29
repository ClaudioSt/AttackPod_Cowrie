#!/usr/bin/env python3
"""
extractor.py

- Beobachtet PCAP-Ordner für neue Dateien (Dateinamenschema ssh-<ts>.pcap)
- Verarbeitet jede pcap atomar (rename .processing -> process -> .done)
- Extrahiert Sessions mit TCP (Port 22) und produziert JSON-Session-Objekte
- Liest cowrie.json (NDJSON) und verknüpft Events mit sessions via src_ip/src_port/timestamps
- Schreibt merged_sessions.json (Gesamtliste)
"""

import os
import sys
import time
import json
import argparse
import hashlib
import shutil
import statistics
from datetime import datetime, timezone
from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict

# --- Helpers ---
def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

def median_or_none(vals):
    return statistics.median(vals) if vals else None

def mean_or_none(vals):
    return statistics.mean(vals) if vals else None

# --- PCAP processing ---
def process_pcap(pcap_path, sensor_id):
    sessions = {}
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"[WARN] Could not read pcap {pcap_path}: {e}", file=sys.stderr)
        return []

    # Group by 4-tuple (src,dst,srcport,dstport) normalized (client->server)
    sess_pkts = defaultdict(list)
    for p in pkts:
        if IP in p and TCP in p:
            ip = p[IP]
            tcp = p[TCP]
            # Only consider SSH traffic (port 22 either side)
            if tcp.sport != 22 and tcp.dport != 22:
                continue
            # Normalize: client has non-22 src port typically
            if tcp.dport == 22:
                client = (ip.src, tcp.sport)
                server = (ip.dst, tcp.dport)
            else:
                client = (ip.dst, tcp.dport)
                server = (ip.src, tcp.sport)
            key = (client[0], client[1], server[0], server[1])
            sess_pkts[key].append(p)

    results = []
    for (c_ip,c_port,s_ip,s_port), pkts in sess_pkts.items():
        timestamps = [float(p.time) for p in pkts]
        timestamps.sort()
        first_seen = timestamps[0]
        last_seen = timestamps[-1]
        duration = last_seen - first_seen
        pkt_count = len(pkts)
        bytes_total = sum(len(p) for p in pkts)
        # IATs
        iats = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        iat_mean = mean_or_none(iats)
        iat_median = median_or_none(iats)
        # TTLs & windows
        ttls = [int(p[IP].ttl) for p in pkts if IP in p]
        wins = [int(p[TCP].window) for p in pkts if TCP in p]
        ttl_median = median_or_none(ttls)
        win_median = median_or_none(wins)
        # TCP flags stats
        flags = [p[TCP].flags for p in pkts]
        flag_counts = {}
        for f in flags:
            flag_counts[str(f)] = flag_counts.get(str(f), 0) + 1
        # Retransmissions heuristic: duplicate seq numbers from same side
        seqs = defaultdict(set)
        retrans = 0
        for p in pkts:
            t = p[TCP]
            side = 'c' if (p[IP].src == c_ip and p[TCP].sport == c_port) else 's'
            seq = int(t.seq)
            if seq in seqs[side]:
                retrans += 1
            else:
                seqs[side].add(seq)

        # Extract ASCII payload sequences and initial banners (simple)
        payloads = []
        banner_client = None
        banner_server = None
        concatenated = b""
        for p in pkts:
            if Raw in p:
                b = bytes(p[Raw].load)
                concatenated += b
                try:
                    s = b.decode('utf-8', errors='ignore')
                except Exception:
                    s = ''
                if 'SSH-' in s:
                    # naive banner find
                    if p[IP].src == c_ip and banner_client is None:
                        idx = s.find('SSH-')
                        banner_client = s[idx:].splitlines()[0]
                    if p[IP].src == s_ip and banner_server is None:
                        idx = s.find('SSH-')
                        banner_server = s[idx:].splitlines()[0]
                # collect ASCII substrings > 4 chars
                ascii_seq = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
                if len(ascii_seq) >= 4:
                    payloads.append(ascii_seq)

        # Heuristic: compute "hassh-like" value as hash of concatenated kex-like strings found
        # Try to parse comma-separated lists in concatenated payload
        kex_candidates = []
        try:
            text = concatenated.decode('utf-8', errors='ignore')
            # look for occurrences like "kex_algorithms: ...", naive
            # or find long comma-separated tokens (kex,enc,mac,comp)
            import re
            combos = re.findall(r'([A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+){2,20})', text)
            for c in combos:
                if any(x in c.lower() for x in ['diffie-','ecdh','rsa','curve25519','aes']):
                    kex_candidates.append(c)
        except Exception:
            pass
        hassh = None
        if kex_candidates:
            hassh = sha256_hex(','.join(kex_candidates).encode('utf-8'))[:64]
        else:
            # fallback: hash of first 2KB of concatenated payload
            hassh = sha256_hex(concatenated[:2048])[:64] if concatenated else None

        session_obj = {
            "sensor_id": sensor_id,
            "pcap_file": os.path.basename(pcap_path),
            "src_ip": c_ip,
            "src_port": c_port,
            "dst_ip": s_ip,
            "dst_port": s_port,
            "first_seen": iso(first_seen),
            "last_seen": iso(last_seen),
            "duration": duration,
            "packet_count": pkt_count,
            "bytes": bytes_total,
            "iat_mean": iat_mean,
            "iat_median": iat_median,
            "ttl_median": ttl_median,
            "tcp_window_median": win_median,
            "tcp_flag_counts": flag_counts,
            "retransmissions": retrans,
            "payload_ascii_sequences": payloads[:20],
            "client_banner": banner_client,
            "server_banner": banner_server,
            "hassh": hassh,
        }
        results.append(session_obj)

    return results

# --- PCAP file watcher/consumer ---
def atomic_process_file(path, process_fn, sensor_id):
    # move file to .processing atomically
    base = os.path.basename(path)
    dirn = os.path.dirname(path)
    processing = os.path.join(dirn, base + ".processing")
    done = os.path.join(dirn, base + ".done")
    try:
        os.rename(path, processing)
    except Exception as e:
        print(f"[INFO] Could not rename {path} -> skip (maybe in use): {e}")
        return []
    try:
        res = process_fn(processing, sensor_id)
        # persist results next to processed outputs
        return res
    finally:
        # mark done
        try:
            os.rename(processing, done)
        except Exception as e:
            print(f"[WARN] could not rename processed file: {e}")

# --- Cowrie NDJSON loader ---
def load_cowrie_events(cowrie_json_path):
    events = []
    if not os.path.exists(cowrie_json_path):
        return events
    try:
        with open(cowrie_json_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    except Exception as e:
        print(f"[WARN] Could not read cowrie.json: {e}")
    return events

def link_sessions_with_events(sessions, events):
    # naive linking by src_ip and time overlap
    for s in sessions:
        s['linked_cowrie_events'] = []
        for ev in events:
            try:
                src_ip = ev.get('src_ip') or ev.get('src_host') or ev.get('src_addr')
                when = ev.get('timestamp') or ev.get('time') or ev.get('timestamp_iso')
                if not when:
                    continue
                # parse when if numeric or iso
                if isinstance(when, (int,float)):
                    wt = when
                else:
                    try:
                        wt = datetime.fromisoformat(when.replace('Z','+00:00')).timestamp()
                    except Exception:
                        continue
                # compare
                first = datetime.fromisoformat(s['first_seen']).timestamp()
                last = datetime.fromisoformat(s['last_seen']).timestamp()
                if src_ip == s['src_ip'] and first - 5 <= wt <= last + 5:
                    s['linked_cowrie_events'].append(ev)
            except Exception:
                continue
    return sessions

# --- Main runner ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--cowrie-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--sensor-id", default="unknown")
    parser.add_argument("--scan-interval", type=int, default=15)
    args = parser.parse_args()

    pcap_dir = args.pcap_dir
    out_dir = args.out_dir
    cowrie_json = args.cowrie_json
    sensor_id = args.sensor_id

    os.makedirs(out_dir, exist_ok=True)

    merged_out = os.path.join(out_dir, "merged_sessions.json")

    while True:
        try:
            # scan pcaps
            pcaps = sorted([os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir)
                            if f.endswith(".pcap")])
        except Exception:
            pcaps = []

        all_sessions = []
        for p in pcaps:
            if p.endswith(".processing") or p.endswith(".done"):
                continue
            try:
                sess = atomic_process_file(p, process_pcap, sensor_id)
                if sess:
                    all_sessions.extend(sess)
            except Exception as e:
                print(f"[ERROR] processing {p}: {e}", file=sys.stderr)

        # load cowrie events
        events = load_cowrie_events(cowrie_json)

        # link
        all_sessions = link_sessions_with_events(all_sessions, events)

        # load existing merged and append
        existing = []
        if os.path.exists(merged_out):
            try:
                with open(merged_out, 'r') as fh:
                    existing = json.load(fh)
            except Exception:
                existing = []

        if all_sessions:
            combined = existing + all_sessions
            # write atomically
            tmp = merged_out + ".tmp"
            with open(tmp, 'w') as fh:
                json.dump(combined, fh, indent=2)
            os.replace(tmp, merged_out)
            print(f"[INFO] Wrote {len(all_sessions)} sessions to {merged_out}")
        time.sleep(args.scan_interval)

if __name__ == "__main__":
    main()
