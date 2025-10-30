#!/usr/bin/env python3
"""
extractor.py

Liest PCAPs und Cowrie-NDJSON, erzeugt pro TCP-Session ein
reichhaltiges JSON-Objekt mit Fingerprints und einer Liste
aller Login-Versuche (aus Cowrie). Optional POST zum Collector
mit HMAC-Signatur (wenn API_KEY gesetzt).

Usage:
  python extractor.py --pcap-dir /data/pcap --cowrie-json /cowrie/log/cowrie.json \
    --out-dir /data/out --sensor-id honeypot-01 --send-url http://host.docker.internal:8000/add_attack

Wichtig: Das Script arbeitet dateiweise: neue PCAPs werden ausgewertet,
Output wird in merged_sessions.json im out-dir angehängt.
"""

import os
import sys
import time
import json
import argparse
import statistics
import re
import hashlib
import hmac
from datetime import datetime, timezone
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except Exception as e:
    print("scapy import failed:", e)
    print("Install with: pip install scapy")
    sys.exit(1)

try:
    import requests
except Exception:
    requests = None

ISO_TZ = timezone.utc

def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=ISO_TZ).isoformat()

def now_iso():
    return iso(time.time())

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def hmac_sha256_hex(key: str, data: bytes) -> str:
    return hmac.new(key.encode('utf-8'), data, digestmod=hashlib.sha256).hexdigest()

def list_pcaps(pcap_dir):
    files = []
    for fn in os.listdir(pcap_dir):
        if fn.endswith(".pcap") and not fn.endswith(".processing"):
            files.append(os.path.join(pcap_dir, fn))
    files.sort()
    return files

def load_cowrie_events(cowrie_json_path):
    """
    Load NDJSON cowrie events into memory as a list of dicts with parsed timestamps.
    Keep relevant fields: eventid, timestamp, src_ip, src_port, username, password, success, session
    """
    events = []
    if not os.path.exists(cowrie_json_path):
        return events
    with open(cowrie_json_path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            ts = None
            # look for "timestamp" or "time" or "@timestamp"
            for k in ("timestamp", "time", "@timestamp"):
                if k in ev:
                    try:
                        # ISO parse tolerant: if numeric epoch use float, else keep as string
                        if isinstance(ev[k], (int, float)):
                            ts = float(ev[k])
                        else:
                            # try to parse
                            try:
                                dt = datetime.fromisoformat(ev[k])
                                ts = dt.replace(tzinfo=ISO_TZ).timestamp()
                            except Exception:
                                ts = None
                    except Exception:
                        ts = None
                    break
            # Fall-back: use file modify time? skip - leave ts None
            ev['_ts_float'] = ts
            # normalize useful fields
            ev['_eventid'] = ev.get('eventid') or ev.get('event') or None
            ev['_src_ip'] = ev.get('src_ip') or ev.get('src') or ev.get('host') or ev.get('peer') or None
            ev['_src_port'] = ev.get('src_port') or ev.get('src_port')
            ev['_username'] = ev.get('username') or ev.get('user') or ev.get('user_input')
            ev['_password'] = ev.get('password') or ev.get('passwd') or ev.get('password_input')
            # for cowrie login events, success is sometimes eventid 'cowrie.login.success'
            ev['_success'] = 'success' in (ev.get('eventid','') or '') or ev.get('success') is True
            events.append(ev)
    return events

def find_login_attempts_for_session(events, session_first_ts, session_last_ts, session_src_ip):
    """
    Return list of login attempts (dicts) from cowrie events that match src_ip and time window.
    "
    session_first_ts/last_ts may be None -> match by ip only
    """
    attempts = []
    for ev in events:
        ts = ev.get('_ts_float')
        ip = ev.get('_src_ip')
        if session_src_ip and ip and session_src_ip != ip:
            continue
        if ts is not None and session_first_ts is not None and session_last_ts is not None:
            # include events overlapping session +/- 5s
            if not (session_first_ts - 5 <= ts <= session_last_ts + 5):
                continue
        # pick login-like events
        evid = ev.get('_eventid') or ''
        if evid and ('login' in evid or 'authentication' in evid or 'username' in ev or 'password' in ev):
            attempts.append({
                'timestamp': iso(ts) if ts else None,
                'eventid': ev.get('_eventid'),
                'username': ev.get('_username'),
                'password': ev.get('_password'),
                'success': ev.get('_success', False),
                'raw': {k: ev.get(k) for k in ('src_ip','dst_ip','session','sessionid') if k in ev}
            })
    # sort by timestamp
    attempts.sort(key=lambda x: x.get('timestamp') or '')
    return attempts

def tcp_flags_str(flags):
    # flags is int or str -> try to normalize to letters (S, A, F, P, R)
    if isinstance(flags, str):
        return flags
    # scapy flag bits -> string
    try:
        # use scapy representation if exists
        return str(flags)
    except Exception:
        return str(flags)

def analyze_session(pkts):
    """
    Given a list of scapy packets belonging to a 5-tuple flow, produce metrics dict.
    """
    if not pkts:
        return {}
    times = [float(p.time) for p in pkts]
    first = min(times)
    last = max(times)
    duration = last - first if last >= first else 0.0
    packet_count = len(pkts)
    total_bytes = sum(len(bytes(p)) for p in pkts)
    # inter-arrival
    times_sorted = sorted(times)
    iats = [t2 - t1 for t1, t2 in zip(times_sorted, times_sorted[1:])] if len(times_sorted) >= 2 else []
    iat_mean = float(statistics.mean(iats)) if iats else 0.0
    iat_median = float(statistics.median(iats)) if iats else 0.0
    # TTLs and window sizes
    ttls = []
    wins = []
    tcp_options = []
    flag_counts = Counter()
    seq_seen = set()
    retrans = 0
    payload_ascii_sequences = []
    concatenated = b""
    client_banner = None
    server_banner = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    # To collect SYN options (first SYN from each side)
    seen_syn_from = set()
    for p in pkts:
        if IP in p:
            ttls.append(int(p[IP].ttl))
            if src_ip is None:
                src_ip = p[IP].src
                dst_ip = p[IP].dst
        if TCP in p:
            tcp = p[TCP]
            wins.append(int(tcp.window))
            flags = tcp.flags
            # scapy may show flags as int or string - coerce to string simple
            flag_counts[str(flags)] += 1
            # seq-based retrans detection
            seq = int(tcp.seq)
            if seq in seq_seen:
                retrans += 1
            else:
                seq_seen.add(seq)
            # options
            if tcp.flags & 0x02:  # SYN bit
                who = (p[IP].src, tcp.sport)
                if who not in seen_syn_from:
                    seen_syn_from.add(who)
                    try:
                        opts = tcp.options
                        tcp_options.append(tuple(opts))
                    except Exception:
                        pass
            if tcp.sport and src_port is None:
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
        if Raw in p:
            b = bytes(p[Raw].load)
            concatenated += b
            try:
                s = b.decode('utf-8', errors='ignore')
            except Exception:
                s = ''
            # detect SSH banners like "SSH-2.0-OpenSSH..."
            if 'SSH-' in s:
                idx = s.find('SSH-')
                # deduce direction via ips
                if p[IP].src == src_ip and client_banner is None:
                    client_banner = s[idx:].splitlines()[0]
                if p[IP].src == dst_ip and server_banner is None:
                    server_banner = s[idx:].splitlines()[0]
            ascii_seq = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
            if len(ascii_seq) >= 4:
                payload_ascii_sequences.append(ascii_seq)
    # aggregate tcp_options into simpler representation
    tcp_options_repr = []
    for o in tcp_options:
        try:
            # o is list of tuples [('MSS',1460), ...]
            pair_list = []
            for item in o:
                if isinstance(item, tuple) and len(item) >= 1:
                    pair_list.append((str(item[0]), item[1] if len(item) > 1 else None))
            tcp_options_repr.append(pair_list)
        except Exception:
            continue

    metrics = {
        'first_seen': iso(first),
        'last_seen': iso(last),
        'duration': round(duration, 6),
        'packet_count': packet_count,
        'bytes': total_bytes,
        'iat_mean': round(iat_mean, 6),
        'iat_median': round(iat_median, 6),
        'ttl_median': int(statistics.median(ttls)) if ttls else None,
        'tcp_window_median': int(statistics.median(wins)) if wins else None,
        'tcp_options': tcp_options_repr,
        'tcp_flag_counts': dict(flag_counts),
        'retransmissions': int(retrans),
        'payload_ascii_sequences': payload_ascii_sequences,
        'client_banner': client_banner,
        'server_banner': server_banner,
        'concatenated_payload_snippet': concatenated[:4096].hex() if concatenated else None,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': int(src_port) if src_port is not None else None,
        'dst_port': int(dst_port) if dst_port is not None else None,
    }
    return metrics

_algos_regexes = {
    'kex': re.compile(r'kex_algorithms[:=]?\s*([A-Za-z0-9\-,@_.]+)', re.IGNORECASE),
    'ciphers': re.compile(r'ciphers[:=]?\s*([A-Za-z0-9\-,@_.]+)', re.IGNORECASE),
    'macs': re.compile(r'macs[:=]?\s*([A-Za-z0-9\-,@_.]+)', re.IGNORECASE),
    'comps': re.compile(r'comps[:=]?\s*([A-Za-z0-9\-,@_.]+)', re.IGNORECASE),
}

def extract_algos_from_concatenated(concat_bytes):
    """
    Try to heuristically extract algorithm lists from payload content.
    Return dict with arrays for kex_algorithms, ciphers, macs, comps and hasshAlgorithms string.
    """
    if not concat_bytes:
        return {}
    try:
        s = concat_bytes.decode('utf-8', errors='ignore')
    except Exception:
        s = ''
    found = {}
    for k, rx in _algos_regexes.items():
        m = rx.search(s)
        if m:
            val = m.group(1)
            arr = [x.strip() for x in val.split(',') if x.strip()]
            found[k] = arr
    # fallback: try to detect comma-separated lists after "SSH KEX" like patterns
    # not perfect; best-effort
    if not found:
        # try to find sequences of algorithms by pattern (many '-' or '@')
        lists = re.findall(r'([A-Za-z0-9@._-]+(?:,[A-Za-z0-9@._-]+){2,})', s)
        if lists:
            # take the first as kex, second as ciphers etc (heuristic)
            if lists:
                parts = [lst.split(',') for lst in lists]
                if parts:
                    found['kex'] = parts[0]
                    if len(parts) > 1:
                        found['ciphers'] = parts[1]
    # canonical hasshAlgorithms string
    hassh_alg_str = None
    if found:
        segs = []
        segs.append(','.join(found.get('kex', [])))
        segs.append(','.join(found.get('ciphers', [])))
        segs.append(','.join(found.get('macs', [])))
        segs.append(','.join(found.get('comps', [])))
        hassh_alg_str = ';'.join(segs)
    # compute hassh (MD5 of the alg string)
    hassh = md5_hex(hassh_alg_str) if hassh_alg_str else None
    return {
        'kex_algorithms': found.get('kex'),
        'ciphers': found.get('ciphers'),
        'macs': found.get('macs'),
        'comps': found.get('comps'),
        'hasshAlgorithms': hassh_alg_str,
        'hassh': hassh
    }

def build_session_document(pcap_filename, metrics, sensor_id, login_attempts, tool_label=None):
    """
    Build final JSON document per session including fingerprint_sources metadata.
    """
    doc = {
        'sensor_id': sensor_id,
        'pcap_file': os.path.basename(pcap_filename) if pcap_filename else None,
        'src_ip': metrics.get('src_ip'),
        'src_port': metrics.get('src_port'),
        'dst_ip': metrics.get('dst_ip'),
        'dst_port': metrics.get('dst_port'),
        'first_seen': metrics.get('first_seen'),
        'last_seen': metrics.get('last_seen'),
        'duration': metrics.get('duration'),
        'packet_count': metrics.get('packet_count'),
        'bytes': metrics.get('bytes'),
        'iat_mean': metrics.get('iat_mean'),
        'iat_median': metrics.get('iat_median'),
        'ttl_median': metrics.get('ttl_median'),
        'tcp_window_median': metrics.get('tcp_window_median'),
        'tcp_options': metrics.get('tcp_options'),
        'tcp_flag_counts': metrics.get('tcp_flag_counts'),
        'retransmissions': metrics.get('retransmissions'),
        'payload_ascii_sequences': metrics.get('payload_ascii_sequences'),
        'client_banner': metrics.get('client_banner'),
        'server_banner': metrics.get('server_banner'),
        # algos: attempt extraction
    }
    algos = extract_algos_from_concatenated(bytes.fromhex(metrics['concatenated_payload_snippet']) if metrics.get('concatenated_payload_snippet') else b'')
    doc.update(algos)
    # selected_algorithms left empty - extractor can't reliably pick without tshark/zeek
    doc['selected_algorithms'] = None
    # ssh_message_types_seen: cannot reliably infer without protocol parsing - leave empty if not available
    doc['ssh_message_types_seen'] = []
    # fingerprint sources
    sources = []
    if doc.get('hassh'):
        sources.append('hassh')
    if doc.get('client_banner'):
        sources.append('client_banner')
    if doc.get('tcp_options'):
        sources.append('tcp_options')
    doc['fingerprint_sources'] = sources
    doc['tool_label'] = tool_label
    doc['login_attempts'] = login_attempts or []
    # add some metadata for debugging/triage
    doc['_meta'] = {
        'generated_at': now_iso(),
    }
    return doc

def post_to_collector(url, api_key, payload_bytes):
    """
    POST payload_bytes (application/json) to url.
    If api_key provided, sign HMAC-SHA256 and set 'X-Payload-Signature: v1=<hex>'
    Return (success_bool, status_code, response_text)
    """
    if requests is None:
        return (False, None, "requests not available")
    headers = {
        'Content-Type': 'application/json'
    }
    if api_key:
        sig = hmac_sha256_hex(api_key, payload_bytes)
        headers['X-Payload-Signature'] = f"v1={sig}"
    try:
        r = requests.post(url, data=payload_bytes, headers=headers, timeout=10)
        return (200 <= r.status_code < 300, r.status_code, r.text)
    except Exception as e:
        return (False, None, str(e))

def process_pcap_file(pcap_path):
    """
    Read pcap and group into TCP sessions by 4-tuple (src,dst,srcport,dstport).
    Return list of tuples (pcap_filename, list_of_pktlists_per_session)
    """
    pkts = rdpcap(pcap_path)
    flows = defaultdict(list)
    # group by flow key (ip-src, ip-dst, sport, dport) but normalize so that client->server and server->client are same flow
    for p in pkts:
        if IP in p and TCP in p:
            a = p[IP].src; b = p[IP].dst
            sa = int(p[TCP].sport); sb = int(p[TCP].dport)
            # canonical tuple: smaller ip/port pair first (string compare)
            if (a, sa) <= (b, sb):
                key = (a, b, sa, sb)
            else:
                key = (b, a, sb, sa)
            flows[key].append(p)
    session_pktlists = []
    for key, plist in flows.items():
        session_pktlists.append((key, plist))
    return session_pktlists

def append_to_merged(merged_out, new_sessions):
    existing = []
    if os.path.exists(merged_out):
        try:
            with open(merged_out, 'r', encoding='utf-8') as fh:
                existing = json.load(fh)
        except Exception:
            existing = []
    combined = existing + new_sessions
    tmp = merged_out + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(combined, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, merged_out)

def main():
    parser = argparse.ArgumentParser(description="Extractor: pcap -> session JSON (+ optional send)")
    parser.add_argument('--pcap-dir', required=True)
    parser.add_argument('--cowrie-json', required=True)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--sensor-id', required=True)
    parser.add_argument('--send-url', required=False, default=None, help='Collector URL to POST per-session JSON')
    parser.add_argument('--api-key', required=False, default=os.environ.get('API_KEY'))
    parser.add_argument('--scan-interval', type=int, default=5)
    parser.add_argument('--merged-out', default=None, help='path for merged output json (defaults to <out-dir>/merged_sessions.json)')
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    merged_out = args.merged_out or os.path.join(args.out_dir, "merged_sessions.json")

    processed_marker = os.path.join(args.out_dir, ".processed")
    processed = set()
    if os.path.exists(processed_marker):
        try:
            with open(processed_marker, 'r', encoding='utf-8') as fh:
                for line in fh:
                    processed.add(line.strip())
        except Exception:
            processed = set()

    print(f"[{now_iso()}] extractor starting; pcap_dir={args.pcap_dir} cowrie_json={args.cowrie_json} out_dir={args.out_dir}")

    while True:
        try:
            cowrie_events = load_cowrie_events(args.cowrie_json)
            pcaps = list_pcaps(args.pcap_dir)
            new_docs = []
            for pcap_path in pcaps:
                if pcap_path in processed:
                    continue
                try:
                    print(f"[{now_iso()}] processing pcap {pcap_path}")
                    sessions = process_pcap_file(pcap_path)
                    for key, pktlist in sessions:
                        metrics = analyze_session(pktlist)
                        # find login attempts
                        session_first_ts = None
                        session_last_ts = None
                        try:
                            session_first_ts = datetime.fromisoformat(metrics['first_seen']).timestamp() if metrics.get('first_seen') else None
                            session_last_ts = datetime.fromisoformat(metrics['last_seen']).timestamp() if metrics.get('last_seen') else None
                        except Exception:
                            session_first_ts = None
                            session_last_ts = None
                        login_attempts = find_login_attempts_for_session(cowrie_events, session_first_ts, session_last_ts, metrics.get('src_ip'))
                        # tool_label/mapping could be applied here (optional): heuristics by hassh or banners
                        tool_label = None
                        if metrics.get('client_banner'):
                            tool_label = metrics['client_banner']
                        doc = build_session_document(os.path.basename(pcap_path), metrics, args.sensor_id, login_attempts, tool_label=tool_label)
                        new_docs.append(doc)
                        # optionally send immediately
                        if args.send_url:
                            payload = json.dumps(doc, ensure_ascii=False).encode('utf-8')
                            ok, sc, resp = post_to_collector(args.send_url, args.api_key, payload)
                            if ok:
                                print(f"[{now_iso()}] POST ok -> {args.send_url} (status={sc}) src={doc.get('src_ip')}")
                            else:
                                print(f"[{now_iso()}] POST failed -> {args.send_url} (status={sc}) err={resp}")
                    # mark processed
                    processed.add(pcap_path)
                    with open(processed_marker, 'w', encoding='utf-8') as fh:
                        for s in processed:
                            fh.write(s + "\n")
                except Exception as e:
                    print(f"[{now_iso()}] error processing {pcap_path}: {e}")
                    continue
            if new_docs:
                append_to_merged(merged_out, new_docs)
                print(f"[{now_iso()}] wrote {len(new_docs)} session docs -> {merged_out}")
            time.sleep(max(1, int(args.scan_interval)))
        except KeyboardInterrupt:
            print("stopping on keyboard interrupt")
            break
        except Exception as e:
            print(f"[{now_iso()}] main loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
