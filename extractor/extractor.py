#!/usr/bin/env python3
"""
extractor.py (patched)

Same behaviour as before, but pcap_file uses the original rotated filename
(without .processing/.done) so merged_sessions.json shows the real PCAP name.
"""

import os, sys, time, json, argparse, statistics
from datetime import datetime, timezone
from collections import defaultdict, Counter
from scapy.all import rdpcap, TCP, IP, Raw  # noqa: E402

def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def parse_iso(s: str):
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()
    except Exception:
        return None

def sha256_hex(b: bytes) -> str:
    import hashlib as _hl
    return _hl.sha256(b).hexdigest()

def median_or_none(vals):
    return statistics.median(vals) if vals else None

def mean_or_none(vals):
    return statistics.mean(vals) if vals else None

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def human(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"

def normalize_pcap_basename(path: str) -> str:
    """Return the original rotated pcap basename without .processing or .done suffixes."""
    base = os.path.basename(path)
    # remove .processing if present
    if base.endswith('.processing'):
        base = base[:-11]
    # remove trailing .done if present
    if base.endswith('.done'):
        base = base[:-5]
    return base

def process_pcap(pcap_path: str, sensor_id: str, ssh_port: int) -> list:
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"[WARN] Could not read pcap {pcap_path}: {human(e)}", file=sys.stderr)
        return []

    sess_pkts = defaultdict(list)
    for p in pkts:
        if IP in p and TCP in p:
            ip = p[IP]; tcp = p[TCP]
            if tcp.sport != ssh_port and tcp.dport != ssh_port:
                continue
            if tcp.dport == ssh_port:
                client=(ip.src, tcp.sport); server=(ip.dst, tcp.dport)
            else:
                client=(ip.dst, tcp.dport); server=(ip.src, tcp.sport)
            key=(client[0], int(client[1]), server[0], int(server[1]))
            sess_pkts[key].append(p)

    results=[]
    for (c_ip,c_port,s_ip,s_port), pkts in sess_pkts.items():
        ts = sorted([float(p.time) for p in pkts])
        first_seen = ts[0]; last_seen = ts[-1]
        duration = last_seen - first_seen if len(ts)>1 else 0.0
        pkt_count = len(pkts)
        bytes_total = sum(len(bytes(p)) for p in pkts)
        iats = [t2 - t1 for t1,t2 in zip(ts, ts[1:])]
        iat_mean = mean_or_none(iats); iat_median = median_or_none(iats)
        ttls = [int(p[IP].ttl) for p in pkts if IP in p]
        wins = [int(p[TCP].window) for p in pkts if TCP in p]
        ttl_median = median_or_none(ttls); win_median = median_or_none(wins)
        flag_counts = Counter()
        for p in pkts:
            if TCP in p:
                flag_counts[str(p[TCP].flags)] += 1
        seen_seqs={'c': set(), 's': set()}; retrans=0
        for p in pkts:
            t=p[TCP]; side='c' if (p[IP].src==c_ip and t.sport==c_port) else 's'
            seq=int(t.seq)
            if seq in seen_seqs[side]:
                retrans += 1
            else:
                seen_seqs[side].add(seq)

        payloads=[]; banner_client=None; banner_server=None; concatenated=b""
        for p in pkts:
            if Raw in p:
                b=bytes(p[Raw].load); concatenated += b
                s = b.decode('utf-8', errors='ignore')
                if 'SSH-' in s:
                    if p[IP].src==c_ip and banner_client is None:
                        idx = s.find('SSH-'); banner_client = s[idx:].splitlines()[0]
                    if p[IP].src==s_ip and banner_server is None:
                        idx = s.find('SSH-'); banner_server = s[idx:].splitlines()[0]
                ascii_seq = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
                if len(ascii_seq) >= 4:
                    payloads.append(ascii_seq)

        hassh=None
        try:
            text = concatenated.decode('utf-8', errors='ignore')
            import re
            combos = re.findall(r'([A-Za-z0-9@._+-]+(?:,[A-Za-z0-9@._+-]+){2,40})', text)
            kex_candidates = [c for c in combos if any(x in c.lower() for x in
                                    ['diffie','ecdh','rsa','curve25519','aes','chacha20','hmac','umac','gcm','ctr'])]
            if kex_candidates:
                hassh = sha256_hex((','.join(kex_candidates)).encode('utf-8'))[:64]
            elif concatenated:
                hassh = sha256_hex(concatenated[:2048])[:64]
        except Exception:
            pass

        session_obj = {
            "sensor_id": sensor_id,
            # keep pcap_file as placeholder; caller will replace with normalized basename
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
            "tcp_flag_counts": dict(flag_counts),
            "retransmissions": retrans,
            "payload_ascii_sequences": payloads[:20],
            "client_banner": banner_client,
            "server_banner": banner_server,
            "hassh": hassh,
        }
        results.append(session_obj)
    return results

def load_cowrie_events_window(cowrie_json_path: str, src_ips: set, tmin: float, tmax: float):
    evs=[]
    if not os.path.exists(cowrie_json_path):
        return evs
    low = tmin - 5; high = tmax + 5
    try:
        with open(cowrie_json_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try: ev=json.loads(line)
                except Exception: continue
                sip = ev.get('src_ip') or ev.get('src_host') or ev.get('src_addr')
                if not sip or sip not in src_ips: continue
                ts_str = ev.get('timestamp') or ev.get('time') or ev.get('timestamp_iso')
                if not ts_str: continue
                ts = parse_iso(ts_str) if not isinstance(ts_str,(int,float)) else float(ts_str)
                if ts is None: continue
                if low <= ts <= high: evs.append(ev)
    except Exception as e:
        print(f"[WARN] Reading cowrie.json failed: {human(e)}", file=sys.stderr)
    return evs

def link_sessions_with_events(sessions, events):
    by_ip=defaultdict(list)
    for ev in events:
        sip = ev.get('src_ip') or ev.get('src_host') or ev.get('src_addr')
        if sip: by_ip[sip].append(ev)
    for s in sessions:
        linked=[]
        evs = by_ip.get(s['src_ip'], [])
        if not evs:
            s['linked_cowrie_events']=linked; continue
        first=parse_iso(s['first_seen']); last=parse_iso(s['last_seen'])
        if first is None or last is None:
            s['linked_cowrie_events']=linked; continue
        low=first-5; high=last+5
        for ev in evs:
            t = ev.get('timestamp') or ev.get('time') or ev.get('timestamp_iso')
            if t is None: continue
            ts = float(t) if isinstance(t,(int,float)) else parse_iso(str(t))
            if ts is None: continue
            if low <= ts <= high: linked.append(ev)
        s['linked_cowrie_events']=linked
    return sessions

def list_candidate_pcaps(pcap_dir: str):
    try:
        files=os.listdir(pcap_dir)
    except Exception:
        return []
    out=[]
    import re
    PCAP_NAME_RE = re.compile(r"^ssh-\d{8}-\d{6}\.pcap(?:\.done)?$")
    for f in files:
        if f.endswith(('.processing', '.processed', '.failed')): continue
        if not (f.endswith('.pcap') or f.endswith('.pcap.done')): continue
        if not PCAP_NAME_RE.match(f): continue
        full=os.path.join(pcap_dir,f)
        try:
            if os.path.getsize(full) <= 64: continue
        except OSError:
            continue
        out.append(full)
    return sorted(out)

def to_processing_name(path: str) -> str:
    base=os.path.basename(path)
    if base.endswith('.pcap.done'):
        base = base[:-5]
    return os.path.join(os.path.dirname(path), base + '.processing')

def archive_path(archive_dir: str, processing_path: str) -> str:
    base=os.path.basename(processing_path)
    if base.endswith('.processing'):
        base = base[:-11]
    return os.path.join(archive_dir, base + '.processed')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--cowrie-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--sensor-id", default="unknown")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--scan-interval", type=int, default=10)
    args = parser.parse_args()

    pcap_dir = args.pcap_dir; out_dir = args.out_dir; cowrie_json = args.cowrie_json
    sensor_id = args.sensor_id; ssh_port = int(args.ssh_port)

    os.makedirs(out_dir, exist_ok=True)
    archive_dir = os.path.join(pcap_dir, "archive"); failed_dir = os.path.join(pcap_dir, "failed")
    os.makedirs(archive_dir, exist_ok=True); os.makedirs(failed_dir, exist_ok=True)

    merged_out = os.path.join(out_dir, "merged_sessions.json")

    while True:
        pcaps = list_candidate_pcaps(pcap_dir)
        new_sessions=[]
        for p in pcaps:
            proc = to_processing_name(p)
            try:
                os.replace(p, proc)
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[INFO] skip {p}: rename failed: {human(e)}", file=sys.stderr)
                continue

            try:
                # extract sessions
                sess_list = process_pcap(proc, sensor_id, ssh_port)
                # normalize pcap filename for output to original rotated name
                real_basename = normalize_pcap_basename(p)
                for s in sess_list:
                    s['pcap_file'] = real_basename
                if sess_list:
                    new_sessions.extend(sess_list)
                final = archive_path(archive_dir, proc)
                os.replace(proc, final)
                print(f"[{now_iso()}] processed {real_basename}, sessions={len(sess_list)}")
            except Exception as e:
                print(f"[ERROR] processing {p}: {human(e)}", file=sys.stderr)
                try:
                    os.replace(proc, os.path.join(failed_dir, os.path.basename(proc)))
                except Exception:
                    pass

        if new_sessions:
            tmins = [parse_iso(s['first_seen']) for s in new_sessions if parse_iso(s['first_seen']) is not None]
            tmaxs = [parse_iso(s['last_seen']) for s in new_sessions if parse_iso(s['last_seen']) is not None]
            if tmins and tmaxs:
                tmin=min(tmins); tmax=max(tmaxs)
                src_ips = {s['src_ip'] for s in new_sessions}
                evs = load_cowrie_events_window(cowrie_json, src_ips, tmin, tmax)
                new_sessions = link_sessions_with_events(new_sessions, evs)

            # merge atomically
            existing=[]
            if os.path.exists(merged_out):
                try:
                    with open(merged_out, 'r', encoding='utf-8') as fh:
                        existing = json.load(fh)
                except Exception:
                    existing = []
            combined = existing + new_sessions
            tmp = merged_out + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(combined, fh, indent=2)
            os.replace(tmp, merged_out)
            print(f"[{now_iso()}] wrote {len(new_sessions)} sessions -> {merged_out}")

        time.sleep(max(1, int(args.scan_interval)))

if __name__ == "__main__":
    main()
