#!/usr/bin/env python3
"""
extractor.py
Erzeugt pro Cowrie-Session genau eine JSON-Zusammenfassung.
Kann optional per --send-url NDJSON posten und per --use-tshark echtes KEX/HASSH aus PCAP extrahieren.
"""
from __future__ import annotations
import os, sys, json, time, argparse, hmac, hashlib, math, subprocess, shutil
from datetime import datetime, timezone, timedelta
from statistics import mean, median
from typing import Dict, List, Any, Optional, Tuple

# scapy
try:
    from scapy.all import rdpcap, TCP, IP
except Exception as e:
    print("ERROR: scapy not available. Install scapy in the image.", file=sys.stderr)
    raise

ISOFMT = "%Y-%m-%dT%H:%M:%S"

def isoparse(s: str) -> Optional[datetime]:
    if not s: return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.strptime(s.split(".")[0], ISOFMT).replace(tzinfo=timezone.utc)
        except Exception:
            return None

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def hmac_sig(api_key: str, payload_bytes: bytes) -> str:
    return hmac.new(api_key.encode(), payload_bytes, hashlib.sha256).hexdigest()

def safe_get(d,k,default=None):
    return d[k] if k in d else default

# ---------- Cowrie NDJSON reader ----------
def read_cowrie_events(cowrie_json_path: str) -> List[Dict[str,Any]]:
    evs = []
    try:
        with open(cowrie_json_path,"r",encoding="utf-8",errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln: continue
                try:
                    evs.append(json.loads(ln))
                except Exception:
                    continue
    except FileNotFoundError:
        return []
    return evs

def group_by_session(events: List[Dict[str,Any]]) -> Dict[str, List[Dict[str,Any]]]:
    sessions = {}
    for e in events:
        sid = e.get("session") or e.get("session_id") or e.get("uuid")
        if not sid: continue
        sessions.setdefault(sid, []).append(e)
    return sessions

# ---------- PCAP helpers ----------
def list_pcaps(pcap_dir: str) -> List[str]:
    if not os.path.isdir(pcap_dir): return []
    return [os.path.join(pcap_dir,fn) for fn in sorted(os.listdir(pcap_dir)) if fn.endswith(".pcap")]

def pcap_mtime(path: str) -> float:
    return os.path.getmtime(path)

def pcap_size(path: str) -> int:
    return os.path.getsize(path)

def packet_belongs_to_flow(pkt, flow_tuple):
    try:
        if not (IP in pkt and TCP in pkt):
            return False
        ip = pkt[IP]; tcp = pkt[TCP]
        s0, sp0, d0, dp0 = flow_tuple
        # beide Richtungen akzeptieren
        if (ip.src==s0 and int(tcp.sport)==int(sp0) and ip.dst==d0 and int(tcp.dport)==int(dp0)) \
           or (ip.src==d0 and int(tcp.sport)==int(dp0) and ip.dst==s0 and int(tcp.dport)==int(sp0)):
            return True
    except Exception:
        return False
    return False

def analyze_pcap_for_session(pcap_path: str, flow: Optional[Tuple[str,int,str,int]]) -> Dict[str,Any]:
    out = {}
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        out["_pcap_error"] = str(e)
        return out

    sel = []
    for p in pkts:
        if IP in p and TCP in p:
            if flow:
                if packet_belongs_to_flow(p, flow):
                    sel.append(p)
            else:
                tcp = p[TCP]
                if tcp.sport in (22,2222) or tcp.dport in (22,2222):
                    sel.append(p)
    if not sel:
        sel = [p for p in pkts if IP in p and TCP in p]
    if not sel:
        return out

    times = [float(p.time) for p in sel]
    times.sort()
    first_ts = times[0]; last_ts = times[-1]
    duration = max(0.0, last_ts - first_ts)
    packet_count = len(sel)
    total_bytes = sum(len(bytes(p)) for p in sel)

    iats = [t2 - t1 for t1,t2 in zip(times,times[1:])] if len(times)>1 else []
    iat_mean = mean(iats) if iats else 0.0
    iat_median = median(iats) if iats else 0.0

    ttls, wins, flags_counts, seq_seen = [], [], {}, {}
    retrans, tcp_options = 0, None
    for p in sel:
        ip = p[IP]; tcp = p[TCP]
        if hasattr(ip,'ttl'): ttls.append(ip.ttl)
        if hasattr(tcp,'window'): wins.append(tcp.window)
        fl = str(tcp.flags); flags_counts[fl] = flags_counts.get(fl,0) + 1
        seq = (ip.src, tcp.sport, ip.dst, tcp.dport, tcp.seq)
        if seq in seq_seen: retrans += 1
        else: seq_seen[seq] = True
        if tcp.flags & 0x02:  # SYN
            opts = []
            try:
                for o in tcp.options:
                    if isinstance(o, tuple) and len(o)>=2:
                        opts.append((o[0], o[1]))
                    else:
                        opts.append(o)
                if opts: tcp_options = opts
            except Exception:
                pass

    ttls_clean = [t for t in ttls if isinstance(t,(int,float))]
    wins_clean = [w for w in wins if isinstance(w,(int,float))]

    out.update({
        "packet_count": packet_count,
        "bytes": total_bytes,
        "duration": round(duration,3),
        "iat_mean": round(iat_mean,6),
        "iat_median": round(iat_median,6),
        "ttl_median": int(median(ttls_clean)) if ttls_clean else None,
        "tcp_window_median": int(median(wins_clean)) if wins_clean else None,
        "tcp_options": tcp_options,
        "tcp_flag_counts": flags_counts,
        "retransmissions": retrans
    })
    return out

# ---------- KEX/HASSH via tshark (optional) ----------
def tshark_path() -> Optional[str]:
    return shutil.which("tshark")

def extract_kex_with_tshark(pcap_path: str) -> Optional[Dict[str,Any]]:
    tsh = tshark_path()
    if not tsh: return None
    fields = [
        "ssh.kex_algorithms",
        "ssh.host_key_algorithms",
        "ssh.encryption_algorithms_client_to_server",
        "ssh.encryption_algorithms_server_to_client",
        "ssh.mac_algorithms_client_to_server",
        "ssh.mac_algorithms_server_to_client",
        "ssh.compression_algorithms_client_to_server",
        "ssh.compression_algorithms_server_to_client",
        "ssh.protocol"
    ]
    cmd = [tsh, "-r", pcap_path, "-Y", "ssh", "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.returncode != 0: return None
        # parse: last non-empty line tends to hold KEXINIT
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if not lines: return None
        last = lines[-1].split("\t")
        # map fields
        vals = dict(zip(fields, last))
        # Build HASSH-style input (Salesforce: concat lists in defined order)
        def clean(v): return (v or "").strip()
        kex = clean(vals.get("ssh.kex_algorithms"))
        hka = clean(vals.get("ssh.host_key_algorithms"))
        c2s = clean(vals.get("ssh.encryption_algorithms_client_to_server"))
        s2c = clean(vals.get("ssh.encryption_algorithms_server_to_client"))
        mc2s = clean(vals.get("ssh.mac_algorithms_client_to_server"))
        ms2c = clean(vals.get("ssh.mac_algorithms_server_to_client"))
        cc2s = clean(vals.get("ssh.compression_algorithms_client_to_server"))
        cs2c = clean(vals.get("ssh.compression_algorithms_server_to_client"))
        hassh_algostr = ";".join([kex,hka,c2s,s2c,mc2s,ms2c,cc2s,cs2c])
        hassh = hashlib.md5(hassh_algostr.encode("utf-8")).hexdigest() if hassh_algostr.replace(";","") else None
        return {
            "kex_algorithms": kex or None,
            "host_key_algorithms": hka or None,
            "ciphers_c2s": c2s or None,
            "ciphers_s2c": s2c or None,
            "macs_c2s": mc2s or None,
            "macs_s2c": ms2c or None,
            "comps_c2s": cc2s or None,
            "comps_s2c": cs2c or None,
            "hasshAlgorithms": hassh_algostr or None,
            "hassh": hassh
        }
    except Exception:
        return None

# ---------- Build session summary ----------
def build_session_summary(session_id: str, events: List[Dict[str,Any]], pcap_dir: str,
                          flow: Optional[Tuple[str,int,str,int]] = None, time_window: Optional[Tuple[datetime,datetime]] = None,
                          sensor_id: str = "", use_tshark: bool=False) -> Dict[str,Any]:

    # Zeiten
    times = []
    for e in events:
        t = e.get("timestamp") or e.get("time") or e.get("ts")
        dt = isoparse(t) if t else None
        if dt: times.append(dt)
    first_seen = min(times).isoformat() if times else None
    last_seen  = max(times).isoformat() if times else None

    # Login-Versuche
    attempts = []
    for e in events:
        if e.get("eventid","").startswith("cowrie.login"):
            attempts.append({
                "username": e.get("username"),
                "password": e.get("password"),
                "timestamp": e.get("timestamp") or e.get("time")
            })

    # Banner & KEX (aus Cowrie, falls vorhanden)
    client_banner = server_banner = None
    hassh = hasshAlgorithms = None
    kex_algorithms = ciphers = macs = comps = None
    for e in events:
        if e.get("eventid") == "cowrie.client.version" and not client_banner:
            client_banner = e.get("version")
        if e.get("eventid") == "cowrie.server.version" and not server_banner:
            server_banner = e.get("version")
        if e.get("eventid") == "cowrie.client.kex":
            hassh = e.get("hassh") or hassh
            hasshAlgorithms = e.get("hasshAlgorithms") or hasshAlgorithms
            kex_algorithms = e.get("kexAlgs") or kex_algorithms
            ciphers = e.get("encCS") or ciphers
            macs = e.get("macCS") or macs
            comps = e.get("compCS") or comps

    # Flow (aus session.connect)
    src_ip = src_port = dst_ip = dst_port = None
    for e in events:
        if e.get("eventid") == "cowrie.session.connect":
            src_ip = e.get("src_ip") or src_ip
            src_port = e.get("src_port") or src_port
            dst_ip = e.get("dst_ip") or dst_ip
            dst_port = e.get("dst_port") or dst_port

    # PCAP-Auswahl (Time-Window berücksichtigen)
    pcaps = list_pcaps(pcap_dir)
    candidate_pcaps = []
    if time_window and all(time_window):
        start, end = time_window
        for p in pcaps:
            try:
                if pcap_size(p) < 64: continue
                mt = datetime.fromtimestamp(pcap_mtime(p), tz=timezone.utc)
                if (mt >= start - timedelta(seconds=15)) and (mt <= end + timedelta(seconds=15)):
                    candidate_pcaps.append(p)
            except Exception:
                continue
    if not candidate_pcaps:
        candidate_pcaps = pcaps

    pcap_metrics = {}
    chosen_pcap = None
    if flow:
        for p in reversed(candidate_pcaps):
            m = analyze_pcap_for_session(p, flow)
            if m.get("packet_count",0) > 0:
                pcap_metrics = m; chosen_pcap = p; break
    else:
        for p in reversed(candidate_pcaps):
            m = analyze_pcap_for_session(p, None)
            if m.get("packet_count",0) > 0:
                pcap_metrics = m; chosen_pcap = p; break

    # Wenn kein hassh in Events und tshark gewünscht/verfügbar: aus PCAP ziehen
    kex_from_pcap = None
    if (not hassh) and use_tshark and chosen_pcap:
        kex_from_pcap = extract_kex_with_tshark(chosen_pcap)
        if kex_from_pcap:
            hassh = hassh or kex_from_pcap.get("hassh")
            hasshAlgorithms = hasshAlgorithms or kex_from_pcap.get("hasshAlgorithms")
            # fülle Felder, falls leer
            kex_algorithms = kex_algorithms or kex_from_pcap.get("kex_algorithms")
            if not ciphers:
                ciphers = (kex_from_pcap.get("ciphers_c2s") or "") + "|" + (kex_from_pcap.get("ciphers_s2c") or "")
            if not macs:
                macs = (kex_from_pcap.get("macs_c2s") or "") + "|" + (kex_from_pcap.get("macs_s2c") or "")
            if not comps:
                comps = (kex_from_pcap.get("comps_c2s") or "") + "|" + (kex_from_pcap.get("comps_s2c") or "")

    summary = {
        "session_id": session_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "ssh",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sensor_id": sensor_id,
        "client_banner": client_banner,
        "server_banner": server_banner,
        "kex_algorithms": kex_algorithms,
        "ciphers": ciphers,
        "macs": macs,
        "comps": comps,
        "hasshAlgorithms": hasshAlgorithms,
        "hassh": hassh,
        "login_attempts": attempts,
        "fingerprint_sources": ["hassh","client_banner","tcp_options"] + (["tshark"] if kex_from_pcap else []),
        "pcap_path": chosen_pcap,
    }
    summary.update(pcap_metrics)
    return summary

def _to_jsonable(x):
    from datetime import datetime
    if x is None or isinstance(x, (str, int, float, bool)):
        if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
            return str(x)
        return x
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, (list, tuple, set)):
        return [_to_jsonable(v) for v in x]
    if isinstance(x, dict):
        return {str(k): _to_jsonable(v) for k, v in x.items()}
    if isinstance(x, datetime):
        return x.isoformat()
    try:
        return str(x)
    except Exception:
        return "<unserializable>"

def send_ndjson(obj: Dict[str,Any], send_url: str, api_key: Optional[str]=None) -> Tuple[bool,int,str]:
    payload = (json.dumps(_to_jsonable(obj), separators=(",",":")) + "\n").encode("utf-8")
    import requests
    headers = {"Content-Type":"application/x-ndjson"}
    if api_key:
        headers["X-Payload-Signature"] = "v1=" + hmac_sig(api_key, payload)
    try:
        r = requests.post(send_url, data=payload, headers=headers, timeout=10)
        return (r.ok, r.status_code, r.text or "")
    except Exception as e:
        return (False, 0, str(e))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap-dir", default=os.getenv("PCAP_DIR","/data/pcap"))
    p.add_argument("--cowrie-json", default=os.getenv("COWRIE_JSON","/cowrie/log/cowrie.json"))
    p.add_argument("--out-dir", default=os.getenv("OUT_DIR","/data/out"))
    p.add_argument("--only-session", default=None)
    p.add_argument("--time-window", default=None, help="ISOstart,ISOend")
    p.add_argument("--flow", default=None, help='SRC:SPORT->DST:DPORT (optional)')
    p.add_argument("--send-url", default=os.getenv("SEND_URL",""))
    p.add_argument("--api-key", default=os.getenv("API_KEY",""))
    p.add_argument("--use-tshark", action="store_true", help="Use tshark to extract KEX/HASSH from PCAP if Cowrie lacks it")
    return p.parse_args()

def main():
    args = parse_args()
    events = read_cowrie_events(args.cowrie_json)
    sessions = group_by_session(events)

    tw = None
    if args.time_window:
        try:
            a,b = args.time_window.split(",")
            tw = (isoparse(a), isoparse(b))
        except Exception:
            tw = None

    flow = None
    if args.flow:
        try:
            left,right = args.flow.split("->")
            s,sport = left.split(":")
            d,dport = right.split(":")
            flow = (s,int(sport),d,int(dport))
        except Exception:
            flow = None

    sensor_id = os.getenv("SENSOR_ID","")
    os.makedirs(args.out_dir, exist_ok=True)

    target_sessions = [args.only_session] if args.only_session else sorted(sessions.keys())
    processed = 0
    for sid in target_sessions:
        if sid is None: continue
        evs = sessions.get(sid, [])
        if not evs: continue
        summary = build_session_summary(sid, evs, args.pcap_dir, flow=flow, time_window=tw, sensor_id=sensor_id, use_tshark=args.use_tshark)
        summary["_collected_at"] = now_iso()

        outpath = os.path.join(args.out_dir, f"session-{sid}.json")
        try:
            with open(outpath,"w",encoding="utf-8") as fh:
                json.dump(_to_jsonable(summary), fh, indent=2, ensure_ascii=False)
        except Exception as e:
            print("Warning: cannot write out file:", e, file=sys.stderr)

        if args.send_url:
            ok, status, text = send_ndjson(summary, args.send_url, args.api_key or None)
            if ok:
                print(f"POST ok -> {args.send_url} (status {status})")
            else:
                print(f"POST failed -> {args.send_url} (status {status}) error: {text}", file=sys.stderr)
        else:
            print(json.dumps(_to_jsonable(summary), separators=(",",":")))
        processed += 1

    if processed == 0:
        print("No sessions processed.", file=sys.stderr)

if __name__ == "__main__":
    main()
