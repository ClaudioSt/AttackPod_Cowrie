#!/usr/bin/env python3
"""
extractor.py

Produces ONE JSON summary per Cowrie session and either writes it to out_dir
or POSTs it (NDJSON, signed) to a collector.

Usage examples:
  python extractor.py --only-session 00c09e5b58af --pcap-dir /data/pcap --cowrie-json /cowrie/log/cowrie.json --send-url http://host.docker.internal:8000/add_attack --api-key supersecret
"""
from __future__ import annotations
import os, sys, json, time, argparse, hmac, hashlib, math
from datetime import datetime, timezone
from statistics import mean, median
from typing import Dict, List, Any, Optional, Tuple

# scapy
try:
    from scapy.all import rdpcap, TCP, IP
except Exception as e:
    print("ERROR: scapy not available. Install scapy in the image.", file=sys.stderr)
    raise

# ---------- Helpers ----------
ISOFMT = "%Y-%m-%dT%H:%M:%S"

def isoparse(s: str) -> Optional[datetime]:
    if not s: return None
    try:
        # accept trailing Z
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
                    # ignored malformed line
                    continue
    except FileNotFoundError:
        return []
    return evs

# ---------- Group by session ----------
def group_by_session(events: List[Dict[str,Any]]) -> Dict[str, List[Dict[str,Any]]]:
    sessions = {}
    for e in events:
        sid = e.get("session") or e.get("session_id") or e.get("uuid")
        if not sid: continue
        sessions.setdefault(sid, []).append(e)
    return sessions

# ---------- Select pcap files by time-window or simple heuristics ----------
def list_pcaps(pcap_dir: str) -> List[str]:
    files = []
    if not os.path.isdir(pcap_dir):
        return files
    for fn in sorted(os.listdir(pcap_dir)):
        if fn.endswith(".pcap"):
            files.append(os.path.join(pcap_dir,fn))
    return files

def pcap_mtime(path: str) -> float:
    return os.path.getmtime(path)

def pcap_size(path: str) -> int:
    return os.path.getsize(path)

# ---------- Flow filter: returns True if packet belongs to flow  -->
def packet_belongs_to_flow(pkt, flow_tuple):
    # flow_tuple: (src, sport, dst, dport) strings/ints
    try:
        if not (IP in pkt and TCP in pkt):
            return False
        ip = pkt[IP]
        tcp = pkt[TCP]
        src = ip.src; dst = ip.dst
        sport = int(tcp.sport); dport = int(tcp.dport)
        s0, sp0, d0, dp0 = flow_tuple
        # Compare both directions
        if (src==s0 and sport==int(sp0) and dst==d0 and dport==int(dp0)) or (src==d0 and sport==int(dp0) and dst==s0 and dport==int(sp0)):
            return True
    except Exception:
        return False
    return False

# ---------- Basic PCAP/flow analysis ----------
def analyze_pcap_for_session(pcap_path: str, flow: Optional[Tuple[str,int,str,int]]) -> Dict[str,Any]:
    """
    Gather simple metrics from pcap for given flow (if flow None, analyze all TCP/SSH packets)
    returns metrics dict (may be empty if pcap unreadable)
    """
    out = {}
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        out["_pcap_error"] = str(e)
        return out

    # pick packets that are TCP (and part of flow if given)
    sel = []
    for p in pkts:
        if IP in p and TCP in p:
            if flow:
                if packet_belongs_to_flow(p, flow):
                    sel.append(p)
            else:
                # heuristics: consider tcp packets to or from port 22/2222
                tcp = p[TCP]
                if tcp.sport in (22,2222) or tcp.dport in (22,2222):
                    sel.append(p)
    if not sel:
        # fallback: all TCP
        sel = [p for p in pkts if IP in p and TCP in p]
    if not sel:
        return out

    times = [float(p.time) for p in sel]
    times.sort()
    first_ts = times[0]; last_ts = times[-1]
    duration = last_ts - first_ts if last_ts>first_ts else 0.0
    packet_count = len(sel)
    total_bytes = sum(len(bytes(p)) for p in sel)

    # IATs
    iats = [t2 - t1 for t1,t2 in zip(times,times[1:])] if len(times)>1 else []
    iat_mean = mean(iats) if iats else 0.0
    iat_median = median(iats) if iats else 0.0

    # TTL, window median
    ttls = []
    wins = []
    flags_counts = {}
    seq_seen = {}
    retrans = 0
    tcp_options = None
    for p in sel:
        ip = p[IP]; tcp = p[TCP]
        ttls.append(ip.ttl if hasattr(ip,'ttl') else None)
        wins.append(tcp.window if hasattr(tcp,'window') else None)
        fl = str(tcp.flags)
        flags_counts[fl] = flags_counts.get(fl,0) + 1
        seq = (ip.src, tcp.sport, ip.dst, tcp.dport, tcp.seq)
        if seq in seq_seen:
            retrans += 1
        else:
            seq_seen[seq] = True
        # options from first SYN
        if tcp.flags & 0x02:  # SYN
            opts = []
            try:
                for o in tcp.options:
                    if isinstance(o, tuple) and len(o)>=2:
                        opts.append((o[0], o[1]))
                    else:
                        opts.append(o)
                if opts:
                    tcp_options = opts
            except Exception:
                pass

    # clean median calculations
    ttls_clean = [t for t in ttls if isinstance(t,int) or isinstance(t,float)]
    wins_clean = [w for w in wins if isinstance(w,int) or isinstance(w,float)]

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

# ---------- Build session summary ----------
def build_session_summary(session_id: str, events: List[Dict[str,Any]], pcap_dir: str,
                          flow: Optional[Tuple[str,int,str,int]] = None, time_window: Optional[Tuple[datetime,datetime]] = None,
                          sensor_id: str = "") -> Dict[str,Any]:
    # basic fields
    # choose earliest and latest timestamps from events
    times = []
    for e in events:
        t = e.get("timestamp") or e.get("time") or e.get("ts")
        dt = isoparse(t) if t else None
        if dt:
            times.append(dt)
    first_seen = min(times).isoformat() if times else None
    last_seen = max(times).isoformat() if times else None

    # gather login attempts
    attempts = []
    for e in events:
        if e.get("eventid") and e.get("eventid").startswith("cowrie.login"):
            attempts.append({
                "username": e.get("username"),
                "password": e.get("password"),
                "timestamp": e.get("timestamp") or e.get("time")
            })

    # kex / client banners
    client_banner = None
    server_banner = None
    hassh = None
    hasshAlgorithms = None
    kex_algorithms = None
    ciphers = None
    macs = None
    comps = None

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

    # choose IP/ports from events (session.connect)
    src_ip = None; src_port = None; dst_ip = None; dst_port = None
    for e in events:
        if e.get("eventid") == "cowrie.session.connect":
            src_ip = e.get("src_ip") or src_ip
            src_port = e.get("src_port") or src_port
            dst_ip = e.get("dst_ip") or dst_ip
            dst_port = e.get("dst_port") or dst_port

    # choose PCAP files to inspect:
    pcaps = list_pcaps(pcap_dir)
    candidate_pcaps = []
    # Heuristics: take pcaps with non-zero size, and if flow defined, prefer ones with mtime in window
    for p in pcaps:
        try:
            if pcap_size(p) < 64: continue
        except Exception:
            continue
        if time_window:
            # include if file mtime intersects window +/- 5s
            mt = datetime.fromtimestamp(pcap_mtime(p), tz=timezone.utc)
            if mt >= time_window[0] - time.timedelta(seconds=5) and mt <= time_window[1] + time.timedelta(seconds=5):
                candidate_pcaps.append(p)
        else:
            candidate_pcaps.append(p)
    # fallback: include all
    if not candidate_pcaps:
        candidate_pcaps = pcaps

    # If we have flow, analyze each pcap for that flow; otherwise pick most recent non-empty pcap
    pcap_metrics = {}
    chosen_pcap = None
    if flow:
        for p in reversed(candidate_pcaps):
            m = analyze_pcap_for_session(p, flow)
            # prefer ones with packet_count > 0
            if m.get("packet_count",0) > 0:
                pcap_metrics = m
                chosen_pcap = p
                break
    else:
        # try most recent first
        for p in reversed(candidate_pcaps):
            m = analyze_pcap_for_session(p, None)
            if m.get("packet_count",0) > 0:
                pcap_metrics = m
                chosen_pcap = p
                break

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
        "fingerprint_sources": ["hassh","client_banner","tcp_options"],
        "pcap_path": chosen_pcap,
    }
    # merge pcap_metrics
    summary.update(pcap_metrics)
    return summary

def _to_jsonable(x):
    """Recursively convert objects to JSON-serializable types."""
    from datetime import datetime
    if x is None or isinstance(x, (str, int, float, bool)):
        # floats: NaN/Inf sind formal kein JSON; werte ggf. in str umwandeln
        if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
            return str(x)
        return x
    if isinstance(x, bytes):
        # kompakt: Hex-String (lesbar, stabil)
        return x.hex()
    if isinstance(x, (list, tuple, set)):
        return [_to_jsonable(v) for v in x]
    if isinstance(x, dict):
        return {str(k): _to_jsonable(v) for k, v in x.items()}
    if isinstance(x, datetime):
        return x.isoformat()
    # Scapy-Objekte o.ä.
    try:
        return str(x)
    except Exception:
        return "<unserializable>"


# ---------- Send NDJSON single-line ----------
def send_ndjson(obj: Dict[str,Any], send_url: str, api_key: Optional[str]=None) -> Tuple[bool,int,str]:
    payload = (json.dumps(_to_jsonable(obj), separators=(",",":")) + "\n").encode("utf-8")
    import requests
    headers = {"Content-Type":"application/x-ndjson"}
    if api_key:
        headers["X-Payload-Signature"] = "v1=" + hmac_sig(api_key, payload)
    try:
        r = requests.post(send_url, data=payload, headers=headers, timeout=10)
        return (r.ok, r.status_code, r.text if r.text else "")
    except Exception as e:
        return (False, 0, str(e))

# ---------- Argparse and main ----------
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
    return p.parse_args()

def main():
    args = parse_args()
    events = read_cowrie_events(args.cowrie_json)
    sessions = group_by_session(events)
    # time window parse
    tw = None
    if args.time_window:
        try:
            a,b = args.time_window.split(",")
            tw = (isoparse(a), isoparse(b))
        except Exception:
            tw = None
    # flow parse
    flow = None
    if args.flow:
        try:
            # format: "1.2.3.4:1234->5.6.7.8:2222"
            left,right = args.flow.split("->")
            s,sport = left.split(":")
            d,dport = right.split(":")
            flow = (s,int(sport),d,int(dport))
        except Exception:
            flow = None

    # sensor id
    sensor_id = os.getenv("SENSOR_ID","")

    # ensure out dir
    try:
        os.makedirs(args.out_dir, exist_ok=True)
    except Exception:
        pass

    # process one session (if provided) or all sessions
    target_sessions = [args.only_session] if args.only_session else sorted(sessions.keys())
    processed = 0
    for sid in target_sessions:
        if sid is None: continue
        evs = sessions.get(sid, [])
        if not evs:
            # nothing to do
            continue
        summary = build_session_summary(sid, evs, args.pcap_dir, flow=flow, time_window=tw, sensor_id=sensor_id)
        # put timestamp
        summary["_collected_at"] = now_iso()
        # write to out dir as pretty json (for debugging)
        outpath = os.path.join(args.out_dir, f"session-{sid}.json")
        try:
            with open(outpath,"w",encoding="utf-8") as fh:
                json.dump(_to_jsonable(summary), fh, indent=2, ensure_ascii=False)
        except Exception as e:
            print("Warning: cannot write out file:", e, file=sys.stderr)
        # send if configured
        if args.send_url:
            ok, status, text = send_ndjson(summary, args.send_url, args.api_key or None)
            if ok:
                print(f"POST ok -> {args.send_url} (status {status})")
            else:
                print(f"POST failed -> {args.send_url} (status {status}) error: {text}", file=sys.stderr)
        else:
            # fallback: print NDJSON to stdout
            print(json.dumps(_to_jsonable(summary), separators=(",",":")))
        processed += 1

    if processed == 0:
        print("No sessions processed.", file=sys.stderr)

if __name__ == "__main__":
    main()
