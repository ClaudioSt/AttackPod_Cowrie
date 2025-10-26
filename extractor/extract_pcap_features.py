#!/usr/bin/env python3
import os
import glob
import json
import re
import hashlib
import math
from statistics import mean, median
from dateutil import parser as dateparser
from scapy.all import rdpcap, TCP, IP, Raw

# -------------------------
# Konfiguration (env-variablen)
# -------------------------
PCAP_DIR   = os.getenv("PCAP_DIR", "/data/pcap")
COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie/data/cowrie.json")  # kann Datei ODER Verzeichnis sein
OUT_JSON   = os.getenv("OUT_JSON", "/data/out/merged_sessions.json")
OUT_NDJSON = os.getenv("OUT_NDJSON", "")  # z.B. "/data/out/merged_sessions.ndjson" (leer = aus)
SSH_PORT   = int(os.getenv("SSH_PORT", "2222"))  # interner Port von Cowrie
TIME_WINDOW= float(os.getenv("TIME_WINDOW", "10.0"))  # Matching-Fenster in Sekunden
PCAP_GLOB  = os.getenv("PCAP_GLOB", "*.pcap*")  # Pattern für PCAP-Dateien
MAX_PCAP_MB= float(os.getenv("MAX_PCAP_MB", "0"))  # >0: PCAPs größer als X MB überspringen

SSH_BANNER_RE = re.compile(rb"SSH-2.0-[^\r\n]+")

def list_ascii_sequences(payload: bytes):
    """Liefert druckbare ASCII-Sequenzen (für heuristische KEX-Listen-Extraktion)."""
    return [c.decode("utf-8", errors="ignore")
            for c in re.findall(rb"([ -~]{10,200})", payload)]

def compute_hassh(kex_list, enc_list, mac_list, comp_list):
    """
    Einfache HASSH-Konstruktion: kex;enc;mac;comp -> md5.
    An Cowrie-Events angleichen, falls dort andere Konkatenationsregeln gelten.
    """
    s = ",".join(kex_list) + ";" + ",".join(enc_list) + ";" + ",".join(mac_list) + ";" + ",".join(comp_list)
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def dir_key(pkt):
    """Richtungs-Schlüssel für Stream: (src,dst,sport,dport)."""
    return (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)

def reverse_dir_key(k):
    src, dst, sp, dp = k
    return (dst, src, dp, sp)

def parse_tcp_options(tcp):
    """Extrahiere gängige TCP-Optionen."""
    mss = None
    wscale = None
    sack = False
    try:
        for opt, val in (tcp.options or []):
            o = (opt or "").lower()
            if o == "mss" and isinstance(val, int):
                mss = val
            elif o == "wscale" and isinstance(val, int):
                wscale = val
            elif o in ("sackok", "sack_permitted", "sackpermitted"):
                sack = True
    except Exception:
        pass
    return mss, wscale, sack

def process_pcap_file(pcapfile):
    """Liest PCAP, gruppiert nach 5-Tuple und berechnet Features pro Stream (Richtung zusammengeführt)."""
    if MAX_PCAP_MB > 0:
        try:
            sz_mb = os.path.getsize(pcapfile) / (1024 * 1024)
            if sz_mb > MAX_PCAP_MB:
                print(f"[extractor] skip {pcapfile} ({sz_mb:.1f} MB > {MAX_PCAP_MB} MB)")
                return []
        except Exception:
            pass

    try:
        pkts = rdpcap(pcapfile)
    except Exception as e:
        print("[extractor] rdpcap error", pcapfile, e)
        return []

    # Streams in beiden Richtungen erfassen
    streams = {}  # key: (src,dst,sport,dport) -> list of records
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            continue
        ip, tcp = p[IP], p[TCP]
        k = dir_key(p)
        rec = {
            "t": float(p.time),
            "ttl": getattr(ip, "ttl", None),
            "win": getattr(tcp, "window", None),
            "len": len(p),
            "syn": int(tcp.flags & 0x02 != 0),
            "fin": int(tcp.flags & 0x01 != 0),
            "rst": int(tcp.flags & 0x04 != 0),
            "ack": int(tcp.flags & 0x10 != 0),
            "psh": int(tcp.flags & 0x08 != 0),
            "payload": bytes(p[Raw].load) if p.haslayer(Raw) else None,
            "mss": None, "wscale": None, "sack": None
        }
        mss, wscale, sack = parse_tcp_options(tcp)
        rec["mss"], rec["wscale"], rec["sack"] = mss, wscale, sack
        streams.setdefault(k, []).append(rec)

    # Features pro "ungerichtetem" Stream (d. h. (A->B) und (B->A) zusammenfassen)
    # Wir normieren den Key so, dass dport==SSH_PORT auf der Serverseite liegt.
    merged_feats = []
    visited = set()

    for k, pklist_fwd in streams.items():
        if k in visited:
            continue
        # finde Gegenrichtung
        k_rev = reverse_dir_key(k)
        pklist_rev = streams.get(k_rev, [])
        visited.add(k)
        visited.add(k_rev)

        # Bestimme, welche Richtung der SSH-Server ist (dport==SSH_PORT)
        # Wenn keine der beiden Richtungen auf dport==SSH_PORT zeigt, wir behalten Original.
        def is_server_dir(key):  # True, wenn diese Richtung zum Server (Cowrie) geht
            return key[3] == SSH_PORT

        if is_server_dir(k):
            client_to_server = pklist_fwd
            server_to_client = pklist_rev
            src, dst, sport, dport = k
        elif is_server_dir(k_rev):
            client_to_server = pklist_rev
            server_to_client = pklist_fwd
            # für das Feature-Objekt benutzen wir die "Client->Server" sichtbare 5-Tuple:
            src, dst, sport, dport = k_rev
        else:
            # Kein klassischer SSH-Port? trotzdem erfassen, aber Markierung setzen
            client_to_server = pklist_fwd
            server_to_client = pklist_rev
            src, dst, sport, dport = k

        # Zeiten / Deltas / Statistiken
        def times_stats(pl):
            if not pl:
                return (None, None, [], 0.0, 0.0)
            ts = sorted(x["t"] for x in pl)
            deltas = [t2 - t1 for t1, t2 in zip(ts, ts[1:])] if len(ts) > 1 else [0.0]
            return (ts[0], ts[-1], deltas, mean(deltas) if deltas else 0.0, median(deltas) if deltas else 0.0)

        f_first, f_last, f_deltas, f_iat_mean, f_iat_med = times_stats(client_to_server)
        r_first, r_last, r_deltas, r_iat_mean, r_iat_med = times_stats(server_to_client)

        def agg_vals(pl, field):
            vals = [x[field] for x in pl if x.get(field) is not None]
            return median(vals) if vals else None

        # TTL/Window Median pro Richtung
        ttl_c2s = agg_vals(client_to_server, "ttl")
        ttl_s2c = agg_vals(server_to_client, "ttl")
        win_c2s = agg_vals(client_to_server, "win")
        win_s2c = agg_vals(server_to_client, "win")

        # Bytes/Packets/Flags
        bytes_c2s = sum(x["len"] for x in client_to_server)
        bytes_s2c = sum(x["len"] for x in server_to_client)
        pkts_c2s = len(client_to_server)
        pkts_s2c = len(server_to_client)

        def sum_flag(pl, name):
            return sum(int(bool(x.get(name))) for x in pl)

        syn_c2s = sum_flag(client_to_server, "syn")
        fin_c2s = sum_flag(client_to_server, "fin")
        rst_c2s = sum_flag(client_to_server, "rst")
        ack_c2s = sum_flag(client_to_server, "ack")
        psh_c2s = sum_flag(client_to_server, "psh")

        syn_s2c = sum_flag(server_to_client, "syn")
        fin_s2c = sum_flag(server_to_client, "fin")
        rst_s2c = sum_flag(server_to_client, "rst")
        ack_s2c = sum_flag(server_to_client, "ack")
        psh_s2c = sum_flag(server_to_client, "psh")

        # TCP-Optionen (erste beobachtete Werte je Richtung)
        def first_opt(pl, key):
            for x in pl:
                val = x.get(key)
                if val is not None:
                    return val
            return None

        mss_c2s = first_opt(client_to_server, "mss")
        wsc_c2s = first_opt(client_to_server, "wscale")
        sack_c2s= bool(first_opt(client_to_server, "sack"))
        mss_s2c = first_opt(server_to_client, "mss")
        wsc_s2c = first_opt(server_to_client, "wscale")
        sack_s2c= bool(first_opt(server_to_client, "sack"))

        # Banner & (heuristische) KEX-Listen
        banner = None
        kex_arr = []
        enc_arr = []
        mac_arr = []
        comp_arr = []

        first_payloads = []
        # aus Performance-Gründen nur die ersten paar Payloads je Richtung betrachten
        for pl in (client_to_server[:12] + server_to_client[:12]):
            if pl.get("payload"):
                first_payloads.append(pl["payload"])

        for pld in first_payloads:
            m = SSH_BANNER_RE.search(pld)
            if (m is not None) and (banner is None):
                banner = m.group(0).decode(errors="ignore")
            # heuristische Extraktion von KEX/Cipher/MAC/Comp
            for cand in list_ascii_sequences(pld):
                if ("," in cand) and re.search(r"(curve25519|diffie-hellman|ecdh|kex)", cand, re.I):
                    kex_arr = [s.strip() for s in cand.split(",")]
                if ("," in cand) and re.search(r"(aes|chacha20|camellia|rc4|gcm|ctr)", cand, re.I):
                    enc_arr = [s.strip() for s in cand.split(",")]
                if ("," in cand) and re.search(r"(hmac|umac|sha2)", cand, re.I):
                    mac_arr = [s.strip() for s in cand.split(",")]
                if ("," in cand) and re.search(r"(zlib|none)", cand, re.I):
                    comp_arr = [s.strip() for s in cand.split(",")]

        computed_hassh = compute_hassh(kex_arr, enc_arr, mac_arr, comp_arr) if any([kex_arr, enc_arr, mac_arr, comp_arr]) else None

        # erste/letzte Payload-Längen als einfache Signal-Features
        def first_last_payload_len(pl):
            fl = [len(x["payload"]) for x in pl if x.get("payload")]
            return (fl[0] if fl else None, fl[-1] if fl else None)

        fpl_c2s, lpl_c2s = first_last_payload_len(client_to_server)
        fpl_s2c, lpl_s2c = first_last_payload_len(server_to_client)

        # Gesamtdauer des beobachteten Flows (min über beide Richtungen bis max)
        begin_ts = min([t for t in [f_first, r_first] if t is not None], default=None)
        end_ts   = max([t for t in [f_last,  r_last ] if t is not None], default=None)
        duration = (end_ts - begin_ts) if (begin_ts is not None and end_ts is not None) else None

        merged_feats.append({
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "first_seen": begin_ts, "last_seen": end_ts, "duration": duration,

            "bytes_c2s": bytes_c2s, "bytes_s2c": bytes_s2c,
            "pkts_c2s": pkts_c2s,   "pkts_s2c": pkts_s2c,

            "syn_c2s": syn_c2s, "fin_c2s": fin_c2s, "rst_c2s": rst_c2s, "ack_c2s": ack_c2s, "psh_c2s": psh_c2s,
            "syn_s2c": syn_s2c, "fin_s2c": fin_s2c, "rst_s2c": rst_s2c, "ack_s2c": ack_s2c, "psh_s2c": psh_s2c,

            "ttl_med_c2s": ttl_c2s, "ttl_med_s2c": ttl_s2c,
            "win_med_c2s": win_c2s, "win_med_s2c": win_s2c,

            "iat_mean_c2s": f_iat_mean, "iat_median_c2s": f_iat_med,
            "iat_mean_s2c": r_iat_mean, "iat_median_s2c": r_iat_med,

            "mss_c2s": mss_c2s, "wscale_c2s": wsc_c2s, "sack_c2s": sack_c2s,
            "mss_s2c": mss_s2c, "wscale_s2c": wsc_s2c, "sack_s2c": sack_s2c,

            "banner": banner,
            "kex_arr": kex_arr, "enc_arr": enc_arr, "mac_arr": mac_arr, "comp_arr": comp_arr,
            "computed_hassh": computed_hassh,
            "pcap_file": os.path.basename(pcapfile),
        })

    return merged_feats

def iter_cowrie_lines(path):
    """Liefert alle JSON-Zeilen aus cowrie.json; akzeptiert Datei oder Verzeichnis mit rotierenden Dateien."""
    if os.path.isdir(path):
        # typische Rotationsmuster: cowrie.json, cowrie.json.1, ...
        candidates = sorted(glob.glob(os.path.join(path, "cowrie.json*")))
    else:
        candidates = [path]

    for p in candidates:
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    yield ln

def load_cowrie_events(path):
    evts = []
    for ln in iter_cowrie_lines(path):
        try:
            j = json.loads(ln)
            evts.append(j)
        except Exception:
            continue
    return evts

def merge(features, events, time_window=TIME_WINDOW):
    """
    Merged PCAP-Features mit Cowrie-Events.
    Matching-Priorität:
      1) src_ip + (src_port,dst_port) + Zeitfenster
      2) src_ip + dst_port (SSH_PORT) + Zeitfenster
      3) src_ip + nur Zeitnähe
    """
    # Indexe
    by_src = {}
    by_src_ports = {}  # (src, sport, dport) -> list
    by_src_dport = {}  # (src, dport) -> list

    for f in features:
        by_src.setdefault(f["src"], []).append(f)
        key_ports = (f["src"], f.get("sport"), f.get("dport"))
        by_src_ports.setdefault(key_ports, []).append(f)
        key_dport = (f["src"], f.get("dport"))
        by_src_dport.setdefault(key_dport, []).append(f)

    def pick_best(candidates, ts):
        if not candidates:
            return None
        if ts is None:
            return candidates[0]
        cand = sorted(
            candidates,
            key=lambda c: abs(((c.get("first_seen") or c.get("last_seen") or ts) - ts))
        )
        best = cand[0]
        # harte Schranke
        fs = best.get("first_seen")
        if fs is not None and abs(fs - ts) > time_window:
            return None
        return best

    merged = []
    for e in events:
        src = e.get("src_ip") or e.get("src")
        ts = None
        if "timestamp" in e:
            try:
                ts = dateparser.parse(e["timestamp"]).timestamp()
            except Exception:
                ts = None

        chosen = None

        # Versuche 5-Tuple-Match (nur falls Ports im Event vorhanden sind)
        sport = e.get("src_port")
        dport = e.get("dst_port")
        if src and sport and dport:
            chosen = pick_best(by_src_ports.get((src, sport, dport), []), ts)

        # Fallback: src + dport
        if chosen is None and src:
            chosen = pick_best(by_src_dport.get((src, SSH_PORT), []), ts)

        # Fallback: nur src
        if chosen is None and src:
            chosen = pick_best(by_src.get(src, []), ts)

        merged.append({
            "event": e,
            "pcap_feature": chosen
        })

    return merged

def write_outputs(merged):
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
    print(f"[extractor] wrote {OUT_JSON} with {len(merged)} merged items.")

    if OUT_NDJSON:
        os.makedirs(os.path.dirname(OUT_NDJSON), exist_ok=True)
        with open(OUT_NDJSON, "w", encoding="utf-8") as fh:
            for m in merged:
                fh.write(json.dumps(m) + "\n")
        print(f"[extractor] wrote NDJSON {OUT_NDJSON}")

def main():
    # 1) PCAP-Features sammeln
    all_feats = []
    pcap_files = sorted(glob.glob(os.path.join(PCAP_DIR, PCAP_GLOB)))
    if not pcap_files:
        print(f"[extractor] no pcap files found in {PCAP_DIR} (pattern {PCAP_GLOB})")
    for f in pcap_files:
        feats = process_pcap_file(f)
        all_feats.extend(feats)

    # 2) Cowrie-Events laden
    events = load_cowrie_events(COWRIE_LOG)
    print(f"[extractor] events: {len(events)}  pcap_streams: {len(all_feats)}")

    # 3) Mergen
    merged = merge(all_feats, events, TIME_WINDOW)

    # 4) Schreiben
    write_outputs(merged)

if __name__ == "__main__":
    main()
