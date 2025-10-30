# 🧠 AttackPod Cowrie Honeypot

Ein modulares Honeypot-System basierend auf **Cowrie**, das SSH-Angriffe überwacht, Rohdaten (PCAP) aufzeichnet, Sitzungen analysiert und strukturierte Angriffsdaten an einen zentralen Collector sendet.

---

## 📦 Architekturübersicht

```
+---------------------------+
|      SSH Angreifer       |
+------------+--------------+
             |
             v
+---------------------------+
|         Cowrie            |   → erzeugt cowrie.json (Event-Logs)
| (SSH Honeypot Container)  |   → erzeugt PCAP (Rohdaten)
+------------+--------------+
             |
             v
+---------------------------+
|      Extractor            |   → verarbeitet PCAPs
|  - extrahiert Sessions    |   → korreliert mit Cowrie-Events
|  - erstellt merged_sessions.json
+------------+--------------+
             |
             v
+---------------------------+
|        Uploader           |   → sendet Daten als NDJSON POST
|  (an Collector Mock)      |   → /add_attack
+------------+--------------+
             |
             v
+---------------------------+
|       Collector Mock      |   → zeigt eingehende Daten an
+---------------------------+
```

---

## 🚀 Komponenten

| Komponente         | Beschreibung                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| **Cowrie**         | SSH-Honeypot, der Angriffsversuche simuliert und in JSON/PCAP protokolliert.                                            |
| **pcap-capture**   | Lauscht auf dem Docker-Netzwerk und schreibt `.pcap`-Dateien.                                                           |
| **Extractor**      | Liest PCAPs, extrahiert TCP-Sessions, berechnet Metriken (z. B. Bytes, IAT, Flags) und verknüpft sie mit Cowrie-Events. |
| **Uploader**       | Überträgt fertige Angriffsobjekte periodisch an den Collector (HTTP POST).                                              |
| **Collector Mock** | Einfacher Testserver, der empfangene POSTs im Log ausgibt (zur Debug-Überprüfung).                                      |

---

## ⚙️ Installation & Start

```bash
# Repository klonen
git clone <repo-url>
cd AttackPod_Cowrie

# Container bauen und starten
docker compose up -d --build

# Logs prüfen
docker logs -f cowrie
docker logs -f honeypot-extractor
docker logs -f honeypot-uploader
```

Nach kurzer Zeit sollte der **Collector Mock** Daten empfangen, z. B.:

```
2025-10-30 01:00:58 [collector_mock] Handling POST /add_attack
2025-10-30 01:00:58 [collector_mock] Body (parsed JSON): {
  "eventid": "cowrie.login.failed",
  "username": "root",
  "password": "1234",
  ...
}
```

---

## 📂 Wichtige Volumes

| Volume                        | Inhalt                                   |
| ----------------------------- | ---------------------------------------- |
| `attackpod_cowrie_cowrie_log` | Cowrie JSON Logs (`cowrie.json`)         |
| `attackpod_cowrie_pcap_data`  | Rohdaten aus PCAP-Capture (`ssh-*.pcap`) |
| `attackpod_cowrie_out_data`   | Ergebnisdateien (`merged_sessions.json`) |

---

## 📊 Datenformate

### Beispiel: Cowrie-Event

```json
{
  "eventid": "cowrie.login.failed",
  "username": "admin",
  "password": "123456",
  "src_ip": "172.18.0.1",
  "timestamp": "2025-10-30T00:54:49.537391Z"
}
```

### Beispiel: Extracted Session (merged_sessions.json)

```json
{
  "src_ip": "172.18.0.1",
  "dst_ip": "172.18.0.3",
  "duration": 8.12,
  "packet_count": 30,
  "bytes": 5433,
  "iat_mean": 0.28,
  "tcp_flag_counts": {"PA": 15, "A": 11, "S": 1, "SA": 1},
  "client_banner": "SSH-2.0-OpenSSH_for_Windows_9.5",
  "server_banner": "SSH-2.0-OpenSSH_9.2p1 Debian",
  "linked_cowrie_events": [...]
}
```

### Beispiel: Collector-POST (Uploader → Collector)

```http
POST /add_attack HTTP/1.1
Content-Type: application/x-ndjson

{"eventid": "cowrie.session.connect", ...}
{"eventid": "cowrie.login.failed", ...}
```

---

## 📈 Metriken (Extractor)

| Feld                              | Beschreibung                                      |
| --------------------------------- | ------------------------------------------------- |
| `duration`                        | Dauer der TCP-Session in Sekunden                 |
| `packet_count`                    | Anzahl der Pakete in der Session                  |
| `bytes`                           | Summe aller übertragenen Bytes                    |
| `iat_mean` / `iat_median`         | Durchschnittlicher / Median Inter-Arrival-Time    |
| `ttl_median`                      | Median der IP-TTLs (Hinweis auf OS)               |
| `tcp_flag_counts`                 | Anzahl TCP-Flags (z. B. SYN, ACK, PSH)            |
| `retransmissions`                 | Doppelte Sequenznummern (Heuristik)               |
| `client_banner` / `server_banner` | SSH-Versionsstrings erkannt im Payload            |
| `hassh`                           | Hash über KEX/Algorithmuslisten (SSH Fingerprint) |

---

## 🧩 Troubleshooting

| Problem                                                | Ursache / Lösung                                                   |
| ------------------------------------------------------ | ------------------------------------------------------------------ |
| `Read-only file system`                                | Volume wurde mit falschen Rechten eingebunden → `:rw` Mount prüfen |
| `No such file or directory: '/cowrie/log/cowrie.json'` | Volume-Pfad oder Mapping in `docker-compose.yml` prüfen            |
| `Extractor unhealthy`                                  | Leere oder korrupte `.pcap`-Dateien → ggf. alte Volumes löschen    |
| `pcap-capture conflict`                                | Vorherige Container-Instanz entfernen: `docker rm -f pcap-capture` |

---

## 🧹 Cleanup

```bash
# Alle Container, Netzwerke, Volumes löschen
docker compose down -v --remove-orphans
```

---

## 📚 Lizenz & Autor

**Autor:** Claudio
**Lizenz:** MIT License
**Version:** 1.0 (Oktober 2025)

---

> Dieses Setup ist ideal für die Analyse und Visualisierung von SSH-Angriffen in einer isolierten Forschungsumgebung. 💻
