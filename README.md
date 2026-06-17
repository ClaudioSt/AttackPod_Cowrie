# 🛰️ Threat Intelligence Collector — basierend auf NetWatch

Dieses Projekt ist eine **Weiterentwicklung des [Netwatch.team](https://Netwatch.team)**-Projekts.  
Es dient zur **automatisierten Erfassung, Analyse und Visualisierung von SSH-Angriffsversuchen** aus Honeypot-Daten (z. B. [Cowrie](https://github.com/cowrie/cowrie)) und kann die gewonnenen Informationen an ein zentrales **Threat-Intelligence-System oder eine Analyseplattform** weiterleiten.

---

## ⚙️ Setup & Installation

### Voraussetzungen

- Docker & Docker Compose  
- Git  
- Optional: Threat-Intelligence-Plattform oder Analyse-Endpoint  

---

### 1️⃣ Repository klonen

```bash
git clone https://github.com/ClaudioSt/AttackPod_Cowrie.git
cd AttackPod_Cowrie
```

---

### 2️⃣ Beispiel-Konfiguration kopieren und anpassen

Kopiere die Beispieldatei:

```bash
cp .env.example .env
```

Bearbeite anschließend `.env` mit deinen eigenen Werten.

#### Umgebungsvariablen

| Variable | Beschreibung |
|-----------|---------------|
| `API_KEY` | API-Schlüssel zur Signierung oder Authentifizierung beim Senden von Daten |
| `COWRIE_SSH_PORT` | Externer Port, über den der SSH-Honeypot erreichbar ist (Standard: 2222) |
| `SENSOR_ID` | Eindeutiger Name oder ID des Sensors/Honeypots |
| `COLLECTOR_URL` | URL eines externen Systems, das die gesammelten Angriffsdaten entgegennimmt |
| `SEND_URL` | Optionaler Upload-Endpoint (wird meist identisch zu `COLLECTOR_URL` gesetzt) |
| `USE_TSHARK` | `1`, wenn das Image mit `tshark` gebaut wurde (zur erweiterten Protokollanalyse) |
| `ENABLE_WEB` | `1`, um das Web-Frontend zu aktivieren |
| `WEB_DOMAIN` | Domainname des Web-Frontends (z. B. `honeypot.example.org`) |
| `WEB_MAIL` | Kontakt- oder Zertifikats-E-Mailadresse für HTTPS-Konfiguration |
| `OUT_DIR` | Verzeichnis für generierte JSON-Daten (Standard: `/data/out`) |
| `PCAP_DIR` | Verzeichnis mit PCAP-Dateien (Standard: `/data/pcap`) |

---

### 3️⃣ Container starten

```bash
docker compose up -d
```

Dies startet:
- den **Cowrie-Honeypot**
- den **pcap-capture**-Dienst (tcpdump auf Port 2222)
- den **session-trigger** (überwacht Sessions und ruft pro Session-Ende `extractor.py` auf)
- den **Caddy-Webserver** (Dashboard)

---

### 4️⃣ Web-Interface öffnen

👉 [http://localhost:8080](http://localhost:8080)

Das Dashboard zeigt die letzten SSH-Sessions mit:
- Angreifer-IP, Login-Versuchen, Start-Zeit  
- `hassh`-Fingerprint und verwendeten SSH-Client-Banner  

---

### 5️⃣ (Optional) Weiterleitung an eine Threat-Intelligence-Plattform

Wenn `SEND_URL` oder `COLLECTOR_URL` gesetzt ist, werden Session-Zusammenfassungen automatisch als NDJSON-Einträge gesendet, z. B.:

```json
{
  "session_id": "a1b2c3d4",
  "src_ip": "203.0.113.45",
  "sensor_id": "honeypot-01",
  "login_attempts": [
    {"username": "root", "password": "123456"}
  ]
}
```

---

## 🧩 Architekturüberblick

```
+-----------------+
|    Cowrie SSH   |  <-- Honeypot
+-----------------+
          |
          v
+-----------------+     tail/parse      +-----------------+
|    trigger.py   | ----------------->  |  extractor.py   |
| (Session Watch) |                    | (PCAP + JSON)   |
+-----------------+                    +-----------------+
          |                                      |
          | schreibt JSONs                       |
          v                                      v
     /data/out/*.json                    (optional POST -> Threat-Intel-System)
          |
          v
+------------------+
|    index.html    |  <-- Dashboard via Caddy
+------------------+
```

---

## 🧠 Forschungshintergrund & gesammelte Telemetrie

Das System analysiert nicht nur einfache Login-Versuche, sondern komplette **SSH-Sitzungen (Sessions)** und sammelt umfangreiche **Metadaten über das Verbindungsverhalten, den TCP-Handshake und die SSH-Protokollverhandlungen**.

Diese Daten dienen der Generierung tiefergehender Threat-Intelligence-Indikatoren, die sich schwerer verändern lassen als IP-Adressen oder einfache Signaturen.

### 📡 Gesammelte Telemetriedaten

| Kategorie | Beschreibung |
|------------|---------------|
| **TCP-Handshakes** | SYN-, ACK-, MSS-, Window- und Timestamp-Werte, Reihenfolge der TCP-Optionen, RTT-Schätzung – Fingerprinting von OS-Stacks und Middleboxes |
| **SSH-Handshake** | Client-Version (`SSH-2.0-libssh-0.9.5`), Reihenfolge der Key-Exchange-, Cipher- und MAC-Algorithmen, KEX-Hashes (`hassh`), Startzeiten und Antwortlatenzen |
| **Session-Level** | Dauer, Authentifizierungsmethoden, Anzahl Login-Versuche, Kommandos, Dateiübertragungen, erkannte Botnet-Muster |
| **Public-Key-Reaktion** | Erkennung installierter Schlüssel durch Challenge-Verhalten (nach [Munteanu – Catch-22]) |
| **Netzwerk-Metadaten** | Quell-IP, Autonomous System, DNS, Hostname, Geo-Informationen, TLS/SSH-Client-Banner |
| **Artefakte & Dateien** | URLs, Hashes, Dateigrößen, MIME-Typen von heruntergeladenen oder ausgeführten Binärdateien |

Diese Herangehensweise wurde inspiriert durch aktuelle Forschungsarbeiten wie:

- **de Jonge (MD-Honeypot-SSH)** – Analyse von SSH-Handshakes zur passiven Identifikation von Clients und Angriffswerkzeugen.  
- **Ghiette et al. (TU Delft)** – Nutzung von Cipher- und Algorithmusreihenfolgen zur Identifikation von Brute-Force-Tools und Kampagnen.  
- **Baiardi et al. (Kex-Filtering)** – Nutzung von KEX-Fingerprints zur Abwehr durch passive Vorfilterung (ähnlich zu „JA3“ bei TLS).  
- **Munteanu et al. (IMC ’25)** – Langzeitbeobachtungen in Honeynets zeigen Verschiebungen in Angreiferverhalten und Werkzeugnutzung.  
- **Ulukapi et al. (Tracing Vendors)** – Untersuchung, wie Middleboxes oder Netzwerkgeräte Fingerprint-Daten verfälschen können.  

---

### 📦 Beispielstruktur einer Session-Datei

```json
{
  "session_id": "abc123",
  "src_ip": "<REDACTED_IP>",
  "src_port": 51542,
  "dst_ip": "<REDACTED_IP>",
  "dst_port": 2222,
  "protocol": "ssh",
  "first_seen": "2025-10-30T21:47:38+00:00",
  "last_seen": "2025-10-30T21:47:45+00:00",
  "sensor_id": "honeypot-01",
  "client_banner": "SSH-2.0-OpenSSH_for_Windows_9.5",
  "server_banner": "SSH-2.0-OpenSSH_8.0",
  "kex_algorithms": "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
  "ciphers": "chacha20-poly1305@openssh.com,aes128-ctr",
  "macs": "hmac-sha2-256-etm@openssh.com",
  "comps": "none,zlib@openssh.com",
  "hasshAlgorithms": "<REDACTED>",
  "hassh": "<REDACTED_HASH>",
  "login_attempts": [
    {"username": "<REDACTED>", "password": "<REDACTED>", "timestamp": "2025-10-30T21:47:41Z"}
  ],
  "fingerprint_sources": ["hassh", "client_banner", "tcp_options"],
  "pcap_path": "/data/pcap/ssh-20251030-214700.pcap",
  "packet_count": 4,
  "bytes": 296,
  "duration": 6.9,
  "iat_mean": 1.72,
  "iat_median": 0.004,
  "ttl_median": 64,
  "tcp_window_median": 64240,
  "tcp_options": [["MSS", 1460], "SAckOK", ["Timestamp", [123, 0]], ["WScale", 7]],
  "tcp_flag_counts": {"S": 1, "SA": 1, "A": 2},
  "retransmissions": 0,
  "_collected_at": "2025-10-30T21:47:46+00:00"
}
```

> Hinweis: `kex_algorithms`, `ciphers`, `macs` und `comps` werden als
> kommaseparierte Strings (so wie Cowrie sie liefert) gespeichert, nicht als
> JSON-Arrays.

Diese Struktur erlaubt sowohl **statistische Auswertung** als auch **Threat-Correlation** (z. B. Clustering ähnlicher Fingerprints).

---

## 📊 Nutzung der Daten für Threat Intelligence

- **Fingerprint-basierte Erkennung:** Nutzung von `hassh`/KEX-Hashes für Tool- oder Kampagnen-Zuordnung.  
- **Clustering:** Gruppierung ähnlicher Sessions über mehrere Sensoren hinweg zur Erkennung verteilter Angriffe.  
- **Langzeit-Trendanalysen:** Beobachtung von Veränderungen in Algorithmen, Fingerprints und Angriffsraten.  
- **Public-Key-Scanning:** Identifikation kompromittierter Systeme über bekannte Schlüssel.  
- **Korrelation mit externen Feeds:** Abgleich mit Feeds, DNS, und Artefakt-Hashes zur Attribution.

---

## 🧰 Lizenz & Danksagung

Basierend auf dem Projekt **[NetWatch.team](https://Netwatch.team)**  
Entwickelt im Rahmen einer Projektarbeit an der Hochschule Aalen im Modul „IT-Sicherheit in Dienstleistungsunternehmen“, betreut von den Lehrenden Phillip Schlinsog und Lars König (Allianz).