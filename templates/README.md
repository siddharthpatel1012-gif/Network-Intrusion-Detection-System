# 🛡️ Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System built with Python and Machine Learning. Detects suspicious network traffic, classifies attack types, and displays live alerts on a web dashboard.

![Dashboard](https://img.shields.io/badge/Dashboard-Live-00c896?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![ML](https://img.shields.io/badge/ML-Anomaly%20Detection-orange?style=flat-square)

---

## 📸 Screenshots

### Live Dashboard
> Real-time packet monitoring, live charts, severity breakdown, and top attackers panel.

```
NET/IDS  •  LIVE  |  Packets: 29.1k  |  Pkt/s: 12108  |  Alerts: 2.3k  |  [Export CSV]
────────────────────────────────────────────────────────────────────────────────────────
Sidebar          │  Charts (Pkt/s & Alerts/s over 60s)     │  Packet Feed
─────────────────│──────────────────────────────────────────│──────────────
Total Packets    │  Intrusion Alerts Table                  │  Live packets
Total Alerts     │  ID | Time | Severity | Attack | Score   │  Top Attackers
Severity Bars    │  ALT-00001 | CRITICAL | SYN Flood | 94%  │
Protocol Dist    │  ALT-00002 | HIGH | Port Scan | 81%      │
Attack Types     │  ALT-00003 | MEDIUM | Anomalous | 62%    │
```

---

## 🚀 Features

- **Real-Time Packet Monitoring** — live packet feed with protocol, source/destination IP, port, and size
- **ML Anomaly Detection** — z-score based statistical detector scores each source IP's traffic (0–100%)
- **Attack Classification** — automatically labels detected threats:
  - 🔴 Port Scan
  - 🔴 SYN Flood (DoS)
  - 🔴 ICMP Flood
  - 🟠 SSH / RDP / FTP Brute Force
  - 🟠 Data Exfiltration
- **Live Charts** — packets/sec and alerts/sec plotted over the last 60 seconds
- **Severity Filters** — filter alerts by CRITICAL / HIGH / MEDIUM / LOW
- **Export to CSV** — download full alert log with one click
- **Top Attackers Panel** — ranked list of most active attacker IPs
- **Protocol Distribution** — breakdown of TCP, UDP, ICMP, HTTP, HTTPS, DNS traffic

---

## 🧠 How It Works

### 1. Feature Extraction
For each source IP, a **sliding window of 50 packets** is maintained. Features extracted per window:

| Feature | Description |
|---------|-------------|
| `mean_length` | Average packet size in bytes |
| `std_length` | Variance in packet sizes |
| `mean_ttl` | Average Time-To-Live value |
| `unique_dst_ports` | Number of distinct destination ports |
| `syn_ratio` | Ratio of SYN packets (no ACK) |
| `pkt_rate` | Packets per second from this IP |

### 2. Anomaly Detection
Each feature is compared to a **normal traffic baseline** (mean ± std). Z-scores are averaged and passed through a sigmoid function:

```
score = 1 / (1 + e^(-0.5 * (mean_z - 2)))
```

Packets with **score ≥ 0.55** trigger alert classification.

### 3. Attack Classification
Rule-based classifier labels the anomaly:
- **Port Scan** → unique_dst_ports > 20
- **SYN Flood** → syn_ratio > 80% AND pkt_rate > 50/s
- **ICMP Flood** → protocol=ICMP AND pkt_rate > 100/s
- **Data Exfiltration** → mean_length > 1400 bytes
- **Brute Force** → high rate to port 22/3389/21/23

---

## 📁 Project Structure

```
ids/
├── ids_engine.py        # Core ML engine
│   ├── FeatureExtractor   — sliding window + feature computation
│   ├── AnomalyDetector    — z-score based scoring
│   ├── AttackClassifier   — rule-based labeling
│   └── TrafficSimulator   — synthetic traffic generator
├── app.py               # Flask web server
│   ├── GET  /             — dashboard UI
│   ├── GET  /api/state    — JSON snapshot
│   ├── GET  /api/stream   — SSE real-time stream
│   └── GET  /api/export/csv — download alerts as CSV
├── templates/
│   └── dashboard.html   # Real-time web dashboard
└── requirements.txt
```

---

## ⚙️ Setup & Run

### Requirements
- Python 3.10+
- pip

### Install
```bash
pip install -r requirements.txt
```

### Run
```bash
python app.py
```

### Open
```
http://127.0.0.1:5000
```

---

## 🔌 Extending to Real Traffic

To capture **live network packets** instead of simulated traffic, use `scapy`:

```bash
pip install scapy
```

```python
from scapy.all import sniff, IP, TCP

def packet_callback(raw_pkt):
    if IP in raw_pkt:
        pkt = Packet(
            timestamp = time.time(),
            src_ip    = raw_pkt[IP].src,
            dst_ip    = raw_pkt[IP].dst,
            src_port  = raw_pkt[TCP].sport if TCP in raw_pkt else 0,
            dst_port  = raw_pkt[TCP].dport if TCP in raw_pkt else 0,
            protocol  = "TCP" if TCP in raw_pkt else "OTHER",
            length    = len(raw_pkt),
            flags     = str(raw_pkt[TCP].flags) if TCP in raw_pkt else "",
            ttl       = raw_pkt[IP].ttl,
        )
        ids._process_packet(pkt)

# Requires root/admin privileges
sniff(prn=packet_callback, store=False)
```

> ⚠️ Live packet capture requires **administrator/root privileges**.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| Web Framework | Flask 3.0 |
| ML Engine | Pure Python (no sklearn needed) |
| Real-Time Stream | Server-Sent Events (SSE) |
| Frontend | HTML5 / CSS3 / Vanilla JS |
| Charts | Chart.js 4.4 |
| Fonts | JetBrains Mono, Syne |

---

## 👨‍💻 Author

Built for Project Exhibition — Cybersecurity + ML track.

> *"Detect threats before they become breaches."*