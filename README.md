# 🛡️ Network Intrusion Detection System (IDS)

> A real-time Network Intrusion Detection System built with **Python** and **Machine Learning**. Captures live network packets, detects anomalies, classifies attack types, and displays everything on a beautiful live web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![ML](https://img.shields.io/badge/Machine%20Learning-Anomaly%20Detection-FF6B35?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-00c896?style=for-the-badge)

---

## 📸 Live Dashboard

![Dashboard Preview](dashboard.png)

> Real-time packet monitoring, live charts, severity breakdown, top attackers panel, and one-click CSV export.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔴 **Real Packet Capture** | Captures live traffic using Scapy + Npcap |
| 🧠 **ML Anomaly Detection** | Z-score based scoring (0–100%) per source IP |
| ⚡ **Attack Classification** | Port Scan, SYN Flood, Brute Force, Data Exfiltration |
| 📊 **Live Charts** | Packets/sec and Alerts/sec over last 60 seconds |
| 🎯 **Severity Filters** | Filter alerts by CRITICAL / HIGH / MEDIUM / LOW |
| 📥 **Export to CSV** | Download full alert log with one click |
| 🌐 **Protocol Breakdown** | TCP, UDP, ICMP, HTTP, HTTPS, DNS distribution |
| 🏴‍☠️ **Top Attackers Panel** | Ranked list of most active attacker IPs |

---

## 🧠 How the ML Works

### 1. Feature Extraction
For each source IP, a **sliding window of 50 packets** is maintained and these features are extracted:

| Feature | Description |
|---------|-------------|
| `mean_length` | Average packet size in bytes |
| `std_length` | Variance in packet sizes |
| `mean_ttl` | Average Time-To-Live value |
| `unique_dst_ports` | Number of distinct destination ports |
| `syn_ratio` | Ratio of SYN packets (no ACK) |
| `pkt_rate` | Packets per second from this IP |

### 2. Anomaly Scoring
Each feature is compared to a **normal traffic baseline**. Z-scores are averaged and passed through a sigmoid:

```
score = 1 / (1 + e^(-0.5 * (mean_z - 2)))
```

Anything with **score ≥ 0.55** triggers attack classification.

### 3. Attack Classification Rules

| Attack Type | Rule |
|-------------|------|
| 🔴 Port Scan | `unique_dst_ports > 20` |
| 🔴 SYN Flood | `syn_ratio > 80%` AND `pkt_rate > 50/s` |
| 🔴 ICMP Flood | `protocol = ICMP` AND `pkt_rate > 100/s` |
| 🟠 Data Exfiltration | `mean_length > 1400 bytes` |
| 🟠 Brute Force | High rate to port `22` / `3389` / `21` / `23` |

---

## 📁 Project Structure

```
ids/
├── ids_engine.py         # 🧠 Core ML engine
│   ├── FeatureExtractor    → sliding window + feature computation
│   ├── AnomalyDetector     → z-score based anomaly scoring
│   ├── AttackClassifier    → rule-based attack labeling
│   └── TrafficSimulator    → synthetic traffic generator (fallback)
│
├── app.py                # 🌐 Flask web server
│   ├── GET  /              → dashboard UI
│   ├── GET  /api/state     → JSON snapshot
│   ├── GET  /api/stream    → SSE real-time stream
│   └── GET  /api/export/csv → download alerts as CSV
│
├── templates/
│   └── dashboard.html    # 🎨 Real-time web dashboard
│
└── requirements.txt
```

---

## ⚙️ Setup & Run

### Prerequisites
- Python 3.10+
- [Npcap](https://npcap.com/#download) (for real packet capture on Windows)

### Install dependencies
```bash
pip install -r requirements.txt
pip install scapy
```

### Run (normal mode — simulator)
```bash
python app.py
```

### Run (real traffic — Windows)
> ⚠️ Must run as **Administrator** for live packet capture

```bash
# Right click CMD → Run as Administrator
python app.py
```

### Open dashboard
```
http://127.0.0.1:5000
```

---

## 🔌 Real Traffic vs Simulator

The IDS automatically detects whether Scapy is available:

```
✅ [IDS] Scapy found — starting REAL packet capture.
⚠️  [IDS] Scapy not installed — using traffic simulator.
```

No code changes needed — it switches automatically.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.11 |
| Web Framework | Flask 3.0 |
| Packet Capture | Scapy + Npcap |
| ML Engine | Pure Python (no sklearn needed) |
| Real-Time Stream | Server-Sent Events (SSE) |
| Frontend | HTML5 / CSS3 / Vanilla JS |
| Charts | Chart.js 4.4 |
| Fonts | JetBrains Mono, Syne |

---

## 👨‍💻 Author

**Siddharth Patel**
- GitHub: [@siddharthpatel1012-gif](https://github.com/siddharthpatel1012-gif)

---

> *"Detect threats before they become breaches."* 🛡️
