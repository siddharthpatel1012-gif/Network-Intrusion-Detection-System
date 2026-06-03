"""
Network Intrusion Detection System (IDS)
Core engine: packet capture simulation + ML anomaly detection
"""

import random
import time
import threading
import json
import math
from datetime import datetime
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from typing import List, Optional


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    flags: str
    ttl: int

@dataclass
class Alert:
    id: str
    timestamp: str
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL
    attack_type: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    description: str
    anomaly_score: float


# ─── Feature Extraction ───────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts statistical features from a sliding window of packets
    for a given source IP, used as input to the anomaly detector.
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.ip_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.port_counters: dict[str, set] = defaultdict(set)
        self.syn_counters: dict[str, int] = defaultdict(int)

    def add_packet(self, pkt: Packet):
        self.ip_windows[pkt.src_ip].append(pkt)
        self.port_counters[pkt.src_ip].add(pkt.dst_port)
        if 'SYN' in pkt.flags and 'ACK' not in pkt.flags:
            self.syn_counters[pkt.src_ip] += 1

    def extract(self, src_ip: str) -> Optional[dict]:
        window = list(self.ip_windows[src_ip])
        if len(window) < 5:
            return None

        lengths     = [p.length for p in window]
        ttls        = [p.ttl    for p in window]
        ports       = [p.dst_port for p in window]
        protocols   = [p.protocol for p in window]

        def mean(xs):   return sum(xs) / len(xs)
        def stdev(xs):
            m = mean(xs)
            return math.sqrt(sum((x - m)**2 for x in xs) / len(xs))

        unique_ports    = len(set(ports))
        unique_protos   = len(set(protocols))
        syn_ratio       = self.syn_counters[src_ip] / max(len(window), 1)
        pkt_rate        = len(window) / max((window[-1].timestamp - window[0].timestamp), 0.001)

        return {
            "pkt_count":        len(window),
            "mean_length":      mean(lengths),
            "std_length":       stdev(lengths),
            "mean_ttl":         mean(ttls),
            "unique_dst_ports": unique_ports,
            "unique_protocols": unique_protos,
            "syn_ratio":        syn_ratio,
            "pkt_rate":         pkt_rate,
        }


# ─── ML Anomaly Detector (Isolation-Forest-inspired, pure Python) ─────────────

class AnomalyDetector:
    """
    Lightweight statistical anomaly detector.
    Uses z-score based outlier detection on extracted features.
    Mimics the behaviour of an Isolation Forest without external deps.
    """

    # Normal traffic baseline (mean, std) per feature
    BASELINE = {
        "mean_length":      (512,  300),
        "std_length":       (200,  150),
        "mean_ttl":         (64,   10),
        "unique_dst_ports": (3,    2),
        "syn_ratio":        (0.15, 0.1),
        "pkt_rate":         (10,   8),
    }

    def score(self, features: dict) -> float:
        """Returns anomaly score 0-1 (higher = more anomalous)."""
        z_scores = []
        for feat, (mu, sigma) in self.BASELINE.items():
            val = features.get(feat, mu)
            z   = abs(val - mu) / max(sigma, 1e-9)
            z_scores.append(z)

        # Normalise: mean z-score mapped through sigmoid-like curve
        mean_z = sum(z_scores) / len(z_scores)
        score  = 1 / (1 + math.exp(-0.5 * (mean_z - 2)))
        return round(score, 4)


# ─── Attack Classifier ────────────────────────────────────────────────────────

class AttackClassifier:
    """Rule-based classifier that labels detected anomalies."""

    def classify(self, features: dict, pkt: Packet) -> tuple[str, str, str]:
        """Returns (attack_type, severity, description)."""
        ports      = features["unique_dst_ports"]
        syn_ratio  = features["syn_ratio"]
        pkt_rate   = features["pkt_rate"]
        mean_len   = features["mean_length"]

        # Port scan
        if ports > 20:
            return (
                "Port Scan",
                "HIGH",
                f"Source scanned {ports} distinct ports — likely reconnaissance."
            )

        # SYN flood
        if syn_ratio > 0.8 and pkt_rate > 50:
            return (
                "SYN Flood",
                "CRITICAL",
                f"SYN ratio {syn_ratio:.0%} at {pkt_rate:.0f} pkt/s — DoS attack suspected."
            )

        # Ping flood / ICMP flood
        if pkt.protocol == "ICMP" and pkt_rate > 100:
            return (
                "ICMP Flood",
                "HIGH",
                f"ICMP flood at {pkt_rate:.0f} pkt/s from {pkt.src_ip}."
            )

        # Unusually large packets (potential data exfil)
        if mean_len > 1400:
            return (
                "Data Exfiltration",
                "CRITICAL",
                f"Mean packet size {mean_len:.0f}B — possible data exfiltration."
            )

        # Brute force (many packets to same port)
        if pkt.dst_port in (22, 3389, 21, 23) and pkt_rate > 20:
            svc = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet"}[pkt.dst_port]
            return (
                f"{svc} Brute Force",
                "HIGH",
                f"High-rate traffic to {svc} port — brute-force login attempt."
            )

        # Generic anomaly
        return (
            "Anomalous Traffic",
            "MEDIUM",
            "Statistical anomaly detected; pattern deviates from baseline."
        )


# ─── Traffic Simulator ────────────────────────────────────────────────────────

class TrafficSimulator:
    """
    Generates synthetic network traffic — a mix of benign packets
    and periodic attack bursts — for demonstration purposes.
    """

    NORMAL_IPS    = [f"192.168.1.{i}" for i in range(2, 20)]
    ATTACKER_IPS  = ["10.0.0.99", "172.16.0.55", "203.0.113.7", "198.51.100.42"]
    INTERNAL_IPS  = [f"192.168.1.{i}" for i in range(100, 120)]
    COMMON_PORTS  = [80, 443, 22, 53, 8080, 3306, 5432]
    PROTOCOLS     = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]

    def __init__(self):
        self._attack_mode  = False
        self._attack_type  = None
        self._attack_timer = 0

    def next_packet(self) -> Packet:
        now = time.time()

        # Randomly trigger attack bursts
        if not self._attack_mode and random.random() < 0.002:
            self._attack_mode  = True
            self._attack_type  = random.choice(
                ["port_scan", "syn_flood", "brute_force", "exfil", "icmp_flood"]
            )
            self._attack_timer = random.randint(30, 80)

        if self._attack_mode:
            self._attack_timer -= 1
            if self._attack_timer <= 0:
                self._attack_mode = False
            pkt = self._attack_packet(now)
        else:
            pkt = self._normal_packet(now)

        return pkt

    def _normal_packet(self, ts: float) -> Packet:
        return Packet(
            timestamp = ts,
            src_ip    = random.choice(self.NORMAL_IPS),
            dst_ip    = random.choice(self.INTERNAL_IPS),
            src_port  = random.randint(1024, 65535),
            dst_port  = random.choice(self.COMMON_PORTS),
            protocol  = random.choice(self.PROTOCOLS),
            length    = int(random.gauss(512, 200)),
            flags     = random.choice(["ACK", "ACK PSH", "SYN ACK", ""]),
            ttl       = random.randint(60, 128),
        )

    def _attack_packet(self, ts: float) -> Packet:
        attacker = random.choice(self.ATTACKER_IPS)
        victim   = random.choice(self.INTERNAL_IPS)

        if self._attack_type == "port_scan":
            return Packet(ts, attacker, victim,
                          random.randint(1024,65535), random.randint(1,65535),
                          "TCP", random.randint(40,80), "SYN", random.randint(32,64))

        if self._attack_type == "syn_flood":
            return Packet(ts, attacker, victim,
                          random.randint(1024,65535), 80,
                          "TCP", 60, "SYN", random.randint(32,64))

        if self._attack_type == "brute_force":
            port = random.choice([22, 3389, 21])
            return Packet(ts, attacker, victim,
                          random.randint(1024,65535), port,
                          "TCP", random.randint(100,300), "SYN ACK", 64)

        if self._attack_type == "exfil":
            return Packet(ts, attacker, "8.8.8.8",
                          random.randint(1024,65535), 443,
                          "HTTPS", random.randint(1300,1500), "ACK PSH", 128)

        if self._attack_type == "icmp_flood":
            return Packet(ts, attacker, victim,
                          0, 0, "ICMP", 64, "", random.randint(32,64))

        return self._normal_packet(ts)


# ─── IDS Core ─────────────────────────────────────────────────────────────────

class IDS:
    """
    Orchestrates packet capture, feature extraction,
    anomaly scoring and alert generation.
    """

    ALERT_THRESHOLD = 0.55

    def __init__(self):
        self.extractor  = FeatureExtractor()
        self.detector   = AnomalyDetector()
        self.classifier = AttackClassifier()
        self.simulator  = TrafficSimulator()

        self.alerts:   List[Alert] = []
        self.packets:  deque       = deque(maxlen=500)
        self.stats = {
            "total_packets":  0,
            "total_alerts":   0,
            "packets_per_sec": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "top_attackers":  defaultdict(int),
            "protocol_dist":  defaultdict(int),
        }
        self._running  = False
        self._lock     = threading.Lock()
        self._alert_id = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        threading.Thread(target=self._capture_loop, daemon=True).start()

    def stop(self):
        self._running = False

    def get_state(self) -> dict:
        with self._lock:
            return {
                "alerts":        [asdict(a) for a in self.alerts[-50:]],
                "recent_packets": list(self.packets)[-20:],
                "stats":         {
                    **self.stats,
                    "top_attackers": dict(
                        sorted(self.stats["top_attackers"].items(),
                               key=lambda x: x[1], reverse=True)[:5]
                    ),
                    "protocol_dist": dict(self.stats["protocol_dist"]),
                    "severity_counts": dict(self.stats["severity_counts"]),
                },
            }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _capture_loop(self):
        """Try real Scapy capture first; fall back to simulator if unavailable."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP as ICMP_layer
            print("[IDS] Scapy found — starting REAL packet capture.")
            print("[IDS] Listening on all interfaces...")
            self._pps_window = deque(maxlen=10)
            self._last_pps_time = time.time()
            self._pps_count = 0

            def handle(raw):
                if not self._running:
                    return
                if IP not in raw:
                    return

                # Determine protocol
                if TCP in raw:
                    proto    = "TCP"
                    src_port = raw[TCP].sport
                    dst_port = raw[TCP].dport
                    flags    = str(raw[TCP].flags)
                elif UDP in raw:
                    proto    = "UDP"
                    src_port = raw[UDP].sport
                    dst_port = raw[UDP].dport
                    flags    = ""
                elif ICMP_layer in raw:
                    proto    = "ICMP"
                    src_port = 0
                    dst_port = 0
                    flags    = ""
                else:
                    proto    = "OTHER"
                    src_port = 0
                    dst_port = 0
                    flags    = ""

                # Classify common app protocols by port
                if proto == "TCP":
                    if dst_port == 80  or src_port == 80:  proto = "HTTP"
                    elif dst_port == 443 or src_port == 443: proto = "HTTPS"
                    elif dst_port == 53  or src_port == 53:  proto = "DNS"
                elif proto == "UDP":
                    if dst_port == 53 or src_port == 53: proto = "DNS"

                pkt = Packet(
                    timestamp = time.time(),
                    src_ip    = raw[IP].src,
                    dst_ip    = raw[IP].dst,
                    src_port  = src_port,
                    dst_port  = dst_port,
                    protocol  = proto,
                    length    = len(raw),
                    flags     = flags,
                    ttl       = raw[IP].ttl,
                )
                self._process_packet(pkt)

                # Update pps
                self._pps_count += 1
                now = time.time()
                elapsed = now - self._last_pps_time
                if elapsed >= 1.0:
                    with self._lock:
                        self.stats["packets_per_sec"] = int(self._pps_count / elapsed)
                    self._pps_count = 0
                    self._last_pps_time = now

            sniff(prn=handle, store=False, stop_filter=lambda x: not self._running)

        except ImportError:
            print("[IDS] Scapy not installed — using traffic simulator.")
            print("[IDS] To use real traffic: pip install scapy")
            self._simulate_loop()

        except PermissionError:
            print("[IDS] Permission denied — run as Administrator for real capture.")
            print("[IDS] Falling back to simulator.")
            self._simulate_loop()

        except Exception as e:
            print(f"[IDS] Scapy error: {e} — falling back to simulator.")
            self._simulate_loop()

    def _simulate_loop(self):
        """Fallback: generate simulated traffic."""
        pps_window = deque(maxlen=10)
        while self._running:
            t0 = time.time()
            burst = random.randint(5, 20)
            for _ in range(burst):
                pkt = self.simulator.next_packet()
                self._process_packet(pkt)
            elapsed = time.time() - t0
            pps_window.append(burst / max(elapsed, 0.001))
            with self._lock:
                self.stats["packets_per_sec"] = int(sum(pps_window) / len(pps_window))
            time.sleep(0.1)

    def _process_packet(self, pkt: Packet):
        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["protocol_dist"][pkt.protocol] += 1
            self.packets.append({
                "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port, "dst_port": pkt.dst_port,
                "protocol": pkt.protocol, "length": pkt.length,
                "flags": pkt.flags,
                "time": datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S"),
            })

        self.extractor.add_packet(pkt)
        features = self.extractor.extract(pkt.src_ip)
        if features is None:
            return

        score = self.detector.score(features)
        if score >= self.ALERT_THRESHOLD:
            attack, severity, desc = self.classifier.classify(features, pkt)
            self._raise_alert(pkt, attack, severity, desc, score)

    def _raise_alert(self, pkt: Packet, attack: str, severity: str,
                     desc: str, score: float):
        with self._lock:
            self._alert_id += 1
            alert = Alert(
                id            = f"ALT-{self._alert_id:05d}",
                timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                severity      = severity,
                attack_type   = attack,
                src_ip        = pkt.src_ip,
                dst_ip        = pkt.dst_ip,
                dst_port      = pkt.dst_port,
                protocol      = pkt.protocol,
                description   = desc,
                anomaly_score = score,
            )
            self.alerts.append(alert)
            self.stats["total_alerts"] += 1
            self.stats["severity_counts"][severity] += 1
            self.stats["top_attackers"][pkt.src_ip] += 1