#!/usr/bin/env python3
"""
AI Guard Pro — COMPLETE Main File (FIXED VERSION)
"""

import sys
import os
import time
import threading
import json
import subprocess
import socket
import requests
from datetime import datetime
from collections import defaultdict, deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# ========== CONFIG ==========
BOT_TOKEN = "8830379998:AAGI8dY_bRjPJ2bRzCdoX9hJJwl2KK3JaJE"
CHAT_ID = "7945236933"

PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW = 10
SYN_FLOOD_THRESHOLD = 80
ALERT_COOLDOWN = 300

BLOCKED_COUNTRIES = ["RU", "CN", "KP", "IR"]
WHITELIST_IPS = ["127.0.0.1", "192.168.8.1"]

MODEL_FILE = "/var/lib/ai-guard/ml_model.pkl"
SCALER_FILE = "/var/lib/ai-guard/ml_scaler.pkl"
TRAINING_DATA_FILE = "/var/lib/ai-guard/training_data.csv"
MIN_SAMPLES = 30
MAX_SAMPLES = 5000
ANOMALY_SCORE_THRESHOLD = 75

ALERT_LOG = "/var/log/ai-guard-alerts.log"
DEVICES_FILE = "/var/lib/ai-guard/devices.json"
os.makedirs("/var/lib/ai-guard", exist_ok=True)

# ========== STATE ==========
packet_count = 0
alert_count = 0
blocked_count = 0
training_data = deque(maxlen=MAX_SAMPLES)
last_retrain = 0
model = None
scaler = None
ml_lock = threading.Lock()

port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": 0})
syn_tracker = defaultdict(lambda: {"count": 0, "window_start": 0})
alert_history = {}
packet_stats = defaultdict(lambda: {
    'count': 0, 'ports': set(), 'sizes': [],
    'timestamps': deque(maxlen=100),
    'syn_count': 0, 'ack_count': 0
})

# ========== LOGGING ==========
def log_alert(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | {message}"
    print(line)
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")

# ========== TELEGRAM ==========
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {"chat_id": CHAT_ID, "text": message, "parse_mode": "HTML"}
        r = requests.post(url, data=data, timeout=10)
        return r.json().get("ok", False)
    except Exception as e:
        log_alert(f"[TELEGRAM ERROR] {e}")
        return False

# ========== IPTABLES ==========
def block_ip(ip):
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                     capture_output=True, text=True)
        return True
    except:
        pass
    try:
        subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"], check=True)
        log_alert(f"[BLOCK] {ip}")
        return True
    except Exception as e:
        log_alert(f"[BLOCK ERROR] {ip}: {e}")
        return False

# ========== GEOIP ==========
def get_country(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "LOCAL", "Local"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country,status", timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return d.get("countryCode", "UNKNOWN"), d.get("country", "Unknown")
    except:
        pass
    return "UNKNOWN", "Unknown"

# ========== ML ==========
def init_ml():
    global model, scaler, last_retrain, training_data
    if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            scaler = joblib.load(SCALER_FILE)
            if os.path.exists(TRAINING_DATA_FILE):
                import pandas as pd
                df = pd.read_csv(TRAINING_DATA_FILE)
                training_data.extend(df.values.tolist())
            last_retrain = time.time()
            log_alert(f"[ML] Loaded. Samples: {len(training_data)}")
            return True
        except Exception as e:
            log_alert(f"[ML] Load error: {e}")
    model = IsolationForest(n_estimators=20, contamination=0.1, random_state=42, max_samples='auto', n_jobs=1)
    scaler = StandardScaler()
    log_alert("[ML] New model created")
    return False

def extract_features(src_ip, dst_ip, dst_port, protocol, packet_size, tcp_flags=None):
    now = time.time()
    st = packet_stats[src_ip]
    st['count'] += 1
    st['ports'].add(dst_port)
    st['sizes'].append(packet_size)
    st['timestamps'].append(now)
    if tcp_flags:
        if 'S' in tcp_flags and 'A' not in tcp_flags:
            st['syn_count'] += 1
        if 'A' in tcp_flags:
            st['ack_count'] += 1
    recent = [t for t in st['timestamps'] if now - t <= 10]
    pps = len(recent)
    up = len(st['ports'])
    rs = st['sizes'][-20:] if st['sizes'] else [packet_size]
    avg = sum(rs) / len(rs)
    var = np.var(rs) if len(rs) > 1 else 0
    pn = 6 if protocol == 'TCP' else 17 if protocol == 'UDP' else 1 if protocol == 'ICMP' else 0
    tot = st['count']
    sr = st['syn_count'] / tot if tot > 0 else 0
    return [pps, up, dst_port, pn, packet_size, avg, var, sr]

def get_ml_score(features):
    global model, scaler, training_data, last_retrain
    with ml_lock:
        training_data.append(features)
        if len(training_data) < MIN_SAMPLES:
            return 0, False, f"Learning ({len(training_data)}/{MIN_SAMPLES})"
        if not hasattr(model, 'offset_'):
            log_alert("[ML] First training... wait 20-40 sec")
            X = np.array(list(training_data))
            scaler.fit(X)
            model.fit(scaler.transform(X))
            joblib.dump(model, MODEL_FILE)
            joblib.dump(scaler, SCALER_FILE)
            last_retrain = time.time()
            log_alert("[ML] Training complete!")
        X = scaler.transform(np.array(features).reshape(1, -1))
        raw = model.decision_function(X)[0]
        score = max(0, min(100, int((1 - (raw + 0.5)) * 100)))
        return score, score >= ANOMALY_SCORE_THRESHOLD, "Anomaly!" if score >= ANOMALY_SCORE_THRESHOLD else "Normal"

# ========== ALERTS ==========
def should_alert(atype, ip):
    key = f"{atype}:{ip}"
    now = time.time()
    if key in alert_history and now - alert_history[key] < ALERT_COOLDOWN:
        return False
    alert_history[key] = now
    return True

def fmt_alert(atype, ip, details, score=None):
    em = {"PORT_SCAN": "🎯", "SYN_FLOOD": "📡", "GEOIP_BLOCK": "🌍", "AI_ANOMALY": "🤖"}.get(atype, "⚠️")
    m = f"{em} <b>AI Guard Alert!</b>\n\n<b>Type:</b> {atype}\n<b>IP:</b> <code>{ip}</code>\n"
    if score:
        m += f"<b>AI Score:</b> {score}/100\n"
    m += f"<b>Details:</b> {details}\n<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n\n🛡️ Action: BLOCKED"
    return m

# ========== PACKET PROCESSING ==========
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "192.168.8.150"

LOCAL_IP = get_local_ip()

def process_packet(pkt):
    global packet_count, alert_count, blocked_count
    packet_count += 1
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if src == LOCAL_IP or src == "127.0.0.1":
            return
        
        # TRUSTED CHECK COMMENTED FOR TESTING
        # devices ko load karo lekin skip mat karo
        # if src in devices and devices[src].get("trusted"):
        #     return

        dst_port = 0
        proto = "OTHER"
        flags = None
        size = len(pkt)

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            proto = "TCP"
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        now = time.time()

        # Port Scan
        ps = port_scan_tracker[src]
        if ps["first_seen"] == 0:
            ps["first_seen"] = now
        ps["ports"].add(dst_port)
        if now - ps["first_seen"] > PORT_SCAN_WINDOW:
            ps["ports"].clear()
            ps["first_seen"] = now
        if len(ps["ports"]) >= PORT_SCAN_THRESHOLD and should_alert("PORT_SCAN", src):
            d = f"Scanned {len(ps['ports'])} ports in {PORT_SCAN_WINDOW}s"
            send_telegram(fmt_alert("PORT_SCAN", src, d))
            block_ip(src)
            log_alert(f"[!] PORT_SCAN {src} | {d}")
            alert_count += 1
            blocked_count += 1
            ps["ports"].clear()

        # SYN Flood
        if proto == "TCP" and flags and "S" in flags and "A" not in flags:
            st = syn_tracker[src]
            if now - st["window_start"] > 10:
                st["count"] = 0
                st["window_start"] = now
            st["count"] += 1
            if st["count"] >= SYN_FLOOD_THRESHOLD and should_alert("SYN_FLOOD", src):
                d = f"{st['count']} SYN in 10s"
                send_telegram(fmt_alert("SYN_FLOOD", src, d))
                block_ip(src)
                log_alert(f"[!] SYN_FLOOD {src} | {d}")
                alert_count += 1
                blocked_count += 1

        # GeoIP
        if packet_count % 10 == 0:
            cc, cn = get_country(src)
            if cc in BLOCKED_COUNTRIES and should_alert("GEOIP_BLOCK", src):
                d = f"GeoIP Block: {cn} ({cc})"
                send_telegram(fmt_alert("GEOIP_BLOCK", src, d))
                block_ip(src)
                log_alert(f"[!] GEOIP_BLOCK {src} | {d}")
                alert_count += 1
                blocked_count += 1

        # ML
        if packet_count % 5 == 0:
            try:
                f = extract_features(src, dst, dst_port, proto, size, flags)
                sc, anom, status = get_ml_score(f)
                if anom and should_alert("AI_ANOMALY", src):
                    d = f"AI detected unusual pattern"
                    send_telegram(fmt_alert("AI_ANOMALY", src, d, sc))
                    block_ip(src)
                    log_alert(f"[!] AI_ANOMALY {src} | Score: {sc}")
                    alert_count += 1
                    blocked_count += 1
            except:
                pass

        if packet_count % 100 == 0:
            print(f"[STATS] Packets: {packet_count} | Alerts: {alert_count} | Blocked: {blocked_count}")

    except Exception as e:
        pass

# ========== HONEYPOT ==========
def honeypot_listener(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        log_alert(f"[HONEYPOT] Port {port} active (TRAP)")
        while True:
            conn, addr = s.accept()
            ip = addr[0]
            log_alert(f"[HONEYPOT] ATTACKER: {ip} on port {port}")
            msg = f"🍯 <b>HONEYPOT TRAP!</b>\n\n<b>IP:</b> <code>{ip}</code>\n<b>Port:</b> {port}\n<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n\n🛡️ Action: BLOCKED"
            send_telegram(msg)
            block_ip(ip)
            try:
                conn.send(b"Windows Server 2019\r\nLogin: ")
            except:
                pass
            conn.close()
    except Exception as e:
        log_alert(f"[HONEYPOT] Port {port} error: {e}")

def start_honeypots():
    HONEYPOT_PORTS = [3389, 445, 1433, 5900]
    log_alert("[HONEYPOT] Starting...")
    for port in HONEYPOT_PORTS:
        threading.Thread(target=honeypot_listener, args=(port,), daemon=True).start()
    log_alert("[HONEYPOT] All honeypot ports active!")

# ========== MAIN ==========
if __name__ == "__main__":
    print("=" * 60)
    print("AI Guard Pro — COMPLETE Engine (FIXED)")
    print("=" * 60)
    init_ml()
    start_honeypots()
    startup = f"🚀 <b>AI Guard Pro Started!</b>\n\n📍 Monitoring: {LOCAL_IP}\n🤖 AI: Active\n⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    send_telegram(startup)
    log_alert("[STARTUP] AI Guard Pro started")
    print("[MONITOR] Starting packet capture on eth0...")
    print("[MONITOR] Press Ctrl+C to stop\n")
    try:
        from scapy.all import sniff
        sniff(iface="eth0", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print(f"\n[STOP] Packets: {packet_count} | Alerts: {alert_count} | Blocked: {blocked_count}")
    except Exception as e:
        print(f"[ERROR] {e}")
