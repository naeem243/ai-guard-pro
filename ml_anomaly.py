#!/usr/bin/env python3
"""
AI Guard Pro — ML Anomaly Detection (Lightweight LXC Version)
Uses IsolationForest to detect unusual network traffic
Optimized for 2GB RAM LXC containers
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
import threading
from datetime import datetime
from collections import deque, defaultdict

# ========== CONFIG ==========
MODEL_FILE = "/var/lib/ai-guard/ml_model.pkl"
SCALER_FILE = "/var/lib/ai-guard/ml_scaler.pkl"
TRAINING_DATA_FILE = "/var/lib/ai-guard/training_data.csv"
MIN_SAMPLES = 30
RETRAIN_INTERVAL = 86400
MAX_SAMPLES = 5000

ANOMALY_SCORE_THRESHOLD = 75

lock = threading.Lock()

training_data = deque(maxlen=MAX_SAMPLES)
last_retrain = 0
model = None
scaler = None

packet_stats = defaultdict(lambda: {
    'count': 0,
    'ports': set(),
    'sizes': [],
    'timestamps': deque(maxlen=100),
    'syn_count': 0,
    'ack_count': 0,
    'fin_count': 0,
    'rst_count': 0
})

def init_model():
    global model, scaler, last_retrain, training_data
    os.makedirs("/var/lib/ai-guard", exist_ok=True)
    with lock:
        if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
            try:
                model = joblib.load(MODEL_FILE)
                scaler = joblib.load(SCALER_FILE)
                if os.path.exists(TRAINING_DATA_FILE):
                    df = pd.read_csv(TRAINING_DATA_FILE)
                    training_data.extend(df.values.tolist())
                last_retrain = time.time()
                print(f"[ML] Model loaded. Samples: {len(training_data)}")
                return True
            except Exception as e:
                print(f"[ML] Load error: {e}")
        model = IsolationForest(
            n_estimators=20,
            contamination=0.1,
            random_state=42,
            max_samples='auto',
            n_jobs=1
        )
        scaler = StandardScaler()
        print("[ML] New lightweight model created (LXC optimized)")
        return False

def extract_features(src_ip, dst_ip, dst_port, protocol, packet_size, tcp_flags=None):
    now = time.time()
    stats = packet_stats[src_ip]
    stats['count'] += 1
    stats['ports'].add(dst_port)
    stats['sizes'].append(packet_size)
    stats['timestamps'].append(now)
    if tcp_flags:
        if 'S' in tcp_flags and 'A' not in tcp_flags:
            stats['syn_count'] += 1
        if 'A' in tcp_flags:
            stats['ack_count'] += 1
        if 'F' in tcp_flags:
            stats['fin_count'] += 1
        if 'R' in tcp_flags:
            stats['rst_count'] += 1
    recent_timestamps = [t for t in stats['timestamps'] if now - t <= 10]
    packets_per_10sec = len(recent_timestamps)
    unique_ports = len(stats['ports'])
    recent_sizes = stats['sizes'][-20:] if stats['sizes'] else [packet_size]
    avg_size = sum(recent_sizes) / len(recent_sizes)
    size_variance = np.var(recent_sizes) if len(recent_sizes) > 1 else 0
    proto_num = 6 if protocol == 'TCP' else 17 if protocol == 'UDP' else 1 if protocol == 'ICMP' else 0
    total = stats['count']
    syn_ratio = stats['syn_count'] / total if total > 0 else 0
    features = [
        packets_per_10sec,
        unique_ports,
        dst_port,
        proto_num,
        packet_size,
        avg_size,
        size_variance,
        syn_ratio,
    ]
    return features

def get_anomaly_score(features):
    global model, scaler, training_data, last_retrain
    with lock:
        training_data.append(features)
        if len(training_data) < MIN_SAMPLES:
            return 0, False, f"Learning... ({len(training_data)}/{MIN_SAMPLES} samples)"
        if time.time() - last_retrain > RETRAIN_INTERVAL:
            retrain_model()
        if not hasattr(model, 'offset_'):
            print("[ML] >>> First time training... please wait 20-40 sec <<<")
            retrain_model()
        X = np.array(features).reshape(1, -1)
        X_scaled = scaler.transform(X)
        raw_score = model.decision_function(X_scaled)[0]
        normalized_score = int((1 - (raw_score + 0.5)) * 100)
        normalized_score = max(0, min(100, normalized_score))
        is_anomaly = normalized_score >= ANOMALY_SCORE_THRESHOLD
        status = "ANOMALY!" if is_anomaly else "Normal"
        return normalized_score, is_anomaly, status

def retrain_model():
    global model, scaler, last_retrain
    if len(training_data) < MIN_SAMPLES:
        print(f"[ML] Not enough samples: {len(training_data)}/{MIN_SAMPLES}")
        return False
    with lock:
        print("[ML] >>> STARTING TRAINING... <<<")
        print(f"[ML] Samples: {len(training_data)}")
        X = np.array(list(training_data))
        print("[ML] Data ready. Training... (20-40 sec on LXC)")
        scaler.fit(X)
        X_scaled = scaler.transform(X)
        model.fit(X_scaled)
        joblib.dump(model, MODEL_FILE)
        joblib.dump(scaler, SCALER_FILE)
        df = pd.DataFrame(list(training_data))
        df.to_csv(TRAINING_DATA_FILE, index=False)
        last_retrain = time.time()
        print("[ML] >>> TRAINING COMPLETE! <<<")
        return True

def get_model_status():
    return {
        'samples': len(training_data),
        'min_required': MIN_SAMPLES,
        'last_retrain': datetime.fromtimestamp(last_retrain).strftime("%Y-%m-%d %H:%M:%S") if last_retrain else "Never",
        'ready': len(training_data) >= MIN_SAMPLES,
        'threshold': ANOMALY_SCORE_THRESHOLD
    }

def reset_model():
    global training_data, model, scaler, last_retrain
    with lock:
        training_data.clear()
        model = IsolationForest(n_estimators=20, contamination=0.1, random_state=42, max_samples='auto', n_jobs=1)
        scaler = StandardScaler()
        last_retrain = 0
        for f in [MODEL_FILE, SCALER_FILE, TRAINING_DATA_FILE]:
            if os.path.exists(f):
                os.remove(f)
        print("[ML] Model reset complete")

if __name__ == "__main__":
    print("=" * 55)
    print("AI Guard Pro — ML Anomaly Detection (LXC Optimized)")
    print("=" * 55)
    init_model()
    print("\n[TEST] NORMAL traffic (35 packets)...")
    print("[TEST] Please wait... AI is learning...\n")
    for i in range(35):
        features = extract_features(
            src_ip="192.168.8.100",
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            packet_size=500 + np.random.randint(-50, 50),
            tcp_flags="SA"
        )
        score, is_anomaly, status = get_anomaly_score(features)
        if (i + 1) % 5 == 0:
            print(f"  Sample {i+1}: Score={score}, Status={status}")
    print("\n[TEST] ATTACK traffic (port scan)...\n")
    for i in range(10):
        features = extract_features(
            src_ip="45.142.212.50",
            dst_ip="192.168.8.150",
            dst_port=22 + i,
            protocol="TCP",
            packet_size=40,
            tcp_flags="S"
        )
        score, is_anomaly, status = get_anomaly_score(features)
        print(f"  Attack pkt {i+1}: Score={score}, Status={status}")
    status = get_model_status()
    print(f"\n[ML] Final Status: {status}")
    print("[ML] ML Anomaly Detection ready!")
