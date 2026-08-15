#!/usr/bin/env python3
"""
AI Guard Pro — Honeypot
Fake ports to trap attackers
"""

import socket
import threading
import time
from datetime import datetime

# Fake ports to trap attackers
HONEYPOT_PORTS = [3389, 445, 1433, 5900, 22]
ATTEMPTS = {}
ALERT_THRESHOLD = 1  # 1 attempt = immediate alert

def log_honeypot_attack(ip, port):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[HONEYPOT] {timestamp} | ATTACKER: {ip} | Port: {port}"
    print(msg)
    # Save to log
    with open("/var/log/ai-guard-honeypot.log", "a") as f:
        f.write(msg + "\n")
    return msg

def handle_honeypot_connection(conn, addr, port):
    ip = addr[0]
    log_honeypot_attack(ip, port)
    
    # Send fake banner to trick attacker
    fake_banner = b"Windows Server 2019\r\nLogin: "
    try:
        conn.send(fake_banner)
    except:
        pass
    finally:
        conn.close()
    
    # Block the IP immediately
    try:
        import subprocess
        subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"], check=False)
        print(f"[HONEYPOT] Blocked {ip} via iptables")
    except Exception as e:
        print(f"[HONEYPOT] iptables error: {e}")

def start_honeypot_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[HONEYPOT] Listening on port {port} (TRAP)")
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_honeypot_connection, args=(conn, addr, port), daemon=True).start()
    except Exception as e:
        print(f"[HONEYPOT] Port {port} error: {e}")

def start_all_honeypots():
    print("=" * 50)
    print("AI Guard Pro — Honeypot Starting...")
    print("Fake ports:", HONEYPOT_PORTS)
    print("=" * 50)
    
    for port in HONEYPOT_PORTS:
        threading.Thread(target=start_honeypot_port, args=(port,), daemon=True).start()
    
    print("[HONEYPOT] All honeypot ports active!")
    print("[HONEYPOT] Waiting for attackers...\n")

if __name__ == "__main__":
    start_all_honeypots()
    # Keep running
    while True:
        time.sleep(60)
