from config import BOT_TOKEN, CHAT_ID
#!/usr/bin/env python3
import socket
import threading
import requests
import subprocess
from datetime import datetime

# BOT_TOKEN = "8830379998:AAGI8dY_bRjPJ2bRzCdoX9hJJwl2KK3JaJE"
CHAT_ID = "7945236933"

def block_ip(ip):
    try:
        # IP ko iptables mein block karo
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        print(f"[BLOCKED] {ip} has been blocked!")
        return True
    except Exception as e:
        print(f"[BLOCK ERROR] {e}")
        return False

def send_alert(ip, port, blocked):
    action = "BLOCKED" if blocked else "ALERT ONLY"
    msg = f"🍯 <b>HONEYPOT TRAP!</b>\n\n<b>IP:</b> <code>{ip}</code>\n<b>Port:</b> {port}\n<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n\n🛡️ Action: <b>{action}</b>"
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=10)
        print(f"[ALERT SENT] Telegram message sent for {ip}")
    except Exception as e:
        print(f"[ALERT ERROR] {e}")

def honeypot(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[HONEYPOT] Port {port} ACTUALLY listening...")
    while True:
        conn, addr = s.accept()
        ip = addr[0]
        print(f"[HONEYPOT] ATTACKER: {ip} on port {port}")
        
        # Auto-block the attacker
        blocked = block_ip(ip)
        send_alert(ip, port, blocked)
        
        try:
            conn.send(b"Windows Server 2019\r\nLogin: ")
        except:
            pass
        conn.close()

for p in [3389, 8081, 22, 445, 5900]:
    threading.Thread(target=honeypot, args=(p,), daemon=True).start()

print("[HONEYPOT] Running! Press Ctrl+C to stop")
import time
while True:
    time.sleep(60)
