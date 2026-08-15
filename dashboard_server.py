#!/usr/bin/env python3
from flask import Flask, render_template_string
import subprocess
import os
import json
import urllib.request
from datetime import datetime

app = Flask(__name__)

# Pi-hole API endpoint
PIHOLE_API = "http://127.0.0.1/admin/api.php?summaryRaw&topItems&getQuerySources&topClients"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Guard Pro + Pi-hole Dashboard</title>
    <meta http-equiv="refresh" content="15">
    <style>
        *{box-sizing:border-box}
        body{font-family:'Segoe UI',Arial,sans-serif;background:#0a0a1a;color:#e0e0e0;margin:0;padding:20px}
        .header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:30px;border-radius:16px;text-align:center;margin-bottom:25px;box-shadow:0 8px 32px rgba(102,126,234,.3)}
        .header h1{margin:0;font-size:36px;color:#fff}
        .header p{color:#e0e0ff;margin:8px 0 0;font-size:16px}
        .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:18px;margin-bottom:25px}
        .stat{background:#13132b;padding:22px;border-radius:14px;text-align:center;border:1px solid #252550;box-shadow:0 4px 20px rgba(0,0,0,.2)}
        .stat h2{margin:0;font-size:36px;color:#00ff88;text-shadow:0 0 10px rgba(0,255,136,.3)}
        .stat p{margin:8px 0 0;color:#a0a0c0;font-size:14px}
        .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-bottom:22px}
        @media(max-width:950px){.grid-2{grid-template-columns:1fr}}
        .section{background:#13132b;padding:22px;border-radius:14px;border:1px solid #252550;box-shadow:0 4px 20px rgba(0,0,0,.2)}
        .section h2{margin-top:0;color:#ffd700;border-bottom:2px solid #667eea;padding-bottom:12px;font-size:20px}
        table{width:100%;border-collapse:collapse;font-size:14px;margin-top:10px}
        th{background:#1e1e4b;padding:12px;text-align:left;color:#fff;font-weight:600;border-bottom:2px solid #667eea}
        td{padding:10px 12px;border-bottom:1px solid #252550}
        tr:hover{background:#1a1a45}
        .blocked{color:#ff6b6b;font-weight:bold}
        .allowed{color:#51cf66;font-weight:bold}
        .online{color:#00ff88;font-weight:bold}
        .small{font-size:12px;color:#888}
        .footer{text-align:center;color:#666;font-size:13px;margin-top:30px;padding:20px;border-top:1px solid #252550}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Guard Pro + 🕳️ Pi-hole</h1>
        <p>Network Security & DNS Filtering Dashboard &bull; Auto-refreshes every 15 seconds</p>
    </div>

    <div class="stats">
        <div class="stat">
            <h2>{{ total_attacks }}</h2>
            <p>🚨 Total Attacks</p>
        </div>
        <div class="stat">
            <h2>{{ blocked_ips }}</h2>
            <p>🚫 Blocked IPs</p>
        </div>
        <div class="stat">
            <h2>{{ honeypot_ports }}</h2>
            <p>🍯 Trap Ports</p>
        </div>
        <div class="stat">
            <h2>{{ pihole_queries }}</h2>
            <p>📊 DNS Queries Today</p>
        </div>
        <div class="stat">
            <h2>{{ pihole_blocked }}</h2>
            <p>🚫 Ads/Malware Blocked</p>
        </div>
        <div class="stat">
            <h2>{{ pihole_percent }}%</h2>
            <p>📉 Block Percentage</p>
        </div>
    </div>

    <div class="grid-2">
        <div class="section">
            <h2>🍯 Recent Honeypot Attacks</h2>
            <table>
                <tr><th>Time</th><th>Attacker IP</th><th>Port</th><th>Action</th></tr>
                {% for a in attacks %}
                <tr>
                    <td>{{ a.time }}</td>
                    <td>{{ a.ip }}</td>
                    <td>{{ a.port }}</td>
                    <td class="blocked">{{ a.action }}</td>
                </tr>
                {% endfor %}
                {% if not attacks %}
                <tr><td colspan="4" style="text-align:center;color:#888;padding:20px">No attacks yet. Honeypot is waiting...</td></tr>
                {% endif %}
            </table>
        </div>

        <div class="section">
            <h2>🚫 Blocked IPs (Firewall)</h2>
            {% if blocked_ips_list %}
            <table>
                <tr><th>#</th><th>IP Address</th></tr>
                {% for ip in blocked_ips_list %}
                <tr><td>{{ loop.index }}</td><td class="blocked">{{ ip }}</td></tr>
                {% endfor %}
            </table>
            {% else %}
            <p style="color:#888">No IPs blocked yet.</p>
            {% endif %}
        </div>
    </div>

    <div class="grid-2">
        <div class="section">
            <h2>🌐 Top Allowed Domains</h2>
            <p class="small">Websites/devices opened most frequently</p>
            <table>
                <tr><th>Domain</th><th>Hits</th></tr>
                {% for domain, hits in top_queries %}
                <tr><td>{{ domain }}</td><td class="allowed">{{ hits }}</td></tr>
                {% endfor %}
                {% if not top_queries %}
                <tr><td colspan="2" style="text-align:center;color:#888;padding:15px">Pi-hole data loading...<br>Make sure Pi-hole is running.</td></tr>
                {% endif %}
            </table>
        </div>

        <div class="section">
            <h2>🚫 Top Blocked Domains (Ads/Malware)</h2>
            <p class="small">Ads, trackers, malware domains blocked by Pi-hole</p>
            <table>
                <tr><th>Domain</th><th>Hits</th></tr>
                {% for domain, hits in top_ads %}
                <tr><td>{{ domain }}</td><td class="blocked">{{ hits }}</td></tr>
                {% endfor %}
                {% if not top_ads %}
                <tr><td colspan="2" style="text-align:center;color:#888;padding:15px">Pi-hole data loading...<br>Make sure Pi-hole is running.</td></tr>
                {% endif %}
            </table>
        </div>
    </div>

    <div class="section">
        <h2>📱 Top Devices (By DNS Queries)</h2>
        <p class="small">Which device is using the internet most? Shows IP and query count.</p>
        <table>
            <tr><th>#</th><th>Device IP / Name</th><th>Queries</th></tr>
            {% for client in top_clients %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ client.name or client.ip }}</td>
                <td>{{ client.count }}</td>
            </tr>
            {% endfor %}
            {% if not top_clients %}
            <tr><td colspan="3" style="text-align:center;color:#888;padding:15px">Pi-hole client data loading...<br>Router DNS set to Pi-hole?</td></tr>
            {% endif %}
        </table>
    </div>

    <div class="footer">
        <p>AI Guard Pro + Pi-hole Dashboard &bull; Last updated: {{ now }} &bull; Refresh: 15s</p>
    </div>
</body>
</html>
"""

def get_pihole_data():
    """Fetch Pi-hole API data"""
    try:
        req = urllib.request.Request(
            PIHOLE_API,
            headers={'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"[DASHBOARD] Pi-hole API error: {e}")
        return {}

def get_blocked_ips():
    """Get IPs blocked by iptables"""
    ips = []
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "DROP" in line and "all" in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3] not in ["0.0.0.0/0", "anywhere"]:
                    ips.append(parts[3])
    except Exception as e:
        print(f"[DASHBOARD] iptables error: {e}")
    return list(set(ips))

def parse_attacks_from_log(filepath):
    """Parse attack entries from log files"""
    attacks = []
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
        for line in lines:
            if "ATTACKER:" in line:
                time = datetime.now().strftime("%H:%M:%S")
                ip = "Unknown"
                port = "Unknown"
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "ATTACKER:":
                        ip = parts[i+1] if i+1 < len(parts) else "Unknown"
                    if p == "port":
                        port = parts[i+1] if i+1 < len(parts) else "Unknown"
                attacks.append({"time": time, "ip": ip, "port": port, "action": "BLOCKED"})
    except:
        pass
    return attacks

def get_attacks():
    """Get all attacks from all log files"""
    attacks = []
    if os.path.exists("/var/log/honeypot.log"):
        attacks.extend(parse_attacks_from_log("/var/log/honeypot.log"))
    if os.path.exists("/var/log/ai-guard-alerts.log"):
        attacks.extend(parse_attacks_from_log("/var/log/ai-guard-alerts.log"))
    
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for a in reversed(attacks):
        key = a["ip"] + a["port"] + a["time"]
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return list(reversed(unique[-20:]))

@app.route("/")
def dashboard():
    # AI Guard data
    attacks = get_attacks()
    blocked_ips_list = get_blocked_ips()
    
    # Check honeypot status
    hp = subprocess.run(["pgrep", "-f", "honeypot"], capture_output=True)
    honeypot_online = hp.returncode == 0

    # Pi-hole data
    pihole = get_pihole_data()

    # Parse Pi-hole top queries (allowed domains)
    top_queries = []
    if pihole and "top_queries" in pihole:
        top_queries = list(pihole["top_queries"].items())[:10]

    # Parse Pi-hole top ads (blocked domains)
    top_ads = []
    if pihole and "top_ads" in pihole:
        top_ads = list(pihole["top_ads"].items())[:10]

    # Parse Pi-hole top clients (devices)
    top_clients = []
    if pihole and "top_sources" in pihole:
        for ip, count in list(pihole["top_sources"].items())[:10]:
            top_clients.append({"ip": ip, "name": None, "count": count})

    return render_template_string(
        HTML,
        total_attacks=len(attacks),
        blocked_ips=len(blocked_ips_list),
        honeypot_ports=5,
        pihole_queries=pihole.get("dns_queries_today", 0) if pihole else 0,
        pihole_blocked=pihole.get("ads_blocked_today", 0) if pihole else 0,
        pihole_percent=round(pihole.get("ads_percentage_today", 0), 1) if pihole else 0,
        attacks=attacks,
        blocked_ips_list=blocked_ips_list,
        top_queries=top_queries,
        top_ads=top_ads,
        top_clients=top_clients,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

if __name__ == "__main__":
    print("[DASHBOARD] Starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
