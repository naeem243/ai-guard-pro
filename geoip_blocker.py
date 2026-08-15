#!/usr/bin/env python3
"""
AI Guard Pro — GeoIP Blocker
Uses ip-api.com free API (no account, no database needed!)
"""

import requests
import subprocess
import time
from datetime import datetime

# ========== CONFIG ==========
BLOCKED_COUNTRIES = ["RU", "CN", "KP", "IR"]  # Russia, China, North Korea, Iran
WHITELIST_IPS = ["127.0.0.1", "192.168.8.1"]   # Router aur local
BLOCKED_IPS_FILE = "/var/log/ai-guard-blocked-ips.txt"
RATE_LIMIT_DELAY = 1.5  # seconds between API calls (free tier safe)
CACHE_DURATION = 3600   # 1 hour cache

# Simple cache: {ip: (country_code, timestamp)}
ip_cache = {}

def log_block(ip, country_code, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{timestamp} | {ip} | {country_code} | {reason}\n")
    print(f"[GEOIP] BLOCKED {ip} ({country_code}) — {reason}")

def block_ip(ip):
    """Block IP using iptables"""
    try:
        # Check if already blocked
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return  # Already blocked
        
        # Add to iptables
        subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"], check=True)
        
        # Save rules
        subprocess.run(["iptables-save", ">", "/etc/iptables/rules.v4"], shell=True)
        print(f"[GEOIP] iptables rule added for {ip}")
    except Exception as e:
        print(f"[GEOIP] iptables error: {e}")

def get_country_code(ip):
    """Get country code from ip-api.com (FREE, no account needed!)"""
    
    # Local IPs ko allow karo
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "LOCAL", "Local Network"
    
    # Check cache
    if ip in ip_cache:
        cached_code, cached_time = ip_cache[ip]
        if time.time() - cached_time < CACHE_DURATION:
            return cached_code, "Cached"
    
    # Rate limit delay
    time.sleep(RATE_LIMIT_DELAY)
    
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,country,status,message",
            timeout=5
        )
        data = response.json()
        
        if data.get("status") == "success":
            country_code = data.get("countryCode", "UNKNOWN")
            country_name = data.get("country", "Unknown")
            
            # Save to cache
            ip_cache[ip] = (country_code, time.time())
            
            return country_code, country_name
        else:
            print(f"[GEOIP] API error for {ip}: {data.get('message', 'Unknown error')}")
            return "UNKNOWN", "Unknown"
            
    except Exception as e:
        print(f"[GEOIP] Request error for {ip}: {e}")
        return "UNKNOWN", "Unknown"

def check_and_block_ip(ip, source="packet"):
    """Main function: check IP and block if from banned country"""
    
    # Whitelist check
    if ip in WHITELIST_IPS:
        return False, "Whitelisted"
    
    country_code, country_name = get_country_code(ip)
    
    if country_code == "LOCAL":
        return False, "Local network"
    
    if country_code in BLOCKED_COUNTRIES:
        reason = f"GeoIP Block: {country_name} ({country_code}) from {source}"
        log_block(ip, country_code, reason)
        block_ip(ip)
        return True, reason
    
    return False, f"Allowed: {country_name} ({country_code})"

def unblock_ip(ip):
    """Remove IP from blocklist"""
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
        print(f"[GEOIP] Unblocked {ip}")
        return True
    except Exception as e:
        print(f"[GEOIP] Unblock error: {e}")
        return False

def list_blocked_ips():
    """Show all blocked IPs"""
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            lines = f.readlines()
            if not lines:
                print("[GEOIP] No IPs blocked yet")
                return []
            print(f"\n[GEOIP] Blocked IPs ({len(lines)} total):\n")
            for line in lines[-20:]:  # Last 20
                print(f"  {line.strip()}")
            return lines
    except FileNotFoundError:
        print("[GEOIP] No block log yet")
        return []

# ========== TEST ==========
if __name__ == "__main__":
    print("=" * 50)
    print("AI Guard Pro — GeoIP Blocker (API Version)")
    print("Using ip-api.com (FREE — no account needed!)")
    print("=" * 50)
    
    # Test karo
    test_ips = [
        "8.8.8.8",      # US — allow
        "185.220.101.0", # Likely Russia/Germany — check
        "103.21.58.1",   # India — allow
    ]
    
    for ip in test_ips:
        blocked, msg = check_and_block_ip(ip, "test")
        print(f"  {ip} → {msg}")
        print()
    
    print("[GEOIP] GeoIP Blocker ready!")
