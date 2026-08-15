#!/usr/bin/env python3
"""
AI Guard Pro — Device Discovery
Auto-detect devices on network
"""

import subprocess
import json
import os
from datetime import datetime
from collections import defaultdict

DEVICES_FILE = "/var/lib/ai-guard/devices.json"

def load_devices():
    if os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_devices(devices):
    os.makedirs("/var/lib/ai-guard", exist_ok=True)
    with open(DEVICES_FILE, 'w') as f:
        json.dump(devices, f, indent=2)

def discover_devices():
    """Scan network for devices using ARP"""
    print("[DEVICE] Scanning network...")
    
    # Get local network range
    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'src' in line and 'dev eth0' in line:
            # Extract network range
            parts = line.split()
            for i, part in enumerate(parts):
                if '/' in part:
                    network = part
                    break
            else:
                network = "192.168.8.0/24"  # Default
            break
    else:
        network = "192.168.8.0/24"  # Default fallback
    
    print(f"[DEVICE] Scanning: {network}")
    
    # ARP scan
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", network],
            capture_output=True, text=True, timeout=60
        )
    except Exception as e:
        print(f"[DEVICE] nmap error: {e}")
        return {}
    
    devices = load_devices()
    found_new = False
    
    for line in result.stdout.split('\n'):
        if 'Nmap scan report for' in line:
            ip = line.split('for ')[-1].strip('()')
            current_ip = ip
        elif 'MAC Address:' in line:
            parts = line.split()
            mac = parts[2]
            vendor = ' '.join(parts[3:]).strip('()') if len(parts) > 3 else "Unknown"
            
            if current_ip not in devices:
                devices[current_ip] = {
                    "mac": mac,
                    "vendor": vendor,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "New",
                    "trusted": False,
                    "name": vendor
                }
                print(f"[DEVICE] NEW DEVICE: {current_ip} | {mac} | {vendor}")
                found_new = True
            else:
                devices[current_ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                devices[current_ip]["status"] = "Online"
    
    save_devices(devices)
    
    if found_new:
        print(f"[DEVICE] New device(s) detected!")
    else:
        print(f"[DEVICE] No new devices. Total: {len(devices)}")
    
    return devices

def list_devices():
    devices = load_devices()
    print("\n" + "=" * 60)
    print("AI Guard Pro — Network Devices")
    print("=" * 60)
    print(f"{'IP':<16} {'MAC':<18} {'Status':<10} {'Trusted':<10} {'Name'}")
    print("-" * 60)
    
    for ip, info in devices.items():
        status = info.get("status", "Unknown")
        trusted = "Yes" if info.get("trusted") else "No"
        name = info.get("name", info.get("vendor", "Unknown"))
        mac = info.get("mac", "Unknown")
        print(f"{ip:<16} {mac:<18} {status:<10} {trusted:<10} {name}")
    
    print("=" * 60)
    return devices

def mark_device_trusted(ip, name=None):
    devices = load_devices()
    if ip in devices:
        devices[ip]["trusted"] = True
        if name:
            devices[ip]["name"] = name
        devices[ip]["status"] = "Trusted"
        save_devices(devices)
        print(f"[DEVICE] {ip} marked as TRUSTED ({name or devices[ip].get('name', 'Unknown')})")
    else:
        print(f"[DEVICE] {ip} not found. Run discover first.")

def mark_device_untrusted(ip):
    devices = load_devices()
    if ip in devices:
        devices[ip]["trusted"] = False
        devices[ip]["status"] = "Untrusted"
        save_devices(devices)
        print(f"[DEVICE] {ip} marked as UNTRUSTED")

if __name__ == "__main__":
    print("=" * 60)
    print("AI Guard Pro — Device Discovery")
    print("=" * 60)
    discover_devices()
    list_devices()
