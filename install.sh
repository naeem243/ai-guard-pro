#!/bin/bash
set -e

echo "=========================================="
echo "  AI Guard Pro - One-Command Installer"
echo "=========================================="

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root: sudo bash install.sh"
    exit 1
fi

# Get system IP
IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')
echo "[*] Detected IP: $IP"

# Update system
echo "[*] Updating system..."
apt update && apt upgrade -y

# Install dependencies
echo "[*] Installing dependencies..."
apt install -y python3 python3-pip python3-scapy python3-sklearn python3-flask python3-geoip2 python3-requests fail2ban iptables-persistent git curl

# Install additional pip packages if apt versions not available
pip3 install requests geoip2 --break-system-packages 2>/dev/null || pip3 install requests geoip2

# Create app directory
INSTALL_DIR="/opt/ai-guard-pro"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Clone from GitHub
echo "[*] Downloading AI Guard Pro from GitHub..."
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[*] Already cloned, pulling latest changes..."
    git pull
else
    git clone https://github.com/naeem243/ai-guard-pro.git $INSTALL_DIR 2>/dev/null || echo "[!] Could not clone. Please manually copy files to $INSTALL_DIR"
fi

# Create config.py if not exists
if [ ! -f "$INSTALL_DIR/config.py" ]; then
    echo "[*] Creating config template..."
    cat > $INSTALL_DIR/config.py << 'PYCFG'
# AI Guard Pro Configuration
# Get Bot Token from @BotFather on Telegram
# Get Chat ID from @userinfobot on Telegram

BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
CHAT_ID = "YOUR_CHAT_ID_HERE"
PYCFG
    echo "[!] IMPORTANT: Edit $INSTALL_DIR/config.py with your Telegram Bot Token and Chat ID"
fi

# Setup Firewall
echo "[*] Setting up firewall..."
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.8.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -s 192.168.8.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -j LOG --log-prefix "[AI-GUARD DROP] " --log-level 4
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Setup Fail2ban
echo "[*] Configuring Fail2ban..."
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
F2B

systemctl restart fail2ban
systemctl enable fail2ban

# Setup Systemd Services
echo "[*] Creating systemd services..."

cat > /etc/systemd/system/ai-guard-pro.service << SVC1
[Unit]
Description=AI Network Guard Pro
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ai_guard_pro.py
Restart=always
RestartSec=15
StandardOutput=append:/var/log/ai-guard.log
StandardError=append:/var/log/ai-guard.log

[Install]
WantedBy=multi-user.target
SVC1

cat > /etc/systemd/system/ai-guard-dashboard.service << SVC2
[Unit]
Description=AI Guard Pro Dashboard
After=network-online.target ai-guard-pro.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/dashboard_server.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ai-guard-dashboard.log
StandardError=append:/var/log/ai-guard-dashboard.log

[Install]
WantedBy=multi-user.target
SVC2

systemctl daemon-reload
systemctl enable ai-guard-pro.service ai-guard-dashboard.service

echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit config: nano $INSTALL_DIR/config.py"
echo "2. Start services: systemctl start ai-guard-pro ai-guard-dashboard"
echo "3. Dashboard: http://$IP:5000"
echo ""
echo "To install Pi-hole, run:"
echo "    curl -sSL https://install.pi-hole.net | bash"
echo "=========================================="
