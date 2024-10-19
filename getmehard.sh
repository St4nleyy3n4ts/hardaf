#!/bin/bash

# 1. Disable IPv6 system-wide
echo "Disabling IPv6 system-wide..."
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 2. Disable Multicast and DNS Multicast
echo "Disabling Multicast and DNS Multicast..."
echo "[Network]
MulticastDNS=no" | sudo tee -a /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# 3. Harden ARP, Routing, and TCP/UDP Settings
echo "Hardening ARP, routing, and TCP/UDP settings..."
cat <<EOT | sudo tee /etc/sysctl.d/99-security.conf
# Prevent IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable packet forwarding
net.ipv4.ip_forward = 0

# Enable TCP SYN Cookies (DoS protection)
net.ipv4.tcp_syncookies = 1

# Harden ARP behavior
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Log martians (bogus packets)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOT
sudo sysctl --system

# 4. Setup Firewalls using nftables and UFW for simplified management
echo "Setting up nftables and UFW firewalls..."
cat <<EOF | sudo tee /etc/nftables.conf
#!/usr/sbin/nft -f
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    tcp dport { 22, 80, 443 } ct state new accept
    drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF
sudo systemctl enable nftables
sudo systemctl start nftables

# Set up UFW for easier firewall management and enable rate limiting on SSH
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit ssh/tcp
sudo ufw allow http/tcp
sudo ufw allow https/tcp
sudo ufw enable
sudo ufw logging on

# 5. Blocking Hosts using StevenBlack’s blocklist
echo "Blocking malicious hosts using StevenBlack's blocklist..."
sudo apt install curl -y
sudo curl -o /etc/hosts https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
sudo systemctl restart networking

# 6. Installing and configuring Snort IDS with 20 popular community rules
echo "Installing and configuring Snort IDS..."
sudo apt install snort -y

# Configure Snort to use community rules
cat <<EOF | sudo tee /etc/snort/snort.conf
include \$RULE_PATH/local.rules
include \$RULE_PATH/community.rules
output alert_fast: alert.log
EOF

# Add popular community rules from the Talos ruleset (includes these rules):
# 1. HTTP Inspect preprocessor rules
# 2. Exploit Detection (detects buffer overflows, CGI attacks, etc.)
# 3. Shellcode detection (monitors for shellcode execution)
# 4. Denial-of-Service (DoS) detection
# 5. DDoS detection (distributed denial-of-service)
# 6. Port scanning detection
# 7. Malicious file download detection
# 8. ICMP tunneling detection
# 9. SQL Injection attack detection
# 10. Remote command execution (RCE) detection
# 11. Trojans and malware signatures
# 12. SSH brute-force detection
# 13. Cross-Site Scripting (XSS) detection
# 14. File and directory traversal attack detection
# 15. PHP code execution detection
# 16. Email malware detection (SMTP-based)
# 17. DNS-based attack detection
# 18. FTP brute-force detection
# 19. Arbitrary code execution detection
# 20. Botnet traffic detection

sudo snort -c /etc/snort/snort.conf -i eth0

# Downloading community rules
sudo apt install oinkmaster -y
sudo oinkmaster -C /etc/snort/snort.conf -o /etc/snort/rules

# 7. Additional Hardening Measures

# Disable core dumps
echo "Disabling core dumps..."
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
sudo sysctl -w fs.suid_dumpable=0

# Disable USB devices
echo "Disabling USB devices..."
echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/blacklist-usb-storage.conf

# Restrict access to /boot
echo "Restricting access to /boot..."
sudo chmod 700 /boot

# Enable AppArmor
echo "Enabling AppArmor..."
sudo apt install apparmor-utils -y
sudo systemctl enable apparmor
sudo systemctl start apparmor

# 8. Harden SSH access
echo "Hardening SSH access..."
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
echo "AllowUsers <your-username>" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh

# 9. Install and configure Fail2Ban for brute-force protection
echo "Installing Fail2Ban..."
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# 10. Enable Automatic Security Updates
echo "Enabling automatic security updates..."
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades

# 11. Enable IP Address Spoof Protection
echo "Enabling IP address spoof protection..."
echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 12. DNS over HTTPS (DoH) using dnscrypt-proxy
echo "Installing dnscrypt-proxy for encrypted DNS..."
sudo apt install dnscrypt-proxy -y
sudo systemctl enable dnscrypt-proxy
sudo systemctl start dnscrypt-proxy

# 13. Install and configure AIDE for file integrity monitoring
echo "Installing AIDE for file integrity monitoring..."
sudo apt install aide -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check

# 14. Set up Firejail for sandboxing applications
echo "Installing Firejail for sandboxing..."
sudo apt install firejail -y
# Example: Sandbox Firefox
firejail firefox

echo "System hardening and security configuration completed successfully."
