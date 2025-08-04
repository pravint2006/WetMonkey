#!/usr/bin/env bash
# wetmonkey dependency installer (Debian/Ubuntu/Termux/RHEL)
set -euo pipefail

if command -v apt >/dev/null 2>&1; then
    PM="apt"
elif command -v pkg >/dev/null 2>&1; then
    PM="pkg"  # Termux
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
else
    echo "Unsupported package manager; install dependencies manually." >&2
    exit 1
fi

DEBS=(nmap hydra sqlmap hping3 gobuster dnsrecon iodine torsocks curl)

sudo $PM update -y
sudo $PM install -y "${DEBS[@]}" || true

# Python deps
if command -v pip3 >/dev/null 2>&1; then
    pip3 install -r requirements.txt
else
    sudo $PM install -y python3-pip
    pip3 install -r requirements.txt
fi

echo "[+] Dependencies installed."
