#!/bin/bash
echo "======================================"
echo " Recon Toolkit VPS Setup Script       "
echo "======================================"

echo "[*] Updating system packages..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git tmux curl jq unzip

echo "[*] Setting up Python Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[+] Virtual environment created."
fi

echo "[*] Installing dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r src/requirements.txt
./venv/bin/pip install waymore

chmod +x run_recon.sh

echo "================================================================"
echo "[+] Installation Complete!"
echo "[!] IMPORTANT: Make sure you add your Discord Webhook URL and "
echo "    API keys to the src/.env file before running."
echo ""
echo "    To run a scan in the background 24/7, use tmux:"
echo "    tmux new -s recon"
echo "    ./run_recon.sh target.com"
echo "    (Press Ctrl+B, then D to detach)"
echo "================================================================"
