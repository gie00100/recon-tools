#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: ./run_recon.sh <domain>"
    echo "Example: ./run_recon.sh hackerone.com"
    exit 1
fi

DOMAIN=$(echo "$1" | tr -d '\r')
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

echo "========================================================"
echo "Starting Advanced Bug Bounty Recon on: $DOMAIN"
echo "========================================================"

if [ ! -f "$SCRIPT_DIR/venv/bin/python" ]; then
    echo "Virtual environment not found. Please run ./setup_vps.sh first."
    exit 1
fi

# Run the recon pipeline with lowest CPU priority (nice -n 19) to ensure the Discord Bot remains fully responsive even under 100% load
nice -n 19 "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/src/recon_master.py" -d "$DOMAIN" -o "$PWD/output" --full --active

echo ""
echo "Reconnaissance finished. Check the output directory for results."
