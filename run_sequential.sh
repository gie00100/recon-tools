#!/bin/bash
# Sequential scan runner — one domain at a time, FULL pipeline
set -e

SCRIPT_DIR="/root/recon-tools"
TARGETS_FILE="$SCRIPT_DIR/targets/targets.txt"
LOG_FILE="$SCRIPT_DIR/scan.log"

cd "$SCRIPT_DIR"
source venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"

echo "============================================" | tee -a "$LOG_FILE"
echo "  Sequential FULL Scan Started: $(date)" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

# Read targets, skip comments and blank lines
TARGETS=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | tr -d '\r' | sort -u)
TOTAL=$(echo "$TARGETS" | wc -l)
COUNT=0

for domain in $TARGETS; do
    COUNT=$((COUNT + 1))
    echo "" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    echo "  [$COUNT/$TOTAL] Scanning: $domain" | tee -a "$LOG_FILE"
    echo "  Started: $(date)" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"

    python3 src/recon_master.py -d "$domain" --full 2>&1 | tee -a "$LOG_FILE"

    echo "  [$COUNT/$TOTAL] Completed: $domain at $(date)" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Brief pause between domains
    sleep 5
done

echo "============================================" | tee -a "$LOG_FILE"
echo "  All $TOTAL scans completed: $(date)" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
