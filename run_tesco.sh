#!/bin/bash
# Tesco recon stream — isolated from the watchlist run.
# One domain at a time, FULL pipeline, low CPU priority so the existing
# watchlist scan and the Discord bot stay responsive on the 512MB box.
# Do NOT use `set -e` — a single domain failing must not abort the whole run.

SCRIPT_DIR="/root/recon-tools"
TARGETS_FILE="$SCRIPT_DIR/targets/tesco_targets.txt"
LOG_FILE="$SCRIPT_DIR/tesco_scan.log"

cd "$SCRIPT_DIR"
source venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"

echo "============================================" >> "$LOG_FILE"
echo "  Tesco FULL Scan Started: $(date)"          >> "$LOG_FILE"
echo "============================================" >> "$LOG_FILE"

TARGETS=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | tr -d '\r' | sort -u)
TOTAL=$(echo "$TARGETS" | wc -l)
COUNT=0
FAILED=0

for domain in $TARGETS; do
    COUNT=$((COUNT + 1))
    echo ""                                          >> "$LOG_FILE"
    echo "========================================"  >> "$LOG_FILE"
    echo "  [$COUNT/$TOTAL] Scanning: $domain"        >> "$LOG_FILE"
    echo "  Started: $(date)"                         >> "$LOG_FILE"
    echo "========================================"  >> "$LOG_FILE"

    nice -n 19 python3 src/recon_master.py -d "$domain" --full >> "$LOG_FILE" 2>&1 || {
        echo "  [ERROR] recon_master.py exited with error for $domain — continuing" >> "$LOG_FILE"
        FAILED=$((FAILED + 1))
    }

    echo "  [$COUNT/$TOTAL] Completed: $domain at $(date)" >> "$LOG_FILE"
    sleep 5
done

echo "============================================"           >> "$LOG_FILE"
echo "  All $TOTAL Tesco scans completed: $(date)"            >> "$LOG_FILE"
echo "  Failed: $FAILED / $TOTAL"                             >> "$LOG_FILE"
echo "============================================"           >> "$LOG_FILE"
