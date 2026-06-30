#!/bin/bash
# Sequential scan runner — one domain at a time, FULL pipeline
# NOTE: Do NOT use set -e here — if one domain scan fails, we want to continue
# with the next domain, not abort the entire session.

SCRIPT_DIR="/root/recon-tools"
TARGETS_FILE="$SCRIPT_DIR/targets/targets.txt"
LOG_FILE="$SCRIPT_DIR/scan.log"

cd "$SCRIPT_DIR"
source venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"

# FIX: Write header directly to log (no tee) — the screen session already
# redirects all stdout to scan.log via ">>" so using "tee -a" doubles every line.
echo "============================================" >> "$LOG_FILE"
echo "  Sequential FULL Scan Started: $(date)" >> "$LOG_FILE"
echo "============================================" >> "$LOG_FILE"

# Read targets: skip comments, blank lines, and mobile bundle IDs (not web domains)
TARGETS=$(grep -v '^#' "$TARGETS_FILE" \
    | grep -v '^$' \
    | tr -d '\r' \
    | grep -v '^com\.' \
    | grep -v '^org\.' \
    | sort -u)
TOTAL=$(echo "$TARGETS" | wc -l)
COUNT=0
FAILED=0

for domain in $TARGETS; do
    COUNT=$((COUNT + 1))
    echo "" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "  [$COUNT/$TOTAL] Scanning: $domain" >> "$LOG_FILE"
    echo "  Started: $(date)" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"

    # FIX: Direct redirect only — no tee, no double write
    python3 src/recon_master.py -d "$domain" --full >> "$LOG_FILE" 2>&1 || {
        echo "  [ERROR] recon_master.py exited with error for $domain — continuing" >> "$LOG_FILE"
        FAILED=$((FAILED + 1))
    }

    echo "  [$COUNT/$TOTAL] Completed: $domain at $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    # Brief pause between domains
    sleep 5
done

echo "============================================" >> "$LOG_FILE"
echo "  All $TOTAL scans completed: $(date)" >> "$LOG_FILE"
echo "  Failed: $FAILED / $TOTAL" >> "$LOG_FILE"
echo "============================================" >> "$LOG_FILE"
