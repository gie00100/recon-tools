#!/bin/bash
# Deep Tesco-ONLY recon — separate from the multi-program watchlist.
# Deterministic, exhaustive enumeration so live-host counts stop bouncing between
# runs: adds DNS brute-force (--brute) + subdomain permutations (--permutations) on
# top of the full active pipeline. One domain at a time, low priority (nice -n 19),
# never aborts on a single failure. Own screen (tesco_deep) + own log.
SCRIPT_DIR="/root/recon-tools"
# Optional $1 = targets file (default the core Tesco list). Log is named after it.
TARGETS_FILE="${1:-$SCRIPT_DIR/targets/tesco_targets.txt}"
LOG="$SCRIPT_DIR/$(basename "${TARGETS_FILE%.txt}")_deep.log"

cd "$SCRIPT_DIR" || exit 1
source venv/bin/activate
export PATH="/root/recon-tools/venv/bin:$HOME/.local/bin:$PATH"

echo "==================================================" >> "$LOG"
echo "  Tesco DEEP scan (brute+permutations) started: $(date)" >> "$LOG"
echo "==================================================" >> "$LOG"

TARGETS=$(grep -vE '^#|^$' "$TARGETS_FILE" | tr -d '\r' | sort -u)
TOTAL=$(echo "$TARGETS" | wc -l); COUNT=0; FAILED=0

for d in $TARGETS; do
    COUNT=$((COUNT + 1))
    # Idempotent: skip a domain already deep-scanned today (lets us resume a
    # serialized queue without re-doing completed work).
    if ls "$SCRIPT_DIR"/output/${d}_$(date +%Y%m%d)_*/report.html >/dev/null 2>&1; then
        echo "[$COUNT/$TOTAL] SKIP $d (already deep-scanned today) — $(date)" >> "$LOG"
        continue
    fi
    echo "" >> "$LOG"
    echo "[$COUNT/$TOTAL] DEEP scanning $d — $(date)" >> "$LOG"
    # Deep on DISCOVERY: exhaustive subdomains (brute+permutations), live probe,
    # JS/schema extraction. SKIP the disk-heavy URL corpora (waymore/urlcollect/crawl/
    # vtscrape) to keep the footprint lean. PRUNED 2026-10-06: dropped asn (0 output)
    # and portscan (near-zero) — neither produced results on the Tesco estate.
    # Per-domain wall-time cap (default 90m) so one slow/wildcard domain can't eat
    # the whole day (tescocloud.com once took ~15h). timeout exits 124 on expiry ->
    # caught below as a soft failure, and the run moves on.
    nice -n 19 timeout "${DOMAIN_TIMEOUT:-5400}" python3 src/recon_master.py -d "$d" -o "$SCRIPT_DIR/output" \
        --modules subdomain,probe,jsextract,schema,report \
        --brute --permutations >> "$LOG" 2>&1 || {
        rc=$?
        if [ "$rc" = "124" ]; then
            echo "[$COUNT/$TOTAL][TIMEOUT] $d hit ${DOMAIN_TIMEOUT:-5400}s cap — moving on" >> "$LOG"
        else
            echo "[$COUNT/$TOTAL][ERROR] $d failed (rc=$rc) — continuing" >> "$LOG"
        fi
        FAILED=$((FAILED + 1))
    }
    echo "[$COUNT/$TOTAL] done $d — $(date)" >> "$LOG"
    sleep 5
done

echo "==================================================" >> "$LOG"
echo "  Tesco DEEP scan complete: $(date)  (failed $FAILED/$TOTAL)" >> "$LOG"
echo "==================================================" >> "$LOG"
