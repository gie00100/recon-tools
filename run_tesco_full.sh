#!/bin/bash
# Tesco EXHAUSTIVE recon — "don't miss a single thing". ONE full pipeline per domain
# so every PRODUCING module runs against the same corpus in one output dir: deep
# subdomain discovery (brute + permutations) + live probe + JS extract (+ raw JS saved
# to js_files/) + schema + the FULL URL corpora (vtscrape/crawl/waymore/urlcollect/
# dedup) + bounty scan + report. Serial, one domain at a time (the 458MB box cannot
# run two at once), nice -n 19, never aborts on a single domain failure.
#
# PRUNED 2026-10-06 (data-driven, from the 2026-10-05 14-domain run): dropped
# asn (0 output), portscan (1 port total), credhunt (0 creds) and backup+--active
# (5 wordlist entries -> 0 creds, and the module that OOM'd the box). takeover/credcheck
# were never in the list. Both actionable leads were provenance=active (crawl/js), so
# nothing of value was lost; the passive corpora (waymore/urlcollect/vtscrape) are KEPT
# per the "exhaustive" stance even though they produced 0 leads this run.
#
# --concurrency 20 now only caps the active bounty-validation fetches; discovery/probe
# modules self-cap at 15-20 regardless. 2G swap is the safety net.
#
# Writes fresh output/<domain>_<ts>/ dirs (NO "skip if scanned today" guard — we want
# a complete, consistent re-scan). Own screen (tesco_full) + own log. A companion
# disk guard: if free disk drops below MIN_FREE_MB it stops before the next domain so
# the box never fills (fetch + cleanup_vps.py locally, then resume).
# RUN STATUS: 2026-09-12 full/exhaustive run COMPLETED 36/36 (0 failed) at 16:31 UTC;
# fetched to local output/2026-09-12/ (7946 subs, 745 live, ~969k unique URLs, 36 domains).
SCRIPT_DIR="/root/recon-tools"
TARGETS_FILE="${1:-$SCRIPT_DIR/targets/tesco_all_targets.txt}"
LOG="$SCRIPT_DIR/$(basename "${TARGETS_FILE%.txt}")_full.log"
MIN_FREE_MB="${MIN_FREE_MB:-800}"     # stop before a domain if less than this is free

cd "$SCRIPT_DIR" || exit 1
source venv/bin/activate
export PATH="/root/recon-tools/venv/bin:$HOME/.local/bin:$PATH"

echo "==================================================" >> "$LOG"
echo "  Tesco FULL/EXHAUSTIVE scan started: $(date)"       >> "$LOG"
echo "  targets=$TARGETS_FILE  min_free=${MIN_FREE_MB}MB"  >> "$LOG"
echo "==================================================" >> "$LOG"

TARGETS=$(grep -vE '^#|^$' "$TARGETS_FILE" | tr -d '\r' | sort -u)
TOTAL=$(echo "$TARGETS" | wc -l); COUNT=0; FAILED=0

for d in $TARGETS; do
    COUNT=$((COUNT + 1))
    FREE_MB=$(df -Pm "$SCRIPT_DIR" | awk 'NR==2{print $4}')
    if [ "${FREE_MB:-0}" -lt "$MIN_FREE_MB" ]; then
        echo "[$COUNT/$TOTAL] STOP: only ${FREE_MB}MB free (< ${MIN_FREE_MB}MB) before $d." >> "$LOG"
        echo "  Fetch results locally + run cleanup_vps.py, then re-launch to resume." >> "$LOG"
        break
    fi
    echo "" >> "$LOG"
    echo "[$COUNT/$TOTAL] FULL scanning $d  (free=${FREE_MB}MB) — $(date)" >> "$LOG"
    nice -n 19 python3 src/recon_master.py -d "$d" -o "$SCRIPT_DIR/output" \
        --modules subdomain,probe,jsextract,schema,vtscrape,crawl,waymore,urlcollect,dedup,bountyscan,report \
        --brute --permutations --concurrency 20 >> "$LOG" 2>&1 || {
        echo "[$COUNT/$TOTAL][ERROR] $d failed — continuing" >> "$LOG"
        FAILED=$((FAILED + 1))
    }
    echo "[$COUNT/$TOTAL] done $d — $(date)" >> "$LOG"
    sleep 5
done

echo "==================================================" >> "$LOG"
echo "  Tesco FULL scan finished: $(date)  (failed $FAILED/$TOTAL, processed $COUNT/$TOTAL)" >> "$LOG"
echo "==================================================" >> "$LOG"
