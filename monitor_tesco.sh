#!/bin/bash
# Tesco weekly JS-change monitor (jsmon-style, the bounty-validated recon pattern).
# Daily: lean deep recon (JS tracked to js_files/) -> diff vs the previous run ->
# Discord alert on what's NEW (changed/new JS bundles + endpoints, new hosts,
# status flips to reachable, new schema/API, new bounty leads).
#
# Idempotent per day: run_tesco_deep.sh skips a domain already scanned today, so
# re-invoking the same day only re-diffs. Scheduled via cron for the week; remove
# with:  crontab -l | grep -v monitor_tesco.sh | crontab -
SCRIPT_DIR="/root/recon-tools"
TARGETS="${1:-$SCRIPT_DIR/tesco_targets.txt}"
LOG="$SCRIPT_DIR/monitor.log"

cd "$SCRIPT_DIR" || exit 1
source venv/bin/activate
export PATH="/root/recon-tools/venv/bin:$HOME/.local/bin:$PATH"

echo "==================================================" >> "$LOG"
echo "  Tesco MONITOR run started: $(date -u)"            >> "$LOG"
echo "==================================================" >> "$LOG"

# 1) Lean, JS-focused recon (subdomain,probe,jsextract,schema,report + brute/perms).
#    run_tesco_deep.sh is idempotent (skips domains already scanned today).
./run_tesco_deep.sh "$TARGETS" >> "$LOG" 2>&1

# 2) Diff the two most recent runs per domain and alert on real change.
python3 scripts/js_diff.py --all --targets "$TARGETS" --alert >> "$LOG" 2>&1

# 3) Retention: keep only the newest 2 runs per domain (the diff needs 2) so the
#    458MB box never fills. Runs AFTER the diff so today's + yesterday's survive.
RECON_KEEP="${RECON_KEEP:-2}" python3 scripts/prune_runs.py >> "$LOG" 2>&1

echo "  Tesco MONITOR run done: $(date -u)"               >> "$LOG"
