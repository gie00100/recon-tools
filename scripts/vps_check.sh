#!/bin/bash
TARGETS_FILE="/root/recon-tools/targets/wix_ebay_targets.txt"
OUTPUT_DIR="/root/recon-tools/output"

completed=$(ls "$OUTPUT_DIR" 2>/dev/null | grep -v state | grep -v '.json' | sed 's/_[0-9].*//' | sort -u)
running=$(ps aux | grep recon_master | grep -v grep | sed -n 's/.*-d \([^ ]*\).*/\1/p')
targets=$(cat "$TARGETS_FILE" 2>/dev/null | grep -v '^#' | grep -v '^$' | sort)

total=$(echo "$targets" | wc -l)
done_count=0
running_count=0
remaining_count=0

echo "============================================"
echo "  RECON PIPELINE STATUS"
echo "============================================"
echo ""

echo "=== COMPLETED SCANS ==="
while IFS= read -r domain; do
    if echo "$completed" | grep -qx "$domain"; then
        if [ -f "$OUTPUT_DIR/${domain}_state.json" ]; then
            echo "  [DONE]    $domain"
        else
            echo "  [DONE*]   $domain  (no state file - may be partial)"
        fi
        done_count=$((done_count + 1))
    fi
done <<< "$targets"
echo ""

echo "=== CURRENTLY RUNNING ==="
if [ -n "$running" ]; then
    echo "  [RUNNING] $running"
    running_count=1
else
    echo "  None"
fi
echo ""

echo "=== NOT STARTED ==="
while IFS= read -r domain; do
    is_done=$(echo "$completed" | grep -cx "$domain")
    is_running=0
    if [ "$domain" = "$running" ]; then is_running=1; fi
    if [ "$is_done" -eq 0 ] && [ "$is_running" -eq 0 ]; then
        echo "  [PENDING] $domain"
        remaining_count=$((remaining_count + 1))
    fi
done <<< "$targets"
if [ "$remaining_count" -eq 0 ]; then echo "  None"; fi
echo ""

echo "=== EXTRA SCANS (not in target list) ==="
extra_count=0
while IFS= read -r scanned; do
    if [ -z "$scanned" ]; then continue; fi
    in_targets=$(echo "$targets" | grep -cx "$scanned")
    if [ "$in_targets" -eq 0 ]; then
        echo "  [EXTRA]   $scanned"
        extra_count=$((extra_count + 1))
    fi
done <<< "$completed"
if [ "$extra_count" -eq 0 ]; then echo "  None"; fi
echo ""

echo "============================================"
echo "  SUMMARY"
echo "============================================"
echo "  Total Targets:  $total"
echo "  Completed:      $done_count"
echo "  Running:        $running_count"
echo "  Remaining:      $remaining_count"
echo "  Extra Scans:    $extra_count"
echo ""

echo "=== DISK ==="
df -h / | tail -1 | awk '{print "  Used: "$3" / "$2"  ("$5" full)"}'
du -sh "$OUTPUT_DIR" 2>/dev/null | awk '{print "  Output: "$1}'
echo ""
