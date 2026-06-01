#!/bin/bash
# Parallel Recon Runner for VPS
# Splits a target list across N screen sessions for concurrent scanning
# Usage: ./run_parallel.sh <targets_file.txt> [max_workers]

set -e

if [ -z "$1" ]; then
    echo "Usage: ./run_parallel.sh <targets_file.txt> [max_workers]"
    echo "  max_workers defaults to 5"
    exit 1
fi

TARGETS_FILE=$1
MAX_WORKERS=${2:-5}
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: File $TARGETS_FILE not found."
    exit 1
fi

# Read targets into array, skip blanks and comments
TARGETS=()
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r' | xargs)
    [[ -z "$line" || "$line" == \#* ]] && continue
    TARGETS+=("$line")
done < "$TARGETS_FILE"

TOTAL=${#TARGETS[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "No targets found in $TARGETS_FILE"
    exit 1
fi

# Cap workers to total targets
if [ "$MAX_WORKERS" -gt "$TOTAL" ]; then
    MAX_WORKERS=$TOTAL
fi

echo "==========================================="
echo " Parallel Recon Launcher"
echo " Targets : $TOTAL"
echo " Workers : $MAX_WORKERS"
echo "==========================================="

# Kill any leftover recon screen sessions
for old in $(screen -ls 2>/dev/null | grep -oP 'recon_w\d+' || true); do
    screen -S "$old" -X quit 2>/dev/null || true
done

# Distribute targets round-robin across workers
for i in "${!TARGETS[@]}"; do
    WORKER_ID=$(( i % MAX_WORKERS ))
    
    # Append this domain to the worker's chunk file
    echo "${TARGETS[$i]}" >> "/tmp/recon_chunk_${WORKER_ID}.txt"
done

# Launch a detached screen session per worker
for w in $(seq 0 $(( MAX_WORKERS - 1 ))); do
    CHUNK="/tmp/recon_chunk_${w}.txt"
    
    if [ ! -f "$CHUNK" ]; then
        continue
    fi
    
    SESSION_NAME="recon_w${w}"
    
    # Count domains assigned to this worker
    COUNT=$(wc -l < "$CHUNK")
    echo "[*] Worker $w ($SESSION_NAME): $COUNT domains"
    cat "$CHUNK" | sed 's/^/     /'
    
    # Launch detached screen running bulk on its chunk
    screen -dmS "$SESSION_NAME" bash -c "cd $SCRIPT_DIR && ./run_bulk.sh $CHUNK; echo '[+] Worker $w finished'; sleep 3600"
    
    echo "    -> screen session '$SESSION_NAME' launched"
done

echo ""
echo "==========================================="
echo " All $MAX_WORKERS workers launched!"
echo " Monitor with: screen -ls"
echo " Attach with:  screen -r recon_w0"
echo "==========================================="

# Cleanup chunk files will happen after screens read them (they read immediately)
sleep 2
