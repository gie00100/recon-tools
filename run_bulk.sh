#!/bin/bash
# Bulk Recon Runner for VPS
# Sequentially executes run_recon.sh against a list of domains

if [ -z "$1" ]; then
    echo "Usage: ./run_bulk.sh <targets_file.txt>"
    exit 1
fi

TARGETS_FILE=$1

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: File $TARGETS_FILE not found."
    exit 1
fi

echo "========================================="
echo " Starting Bulk Recon from $TARGETS_FILE"
echo "========================================="

# Loop through each target in the file
while IFS= read -r domain; do
    # Strip carriage return if uploaded from Windows
    domain=$(echo "$domain" | tr -d '\r')
    
    # Skip empty lines or lines starting with #
    if [[ -z "$domain" ]] || [[ "$domain" == \#* ]]; then
        continue
    fi
    
    # Check if a completed scan report already exists under output directory
    if ls output/${domain}_*/report.html &>/dev/null; then
        echo "[*] Target $domain is already completed. Skipping."
        continue
    fi
    
    echo ""
    echo "[*] Initiating recon for: $domain"
    # Redirect stdin to /dev/null to prevent inner tools (like waymore/python) from swallowing standard input
    ./run_recon.sh "$domain" < /dev/null
    
done < "$TARGETS_FILE"

echo ""
echo "========================================="
echo " Retry Pass: Re-processing Failed Domains"
echo "========================================="

RETRY_COUNT=0
while IFS= read -r domain; do
    domain=$(echo "$domain" | tr -d '\r')
    if [[ -z "$domain" ]] || [[ "$domain" == \#* ]]; then
        continue
    fi

    # Already completed? Skip.
    if ls output/${domain}_*/report.html &>/dev/null; then
        continue
    fi

    # Has an output dir but NO report = crashed mid-pipeline
    if ls -d output/${domain}_*/ &>/dev/null; then
        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo ""
        echo "[RETRY] Domain $domain has incomplete output. Cleaning up and re-running..."
        rm -rf output/${domain}_*/
        ./run_recon.sh "$domain" < /dev/null
    fi

done < "$TARGETS_FILE"

if [ "$RETRY_COUNT" -eq 0 ]; then
    echo "[+] No failed domains to retry."
else
    echo "[+] Retried $RETRY_COUNT domains."
fi

echo ""
echo "[+] Bulk Recon Complete!"
