"""
Run Watchlist Scan — Sequential recon on all watchlist domains via VPS.

Reads domains from targets/watchlist.txt, strips comments and metadata,
uploads a clean domain list, and launches a sequential bulk scan on the VPS.

Usage:
  python scripts/vps/run_watchlist.py                    # Uses watchlist.txt
  python scripts/vps/run_watchlist.py --file targets.txt # Uses a custom file
  python scripts/vps/run_watchlist.py --dry-run           # Show domains without launching
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vps_helper import connect_vps, run_remote

PROJECT_ROOT = Path(__file__).parent.parent.parent


def parse_watchlist(filepath: Path) -> list:
    """Extract clean domain list from watchlist file (strips comments, metadata)."""
    domains = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip pipe-separated metadata: "domain | type | date | reason" → "domain"
            domain = line.split("|")[0].strip()
            if domain and "." in domain:
                domains.append(domain)
    return domains


def main():
    parser = argparse.ArgumentParser(description="Run sequential recon on watchlist domains via VPS")
    parser.add_argument("--file", default="watchlist.txt", help="Target file in targets/ dir (default: watchlist.txt)")
    parser.add_argument("--dry-run", action="store_true", help="Show parsed domains without launching")
    args = parser.parse_args()

    # Resolve file path
    filepath = PROJECT_ROOT / "targets" / args.file
    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    # Parse domains
    domains = parse_watchlist(filepath)
    if not domains:
        print("[!] No domains found in file.")
        sys.exit(1)

    print(f"[*] Parsed {len(domains)} domain(s) from {args.file}:")
    for i, d in enumerate(domains, 1):
        print(f"    {i}. {d}")

    if args.dry_run:
        print("\n[DRY-RUN] No scan launched.")
        return

    # Connect to VPS
    ssh, cfg = connect_vps()

    try:
        # Write clean domain list to a temp file and upload
        tmp_file = PROJECT_ROOT / "targets" / ".watchlist_run.txt"
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(domains) + "\n")

        remote_file = f"{cfg['remote_path']}/watchlist_run.txt"
        print(f"\n[*] Uploading {len(domains)} domains to VPS...")
        sftp = ssh.open_sftp()
        sftp.put(str(tmp_file), remote_file)
        
        # Also upload the raw targets file so the Discord !status command has the latest data
        remote_targets_file = f"{cfg['remote_path']}/targets/targets.txt"
        sftp.put(str(filepath), remote_targets_file)
        
        sftp.close()
        tmp_file.unlink()  # Clean up local temp

        # Kill any existing watchlist scan sessions
        print("[*] Cleaning up old watchlist sessions...")
        run_remote(ssh, "screen -S watchlist_recon -X quit 2>/dev/null || true", silent=True)
        run_remote(ssh, "pkill -f 'watchlist_run.txt' 2>/dev/null || true", silent=True)
        time.sleep(1)

        # Make sure screen is available
        run_remote(ssh, "which screen || apt-get install -y screen", silent=True)

        # Launch sequential bulk scan in a detached screen session
        cmd = (
            f"cd {cfg['remote_path']} && "
            f'screen -dmS watchlist_recon bash -c "'
            f"./run_bulk.sh watchlist_run.txt; "
            f'echo WATCHLIST SCAN COMPLETE; sleep 3600"'
        )
        print(f"[*] Launching sequential scan...")
        run_remote(ssh, cmd, silent=True)
        time.sleep(2)

        # Verify
        sessions = run_remote(ssh, "screen -ls", silent=True)
        if "watchlist_recon" in sessions:
            print("[+] Watchlist scan launched successfully!")
            print(f"[+] Running {len(domains)} domains sequentially (one at a time)")
            print(f"[+] Screen session: watchlist_recon")
            print(f"\n    Monitor:  ssh root@{cfg['host']} 'screen -r watchlist_recon'")
            print(f"    Status:   python scripts/vps/check_recon_progress.py")
        else:
            print("[!] Failed to launch screen session.")
            print(sessions)

    finally:
        ssh.close()
        print("\n[*] Done.")


if __name__ == "__main__":
    main()
