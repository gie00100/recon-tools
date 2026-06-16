"""
Run Watchlist Scan — Sequential recon on all watchlist domains via VPS.

Steps performed automatically:
  1. Clean old VPS output directory (rm -rf output/*)
  2. git pull latest code + targets on VPS
  3. Parse active (uncommented) domains from targets/targets.txt
  4. Upload clean domain list to VPS
  5. Launch one-by-one sequential scan in a detached screen session

Usage:
  python scripts/vps/run_watchlist.py                     # Use targets/targets.txt
  python scripts/vps/run_watchlist.py --file custom.txt   # Use custom file
  python scripts/vps/run_watchlist.py --dry-run           # Show domains without launching
  python scripts/vps/run_watchlist.py --no-clean          # Skip VPS output cleanup
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vps_helper import connect_vps, run_remote

PROJECT_ROOT = Path(__file__).parent.parent.parent


def parse_targets(filepath: Path) -> list:
    """Extract active (uncommented) domain list from targets file."""
    domains = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip pipe-separated metadata: "domain | type | date" → "domain"
            domain = line.split("|")[0].strip()
            if domain and "." in domain:
                domains.append(domain)
    return domains


def main():
    parser = argparse.ArgumentParser(description="Clean VPS, update code, and run sequential recon on watchlist")
    parser.add_argument("--file", default="targets.txt", help="Target file in targets/ dir (default: targets.txt)")
    parser.add_argument("--dry-run", action="store_true", help="Show parsed domains without launching")
    parser.add_argument("--no-clean", action="store_true", help="Skip cleaning VPS output directory")
    args = parser.parse_args()

    # Resolve file path
    filepath = PROJECT_ROOT / "targets" / args.file
    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    # Parse active domains
    domains = parse_targets(filepath)
    if not domains:
        print("[!] No active (uncommented) domains found in file.")
        sys.exit(1)

    print(f"[*] Parsed {len(domains)} active domain(s) from {args.file}:")
    for i, d in enumerate(domains, 1):
        print(f"    {i:>3}. {d}")

    if args.dry_run:
        print("\n[DRY-RUN] No scan launched.")
        return

    # Connect to VPS
    ssh, cfg = connect_vps()
    remote_path = cfg["remote_path"]

    try:
        # ── Step 1: Kill any existing scan sessions ───────────────────────
        print("\n[*] Stopping any running scan sessions...")
        run_remote(ssh, "screen -S watchlist_recon -X quit 2>/dev/null || true", silent=True)
        run_remote(ssh, "screen -S recon -X quit 2>/dev/null || true", silent=True)
        run_remote(ssh, "pkill -f 'recon_master.py' 2>/dev/null || true", silent=True)
        run_remote(ssh, "pkill -f 'run_bulk.sh' 2>/dev/null || true", silent=True)
        time.sleep(2)
        print("    Done.")

        # ── Step 2: Clean VPS output directory ───────────────────────────
        if not args.no_clean:
            print(f"\n[*] Cleaning VPS output directory ({remote_path}/output/)...")
            out = run_remote(ssh, f"du -sh {remote_path}/output/ 2>/dev/null | cut -f1 || echo '0'", silent=True)
            print(f"    Current output size: {out.strip() or '0'}")
            run_remote(ssh, f"rm -rf {remote_path}/output/*", silent=True)
            print("    Cleaned.")
        else:
            print("\n[--no-clean] Skipping VPS output cleanup.")

        # ── Step 3: Git pull latest code + targets ────────────────────────
        print(f"\n[*] Pulling latest code from git on VPS...")
        git_out = run_remote(
            ssh,
            f"cd {remote_path} && git fetch origin && git reset --hard origin/main 2>&1",
            silent=True
        )
        print(f"    {git_out.splitlines()[-1] if git_out else 'Done.'}")

        # ── Step 4: Upload clean domain list ─────────────────────────────
        tmp_file = PROJECT_ROOT / "targets" / ".watchlist_run.txt"
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(domains) + "\n")

        remote_domain_file = f"{remote_path}/watchlist_run.txt"
        print(f"\n[*] Uploading {len(domains)} domains to VPS ({remote_domain_file})...")
        sftp = ssh.open_sftp()
        sftp.put(str(tmp_file), remote_domain_file)
        sftp.close()
        tmp_file.unlink()  # Clean up local temp
        print("    Uploaded.")

        # ── Step 5: Launch sequential scan ───────────────────────────────
        run_remote(ssh, "which screen || apt-get install -y screen", silent=True)

        cmd = (
            f"cd {remote_path} && "
            f'screen -dmS watchlist_recon bash -c "'
            f"./run_bulk.sh watchlist_run.txt; "
            f'echo WATCHLIST_SCAN_COMPLETE; sleep 3600"'
        )
        print(f"\n[*] Launching sequential scan on VPS (screen session: watchlist_recon)...")
        run_remote(ssh, cmd, silent=True)
        time.sleep(2)

        # ── Verify ────────────────────────────────────────────────────────
        sessions = run_remote(ssh, "screen -ls", silent=True)
        if "watchlist_recon" in sessions:
            print("=" * 60)
            print(f"  [+] SCAN LAUNCHED SUCCESSFULLY!")
            print(f"  [+] Domains: {len(domains)} (sequential, one at a time)")
            print(f"  [+] Session: watchlist_recon")
            print("=" * 60)
            print(f"\n  Monitor live:  ssh root@{cfg['host']} 'screen -r watchlist_recon'")
            print(f"  Check progress: python scripts/vps/check_recon_progress.py")
            print(f"  Fetch results:  python scripts/vps/fetch_results.py")
        else:
            print("[!] WARNING: screen session not found — scan may not have started.")
            print("    Sessions found:")
            print(sessions)

    finally:
        ssh.close()
        print("\n[*] SSH connection closed.")


if __name__ == "__main__":
    main()
