#!/usr/bin/env python3
"""
scan.py — One-command scan launcher for the Recon Pipeline VPS

Usage:
    python scripts/local/scan.py bykea.com api.bykea.net tomoe.bykea.net
    python scripts/local/scan.py --file targets/targets.txt
    python scripts/local/scan.py --active          # read active (uncommented) targets
    python scripts/local/scan.py bykea.com --no-start  # deploy only, don't launch scan

What it does:
    1. Syncs targets.txt → VPS (SFTP)
    2. Syncs updated source files → VPS (src/recon/*.py, src/*.py, src/.env)
    3. git pull on VPS to get latest code
    4. Starts a scan for each domain (bulk_runner.py in background, one per domain)
    5. Restarts the Discord bot so it picks up the new targets list
    6. Prints a summary with the nohup log paths to monitor
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "vps"))
from vps_helper import connect_vps, get_vps_config, run_remote

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Paths ─────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.parent
TARGETS_FILE  = PROJECT_ROOT / "targets" / "targets.txt"
REMOTE_ROOT   = "/root/recon-tools"

# Files to always sync to VPS before starting
FILES_TO_SYNC = [
    ("src/.env",                         f"{REMOTE_ROOT}/src/.env"),
    ("src/recon/bounty_scanner.py",      f"{REMOTE_ROOT}/src/recon/bounty_scanner.py"),
    ("src/recon/vt_url_scraper.py",      f"{REMOTE_ROOT}/src/recon/vt_url_scraper.py"),
    ("src/recon/config.py",              f"{REMOTE_ROOT}/src/recon/config.py"),
    ("targets/targets.txt",              f"{REMOTE_ROOT}/targets/targets.txt"),
]


# ── Target parsing ─────────────────────────────────────────────

def _active_targets(targets_file: Path) -> list:
    """Read all uncommented, non-empty, non-header lines from targets.txt."""
    targets = []
    with open(targets_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def _parse_targets(args) -> list:
    if args.active:
        targets = _active_targets(TARGETS_FILE)
        print(f"[*] --active: found {len(targets)} active targets in targets.txt")
        return targets
    if args.file:
        path = Path(args.file)
        targets = _active_targets(path)
        print(f"[*] --file: found {len(targets)} targets in {path}")
        return targets
    if args.domains:
        return list(args.domains)
    return []


# ── VPS helpers ────────────────────────────────────────────────

def sync_files(ssh, sftp):
    """Upload local source files to the VPS."""
    print("\n[*] Syncing files to VPS...")
    for local_rel, remote_path in FILES_TO_SYNC:
        local = PROJECT_ROOT / local_rel
        if not local.exists():
            print(f"  [!] Missing locally: {local_rel} — skip")
            continue
        try:
            sftp.put(str(local), remote_path)
            print(f"  [+] {local_rel:45s} → {remote_path}")
        except Exception as e:
            print(f"  [!] Failed to sync {local_rel}: {e}")


def git_pull_vps(ssh):
    """Run git pull on the VPS to get latest commits."""
    print("\n[*] Git pull on VPS...")
    out = run_remote(ssh, f"cd {REMOTE_ROOT} && git pull origin main 2>&1", silent=True)
    print(f"  {out.splitlines()[0] if out else 'no output'}")


def check_already_scanning(ssh, domain: str) -> bool:
    """Return True if a scan for this domain is already running."""
    out = run_remote(ssh, f"pgrep -a python | grep '{domain}'", silent=True)
    return bool(out.strip())


def start_scan(ssh, domain: str, log_dir: str = "/root/recon-tools/logs") -> str:
    """
    Launch a background scan for a single domain.
    Returns the log file path.
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/{domain}_{ts}.log"

    # Ensure log dir exists
    run_remote(ssh, f"mkdir -p {log_dir}", silent=True)

    cmd = (
        f"cd {REMOTE_ROOT} && "
        f"nohup venv/bin/python src/recon_master.py {domain} "
        f"> {log_file} 2>&1 &"
    )
    run_remote(ssh, cmd, silent=True)
    return log_file


def restart_bot(ssh):
    """Restart the Discord bot so it picks up the updated targets.txt."""
    print("\n[*] Restarting Discord bot...")
    out = run_remote(ssh, "systemctl restart recon-bot && echo OK", silent=True)
    print(f"  {'[+] Bot restarted' if 'OK' in out else '[!] ' + out}")


def verify_scan_started(ssh, domain: str, log_file: str) -> bool:
    """Give the process 3s to start, then check it's actually running."""
    time.sleep(3)
    pid_out = run_remote(ssh, f"pgrep -a python | grep '{domain}'", silent=True)
    return bool(pid_out.strip())


# ── Main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recon Pipeline — Deploy + Start Scans on VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific domains
  python scripts/local/scan.py bykea.com api.bykea.net

  # Scan all active (uncommented) targets from targets.txt
  python scripts/local/scan.py --active

  # Scan domains from a custom file
  python scripts/local/scan.py --file my_targets.txt

  # Deploy/sync only — don't start scans
  python scripts/local/scan.py bykea.com --no-start

  # Deploy targets.txt + restart bot (no domain scan)
  python scripts/local/scan.py --sync-only
        """,
    )
    parser.add_argument(
        "domains",
        nargs="*",
        metavar="DOMAIN",
        help="One or more domains to scan",
    )
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Read domains from a file (one per line, # comments ignored)",
    )
    parser.add_argument(
        "--active", "-a",
        action="store_true",
        help="Read all active (uncommented) domains from targets/targets.txt",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Sync files and update VPS but don't launch scans",
    )
    parser.add_argument(
        "--sync-only",
        action="store_true",
        help="Only sync targets.txt + restart bot, do not start any scan",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="Skip file sync, just start the scan(s)",
    )

    args = parser.parse_args()

    targets = _parse_targets(args)

    if not targets and not args.sync_only:
        parser.print_help()
        print("\n[!] Error: provide domain(s), --active, --file, or --sync-only")
        sys.exit(1)

    # ── Connect ───────────────────────────────────────────────
    try:
        ssh, cfg = connect_vps()
        sftp = ssh.open_sftp()
    except Exception as e:
        print(f"[!] Cannot connect to VPS: {e}")
        sys.exit(1)

    try:
        # ── Sync files ────────────────────────────────────────
        if not args.no_sync:
            sync_files(ssh, sftp)
            git_pull_vps(ssh)

        # ── Restart bot (always — picks up new targets.txt) ──
        restart_bot(ssh)

        # ── Launch scans ─────────────────────────────────────
        if args.sync_only or args.no_start:
            print(f"\n[=] Skipping scan launch (--{'sync-only' if args.sync_only else 'no-start'} mode)")
        else:
            print(f"\n[*] Launching scans for {len(targets)} domain(s)...")
            results = []
            skipped = []

            for domain in targets:
                domain = domain.strip().lower()
                if not domain:
                    continue

                if check_already_scanning(ssh, domain):
                    print(f"  [=] {domain:40s} → already scanning, skip")
                    skipped.append(domain)
                    continue

                log_file = start_scan(ssh, domain)
                started = verify_scan_started(ssh, domain, log_file)
                status = "✓ started" if started else "? check log"
                print(f"  [+] {domain:40s} → {status}")
                print(f"       Log: {log_file}")
                results.append((domain, log_file, started))

            # ── Summary ───────────────────────────────────────
            print(f"\n{'='*65}")
            print(f"  SCAN LAUNCH SUMMARY")
            print(f"{'='*65}")
            ok  = [(d, l) for d, l, s in results if s]
            bad = [(d, l) for d, l, s in results if not s]
            print(f"  Started:  {len(ok)} domain(s)")
            if skipped:
                print(f"  Skipped:  {len(skipped)} (already running): {', '.join(skipped)}")
            if bad:
                print(f"  Failed:   {len(bad)} — check logs:")
                for d, l in bad:
                    print(f"    tail -f {l}")
            print(f"\n  Monitor via Discord: !status or !scans")
            print(f"  Or SSH:  tail -f /root/recon-tools/logs/<domain>_*.log")
            print(f"{'='*65}")

    finally:
        sftp.close()
        ssh.close()
        print("\n[*] Connection closed.")


if __name__ == "__main__":
    main()
