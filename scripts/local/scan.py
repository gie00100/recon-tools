#!/usr/bin/env python3
"""
Recon Scan Launcher — One-command scan start with VPS sync and Discord notification.

Reads targets from targets.txt, syncs latest code + targets to VPS,
launches the bulk scan in a named screen session, and notifies Discord.

Usage:
  # Scan specific domains
  python scripts/local/scan.py --domains bykea.com api.bykea.net tomoe.bykea.net

  # Scan all domains for a named program (reads from targets.txt)
  python scripts/local/scan.py --program bykea
  python scripts/local/scan.py --program wellsfargo
  python scripts/local/scan.py --program khealth

  # Scan ALL un-commented domains in targets.txt
  python scripts/local/scan.py --all

  # Preview what would be scanned (no launch)
  python scripts/local/scan.py --program bykea --dry-run

  # Custom targets file
  python scripts/local/scan.py --file targets/my_targets.txt
"""

import argparse
import os
import sys
import time
from pathlib import Path

import paramiko
from scp import SCPClient

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).parent.parent.parent
TARGETS_FILE = PROJECT_ROOT / "targets" / "targets.txt"

# VPS credentials
IP   = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
REMOTE_PATH = "/root/recon-tools"

# Files to sync to VPS on every scan launch (keep VPS code up to date)
SYNC_FILES = [
    ("src/recon/vt_url_scraper.py",  f"{REMOTE_PATH}/src/recon/vt_url_scraper.py"),
    ("src/recon/bounty_scanner.py",  f"{REMOTE_PATH}/src/recon/bounty_scanner.py"),
    ("src/.env",                      f"{REMOTE_PATH}/src/.env"),
    ("targets/targets.txt",           f"{REMOTE_PATH}/targets/targets.txt"),
]

# Discord webhook for scan notifications
DISCORD_WEBHOOK = ""  # Loaded from .env below


def _load_discord_webhook() -> str:
    env_path = PROJECT_ROOT / "src" / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding='utf-8').splitlines():
            if line.startswith("DISCORD_WEBHOOK_URL="):
                return line.split("=", 1)[1].strip()
    return ""


def _parse_targets_txt(program_filter: str = None) -> list:
    """
    Parse targets.txt and return active (non-commented) domains.
    If program_filter is given, only return domains for that program section.
    """
    if not TARGETS_FILE.exists():
        print(f"[!] targets.txt not found at {TARGETS_FILE}")
        return []

    domains = []
    in_section = False
    current_section = None

    with open(TARGETS_FILE, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n').rstrip('\r')
            stripped = line.strip()

            # Detect section headers: # === Program Name ===
            if stripped.startswith("# ===") and "===" in stripped:
                section_name = stripped.strip("# =").strip().lower()
                current_section = section_name
                if program_filter:
                    # Match loosely: "bykea" matches "Bykea (HackerOne)"
                    in_section = program_filter.lower() in section_name
                else:
                    in_section = True
                continue

            # Skip blank lines and commented-out domains
            if not stripped or stripped.startswith("#"):
                continue

            # Active domain line
            if program_filter:
                if in_section:
                    domains.append(stripped)
            else:
                domains.append(stripped)

    return domains


def _connect() -> paramiko.SSHClient:
    print(f"[*] Connecting to VPS ({IP})...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(IP, username=USER, password=PASS, timeout=30,
                look_for_keys=False, allow_agent=False)
    print("[+] Connected.")
    return ssh


def _sync_code(ssh: paramiko.SSHClient):
    """Push latest code files + targets.txt to VPS."""
    print("\n[*] Syncing latest code to VPS...")
    sftp = ssh.open_sftp()
    try:
        for local_rel, remote_path in SYNC_FILES:
            local_path = PROJECT_ROOT / local_rel
            if not local_path.exists():
                print(f"  [!] Skipping {local_rel} (not found locally)")
                continue
            try:
                sftp.put(str(local_path), remote_path)
                size_kb = local_path.stat().st_size // 1024
                print(f"  [+] {local_rel} → {remote_path} ({size_kb} KB)")
            except Exception as e:
                print(f"  [!] Failed to sync {local_rel}: {e}")
    finally:
        sftp.close()


def _upload_scan_list(ssh: paramiko.SSHClient, domains: list, session_name: str) -> str:
    """Upload clean domain list to VPS and return remote file path."""
    remote_scan_file = f"{REMOTE_PATH}/{session_name}_targets.txt"
    print(f"\n[*] Uploading {len(domains)} domains to VPS...")

    domain_list = "\n".join(domains) + "\n"
    sftp = ssh.open_sftp()
    try:
        with sftp.open(remote_scan_file, 'w') as f:
            f.write(domain_list)
        print(f"  [+] Uploaded to {remote_scan_file}")
    finally:
        sftp.close()

    return remote_scan_file


def _run(ssh: paramiko.SSHClient, cmd: str, silent: bool = False) -> str:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode('utf-8', errors='replace').strip()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    if not silent:
        if out:
            print(out)
        if err:
            print(f"  STDERR: {err}")
    return out


def _launch_scan(ssh: paramiko.SSHClient, remote_scan_file: str, session_name: str) -> bool:
    """Launch scan in a named screen session on the VPS."""
    filename = Path(remote_scan_file).name

    # Kill existing session with same name
    _run(ssh, f"screen -S {session_name} -X quit 2>/dev/null || true", silent=True)
    time.sleep(1)

    # Ensure screen is installed
    _run(ssh, "which screen || apt-get install -y screen -q", silent=True)

    # Launch bulk scan in detached screen
    cmd = (
        f"cd {REMOTE_PATH} && "
        f'screen -dmS {session_name} bash -c "'
        f"./run_bulk.sh {filename}; "
        f'echo \'[DONE] {session_name} complete\'; sleep 3600"'
    )
    _run(ssh, cmd, silent=True)
    time.sleep(2)

    # Verify session started
    sessions = _run(ssh, "screen -ls", silent=True)
    if session_name in sessions:
        return True
    else:
        print(f"  [!] Screen session '{session_name}' not found. Output:")
        print(sessions)
        return False


def _notify_discord(webhook_url: str, domains: list, session_name: str, program: str):
    """Send scan start notification to Discord."""
    if not webhook_url:
        return
    try:
        import urllib.request, json
        domain_list = "\n".join(f"• `{d}`" for d in domains[:20])
        if len(domains) > 20:
            domain_list += f"\n• _(+{len(domains)-20} more)_"

        payload = {
            "embeds": [{
                "title": f"🚀 Scan Started — {program.upper() if program else 'Custom'}",
                "description": (
                    f"**Session:** `{session_name}`\n"
                    f"**Domains ({len(domains)}):**\n{domain_list}"
                ),
                "color": 0x00ff88,
                "footer": {"text": f"Recon Pipeline • VPS {IP}"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }]
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
        print("  [+] Discord notification sent.")
    except Exception as e:
        print(f"  [!] Discord notify failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Launch recon scan on VPS with code sync and Discord notification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--program", "-p", metavar="NAME",
                       help="Program name to scan (reads from targets.txt, e.g. bykea)")
    group.add_argument("--domains", "-d", nargs="+", metavar="DOMAIN",
                       help="Explicit list of domains to scan")
    group.add_argument("--file", "-f", metavar="FILE",
                       help="Custom targets file (plain domain list)")
    group.add_argument("--all", "-a", action="store_true",
                       help="Scan ALL active (non-commented) domains in targets.txt")

    parser.add_argument("--session", "-s", metavar="NAME",
                        help="Screen session name (default: auto from program/timestamp)")
    parser.add_argument("--no-sync", action="store_true",
                        help="Skip syncing code to VPS (faster, use if code unchanged)")
    parser.add_argument("--no-notify", action="store_true",
                        help="Skip Discord notification")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be scanned without launching")
    args = parser.parse_args()

    # ── Resolve domain list ──────────────────────────────────────────────────
    domains = []
    program_label = "custom"

    if args.program:
        program_label = args.program
        domains = _parse_targets_txt(args.program)
        if not domains:
            print(f"[!] No active domains found for program '{args.program}' in targets.txt")
            print(f"    (Check that the section header contains '{args.program}' and domains are uncommented)")
            sys.exit(1)

    elif args.domains:
        domains = args.domains
        program_label = domains[0].split('.')[0]

    elif args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            fpath = PROJECT_ROOT / args.file
        if not fpath.exists():
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        domains = [l.strip() for l in fpath.read_text(encoding='utf-8').splitlines()
                   if l.strip() and not l.strip().startswith('#')]
        program_label = fpath.stem

    elif args.all:
        program_label = "all"
        domains = _parse_targets_txt(None)
        if not domains:
            print("[!] No active domains found in targets.txt")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(0)

    # ── Session name ─────────────────────────────────────────────────────────
    session_name = args.session or f"recon_{program_label.replace('-', '_').replace('.', '_')}"

    # ── Preview ──────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Recon Scan — {program_label.upper()}")
    print(f"{'='*60}")
    print(f"  Domains   : {len(domains)}")
    print(f"  Session   : {session_name}")
    print(f"  Sync code : {'NO (--no-sync)' if args.no_sync else 'YES'}")
    print(f"  Dry run   : {'YES' if args.dry_run else 'NO'}")
    print()
    for i, d in enumerate(domains, 1):
        print(f"  {i:3}. {d}")
    print()

    if args.dry_run:
        print("[DRY-RUN] No scan launched.")
        return

    # ── Connect & run ────────────────────────────────────────────────────────
    ssh = _connect()
    try:
        # 1. Sync latest code + targets.txt + .env
        if not args.no_sync:
            _sync_code(ssh)

        # 2. Upload domain list for this scan
        remote_scan_file = _upload_scan_list(ssh, domains, session_name)

        # 3. Launch scan
        print(f"\n[*] Launching scan session '{session_name}'...")
        success = _launch_scan(ssh, remote_scan_file, session_name)

        if success:
            print(f"\n{'='*60}")
            print(f"  ✅ Scan launched successfully!")
            print(f"{'='*60}")
            print(f"  Session  : {session_name}")
            print(f"  Targets  : {len(domains)} domains")
            print(f"  Monitor  : ssh root@{IP} 'screen -r {session_name}'")
            print(f"  Status   : python scripts/vps/check_recon_progress.py")
            print(f"  Fetch    : run fetch_results.bat when done")
            print()

            # 4. Discord notification
            if not args.no_notify:
                print("[*] Notifying Discord...")
                webhook = _load_discord_webhook()
                _notify_discord(webhook, domains, session_name, program_label)

        else:
            print("\n[!] Scan may not have started. Check VPS manually.")

    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        ssh.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    main()
